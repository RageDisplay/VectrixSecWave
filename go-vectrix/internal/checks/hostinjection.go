package checks

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"vectrixgo/internal/crawler"
	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
)

// hostinjProbeHost mirrors PROBE_HOST in hostinjection.py.
const hostinjProbeHost = "vectrix-probe.attacker-host.com"

// hostinjOverrideHeaders mirrors HOST_OVERRIDE_HEADERS.
var hostinjOverrideHeaders = []string{
	"X-Forwarded-Host",
	"X-Host",
	"X-Forwarded-Server",
	"X-HTTP-Host-Override",
	"X-Original-Host",
}

// hostinjResetPaths mirrors RESET_PATHS.
var hostinjResetPaths = []string{
	"/forgot-password", "/forgot_password", "/password/reset",
	"/password-reset", "/auth/reset", "/api/password/reset",
	"/api/auth/forgot", "/api/auth/password/reset",
	"/users/password", "/account/forgot", "/reset-password",
	"/api/v1/auth/forgot", "/api/v2/auth/forgot",
}

// RunHostInjection checks for Host header reflection (cache poisoning, open
// redirect) and password-reset poisoning via forged Host headers. Mirrors
// modules/checks/hostinjection.py run().
func RunHostInjection(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, store *findings.FindingStore) {
	logging.Println("[*] Checking host header injection...")
	curlAuth := session.CurlAuthFlags(baseURL)

	hostinjCheckHostReflection(session, baseURL, curlAuth, store)
	hostinjCheckResetPoisoning(session, baseURL, endpoints, curlAuth, store)
}

// hostinjCheckHostReflection mirrors _check_host_reflection — tries injecting
// PROBE_HOST via various override headers and looks for reflection.
func hostinjCheckHostReflection(session *httpsession.Session, baseURL, curlAuth string, store *findings.FindingStore) {
	for _, header := range hostinjOverrideHeaders {
		resp, err := session.Request("GET", baseURL, httpsession.Options{
			Headers:        map[string]string{header: hostinjProbeHost},
			AllowRedirects: false,
			Timeout:        15 * time.Second,
		})
		if err != nil {
			continue
		}

		probeLower := strings.ToLower(hostinjProbeHost)
		reflectedInBody := strings.Contains(strings.ToLower(resp.Body), probeLower)
		reflectedInLocation := strings.Contains(strings.ToLower(resp.Header.Get("Location")), probeLower)
		reflectedInLink := strings.Contains(strings.ToLower(resp.Header.Get("Link")), probeLower)

		if !reflectedInBody && !reflectedInLocation && !reflectedInLink {
			continue
		}

		var where []string
		if reflectedInBody {
			where = append(where, "body")
		}
		if reflectedInLocation {
			where = append(where, "Location header")
		}
		if reflectedInLink {
			where = append(where, "Link header")
		}

		f := findings.NewFinding(
			fmt.Sprintf("Host Header Injection — отражение через '%s'", header),
			findings.High,
			"Injection",
			"CWE-113",
			baseURL,
			fmt.Sprintf("Заголовок '%s: %s' отражается в ответе (%s).\n\n"+
				"Векторы эксплуатации:\n"+
				"• **Web Cache Poisoning** — CDN/proxy кэшируют ответ с injected-ссылками\n"+
				"• **Password Reset Poisoning** — ссылка в письме указывает на сервер атакующего\n"+
				"• **Open Redirect** — Location содержит внешний домен\n"+
				"• **SSRF через Host** — внутренние сервисы принимают запросы по поддельному хосту",
				header, hostinjProbeHost, strings.Join(where, ", ")),
			"1. Формируйте абсолютные URL из жёстко заданного домена в конфигурации, "+
				"   а не из заголовка HTTP Host.\n"+
				"2. Валидируйте Host и X-Forwarded-Host по whitelist разрешённых доменов.\n"+
				"3. В nginx/Apache/CDN задайте canonical hostname и отклоняйте нераспознанные.\n"+
				"4. Для cache poisoning: установьте Vary: Host на кэшируемые ответы.",
			fmt.Sprintf("curl -sk %s -H '%s: %s' -I '%s'", curlAuth, header, hostinjProbeHost, baseURL),
		)
		f.Evidence = fmt.Sprintf("Заголовок: %s: %s\nЗеркало найдено в: %s\nHTTP %d",
			header, hostinjProbeHost, strings.Join(where, ", "), resp.StatusCode)
		store.Add(f)
		return // One finding per base_url is enough
	}
}

// hostinjCheckResetPoisoning mirrors _check_reset_poisoning — tries to
// trigger a password reset and checks if the injected Host appears in the
// response.
func hostinjCheckResetPoisoning(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, curlAuth string, store *findings.FindingStore) {
	// Collect reset endpoints from crawl + static list.
	resetURLs := make(map[string]struct{})
	for _, ep := range endpoints {
		urlLower := strings.ToLower(ep.URL)
		for _, p := range hostinjResetPaths {
			if strings.Contains(urlLower, p) {
				resetURLs[ep.URL] = struct{}{}
				break
			}
		}
	}
	for _, path := range hostinjResetPaths {
		resetURLs[strings.TrimRight(baseURL, "/")+path] = struct{}{}
	}

	count := 0
	for u := range resetURLs {
		if count >= 12 {
			break
		}
		count++

		// Quick GET probe — skip if 404/410.
		probe, err := session.Request("GET", u, httpsession.Options{AllowRedirects: false, Timeout: 15 * time.Second})
		if err != nil {
			continue
		}
		if probe.StatusCode == 404 || probe.StatusCode == 410 {
			continue
		}

		for _, header := range []string{"Host", "X-Forwarded-Host"} {
			extra := map[string]string{header: hostinjProbeHost}
			if header == "Host" {
				extra["X-Forwarded-Host"] = hostinjProbeHost
			}

			form := url.Values{"email": {"pentest-probe@example.com"}}
			h := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
			for k, v := range extra {
				h[k] = v
			}

			resp, err := session.Request("POST", u, httpsession.Options{
				Headers:        h,
				Body:           strings.NewReader(form.Encode()),
				AllowRedirects: false,
				Timeout:        15 * time.Second,
			})
			if err != nil {
				continue
			}

			switch resp.StatusCode {
			case 200, 201, 202, 204, 302, 301:
			default:
				continue
			}

			if !strings.Contains(strings.ToLower(resp.Body), strings.ToLower(hostinjProbeHost)) {
				continue
			}

			f := findings.NewFinding(
				"Password Reset Poisoning — Host header в теле ответа сброса пароля",
				findings.High,
				"Authentication",
				"CWE-640",
				u,
				fmt.Sprintf("Endpoint %s принял POST с поддельным %s "+
					"и отразил '%s' в теле ответа.\n\n"+
					"Если сервер использует Host для формирования ссылки в reset-письме, "+
					"атакующий может перехватить токен сброса пароля:\n"+
					"1. Злоумышленник инициирует сброс для жертвы с Host: evil.com\n"+
					"2. Жертва получает письмо со ссылкой https://evil.com/reset?token=...\n"+
					"3. При клике — токен улетает на сервер атакующего\n"+
					"4. Атакующий меняет пароль жертвы",
					u, header, hostinjProbeHost),
				"1. Генерируйте reset-ссылки с доменом из конфигурации приложения, "+
					"   НЕ из заголовка Host.\n"+
					"2. Добавьте whitelist разрешённых доменов для Host/X-Forwarded-Host.\n"+
					"3. Проверьте: config('app.url') в Laravel, settings.ALLOWED_HOSTS в Django, "+
					"   ServerName в Apache, server_name в nginx.",
				fmt.Sprintf("curl -sk %s -X POST -H 'Host: %s' -H 'X-Forwarded-Host: %s' -d 'email=victim@target.com' '%s'",
					curlAuth, hostinjProbeHost, hostinjProbeHost, u),
			)
			f.Method = "POST"
			f.Evidence = fmt.Sprintf("%s: %s → '%s' найдено в ответе\nHTTP %d",
				header, hostinjProbeHost, hostinjProbeHost, resp.StatusCode)
			store.Add(f)
			return // One finding is enough
		}
	}
}
