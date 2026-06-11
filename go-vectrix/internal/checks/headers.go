// Package checks contains the deterministic security checks ported from
// modules/checks/*.py.
package checks

import (
	"fmt"
	"strconv"
	"strings"

	"vectrixgo/internal/crawler"
	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
)

// RunHeaders checks the response headers of base_url for missing/misconfigured
// security headers. Mirrors modules/checks/headers.py run().
func RunHeaders(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, store *findings.FindingStore) {
	logging.Println("[*] Checking security headers...")
	resp, err := session.Get(baseURL, nil)
	if err != nil {
		logging.Printf("  [!] Headers check failed: %v", err)
		return
	}

	headers := lowerHeaders(resp.Header)
	curlAuth := session.CurlAuthFlags(baseURL)

	checkCSP(headers, baseURL, curlAuth, store)
	checkHSTS(headers, baseURL, curlAuth, store)
	checkXFrame(headers, baseURL, curlAuth, store)
	checkXContent(headers, baseURL, curlAuth, store)
	checkReferrer(headers, baseURL, curlAuth, store)
	checkPermissions(headers, baseURL, curlAuth, store)
	checkServerBanner(headers, baseURL, store)
	checkCORSWildcard(headers, baseURL, curlAuth, session, store)
	checkCacheControl(headers, baseURL, curlAuth, store)
}

// lowerHeaders flattens an http.Header into a lower-cased single-value map,
// matching Python's `{k.lower(): v for k, v in resp.headers.items()}`.
func lowerHeaders(h map[string][]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			out[strings.ToLower(k)] = v[0]
		}
	}
	return out
}

func checkCSP(headers map[string]string, url, curlAuth string, store *findings.FindingStore) {
	csp := headers["content-security-policy"]
	if csp == "" {
		f := findings.NewFinding(
			"Отсутствует заголовок Content-Security-Policy",
			findings.Medium,
			"Security Headers",
			"CWE-693",
			url,
			"Заголовок Content-Security-Policy не установлен. "+
				"Это позволяет XSS-атакам загружать произвольные скрипты из внешних источников.",
			"Добавьте строгий CSP. Минимум: "+
				"Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
			fmt.Sprintf("curl -sk %s -I '%s' | grep -i content-security", curlAuth, url),
		)
		f.Evidence = "Заголовок Content-Security-Policy отсутствует в ответе"
		store.Add(f)
		return
	}

	var issues []string
	lowerCSP := strings.ToLower(csp)
	if strings.Contains(csp, "unsafe-inline") && strings.Contains(lowerCSP, "script-src") {
		issues = append(issues, "'unsafe-inline' в script-src нейтрализует защиту от XSS")
	}
	if strings.Contains(csp, "unsafe-eval") {
		issues = append(issues, "'unsafe-eval' разрешает выполнение eval(), что опасно")
	}
	if strings.Contains(csp, "* ") || strings.HasSuffix(strings.TrimSpace(csp), "*") {
		issues = append(issues, "wildcard (*) в CSP разрешает любые источники")
	}
	if strings.Contains(csp, "http://") {
		issues = append(issues, "CSP разрешает небезопасные http:// источники")
	}
	if len(issues) > 0 {
		f := findings.NewFinding(
			"Небезопасная конфигурация Content-Security-Policy",
			findings.Medium,
			"Security Headers",
			"CWE-693",
			url,
			"CSP установлен, но содержит небезопасные директивы:\n• "+strings.Join(issues, "\n• "),
			"Уберите 'unsafe-inline', 'unsafe-eval' и wildcard из CSP. Используйте nonces или hashes.",
			fmt.Sprintf("curl -sk %s -I '%s' | grep -i content-security", curlAuth, url),
		)
		f.Evidence = fmt.Sprintf("CSP: %s", truncate(csp, 300))
		store.Add(f)
	}
}

func checkHSTS(headers map[string]string, url, curlAuth string, store *findings.FindingStore) {
	if !strings.HasPrefix(url, "https://") {
		return
	}
	hsts := headers["strict-transport-security"]
	if hsts == "" {
		f := findings.NewFinding(
			"Отсутствует HTTP Strict Transport Security (HSTS)",
			findings.Medium,
			"Security Headers",
			"CWE-319",
			url,
			"Заголовок HSTS не установлен. Браузеры могут быть принудительно переключены "+
				"на HTTP, что делает возможными атаки типа SSL stripping / MITM.",
			"Добавьте: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
			fmt.Sprintf("curl -sk %s -I '%s' | grep -i strict", curlAuth, url),
		)
		f.Evidence = "Заголовок Strict-Transport-Security отсутствует"
		store.Add(f)
		return
	}

	if strings.Contains(hsts, "max-age=0") {
		f := findings.NewFinding(
			"HSTS установлен с max-age=0 (отключён)",
			findings.Medium,
			"Security Headers",
			"CWE-319",
			url,
			"HSTS установлен с max-age=0, что фактически отключает его.",
			"Установите max-age минимум 31536000 (1 год).",
			fmt.Sprintf("curl -sk %s -I '%s' | grep -i strict", curlAuth, url),
		)
		f.Evidence = fmt.Sprintf("Strict-Transport-Security: %s", hsts)
		store.Add(f)
	} else if strings.Contains(hsts, "max-age=") {
		rest := strings.SplitN(hsts, "max-age=", 2)[1]
		rest = strings.SplitN(rest, ";", 2)[0]
		rest = strings.SplitN(rest, ",", 2)[0]
		rest = strings.TrimSpace(rest)
		if age, err := strconv.Atoi(rest); err == nil {
			if age < 15768000 {
				f := findings.NewFinding(
					fmt.Sprintf("HSTS max-age слишком мал (%d сек)", age),
					findings.Low,
					"Security Headers",
					"CWE-319",
					url,
					fmt.Sprintf("max-age=%d меньше рекомендуемых 6 месяцев (15768000).", age),
					"Установите max-age минимум 15768000.",
					fmt.Sprintf("curl -sk %s -I '%s' | grep -i strict", curlAuth, url),
				)
				f.Evidence = fmt.Sprintf("Strict-Transport-Security: %s", hsts)
				store.Add(f)
			}
		}
	}
}

func checkXFrame(headers map[string]string, url, curlAuth string, store *findings.FindingStore) {
	xfo := headers["x-frame-options"]
	csp := headers["content-security-policy"]
	hasFrameInCSP := strings.Contains(strings.ToLower(csp), "frame-ancestors")
	if xfo == "" && !hasFrameInCSP {
		f := findings.NewFinding(
			"Отсутствует защита от Clickjacking (X-Frame-Options / CSP frame-ancestors)",
			findings.Medium,
			"Security Headers",
			"CWE-1021",
			url,
			"Ни X-Frame-Options, ни CSP frame-ancestors не установлены. "+
				"Приложение может быть встроено в iframe на стороннем сайте (clickjacking).",
			"Добавьте: X-Frame-Options: DENY\nИли в CSP: Content-Security-Policy: frame-ancestors 'none';",
			fmt.Sprintf("# Создайте HTML-файл и откройте в браузере:\n"+
				"echo '<iframe src=\"%s\"></iframe>' > /tmp/clickjack.html && xdg-open /tmp/clickjack.html", url),
		)
		f.Evidence = "X-Frame-Options отсутствует, frame-ancestors в CSP не задан"
		store.Add(f)
	}
}

func checkXContent(headers map[string]string, url, curlAuth string, store *findings.FindingStore) {
	if headers["x-content-type-options"] == "" {
		f := findings.NewFinding(
			"Отсутствует X-Content-Type-Options",
			findings.Low,
			"Security Headers",
			"CWE-693",
			url,
			"Заголовок X-Content-Type-Options: nosniff не установлен. "+
				"Браузер может интерпретировать ответы не по объявленному Content-Type "+
				"(MIME sniffing), что открывает вектор для некоторых XSS-атак.",
			"Добавьте: X-Content-Type-Options: nosniff",
			fmt.Sprintf("curl -sk %s -I '%s' | grep -i x-content-type", curlAuth, url),
		)
		f.Evidence = "X-Content-Type-Options отсутствует"
		store.Add(f)
	}
}

func checkReferrer(headers map[string]string, url, curlAuth string, store *findings.FindingStore) {
	rp := headers["referrer-policy"]
	if rp == "" {
		f := findings.NewFinding(
			"Отсутствует Referrer-Policy",
			findings.Low,
			"Security Headers",
			"CWE-116",
			url,
			"Referrer-Policy не установлен. URL с токенами и параметрами сессии "+
				"могут утекать в Referer-заголовке к третьим сторонам.",
			"Добавьте: Referrer-Policy: strict-origin-when-cross-origin",
			fmt.Sprintf("curl -sk %s -I '%s' | grep -i referrer", curlAuth, url),
		)
		f.Evidence = "Referrer-Policy отсутствует"
		store.Add(f)
	} else if lower := strings.ToLower(rp); lower == "unsafe-url" || lower == "no-referrer-when-downgrade" {
		f := findings.NewFinding(
			fmt.Sprintf("Небезопасный Referrer-Policy: %s", rp),
			findings.Low,
			"Security Headers",
			"CWE-116",
			url,
			fmt.Sprintf("Значение '%s' передаёт полный URL (включая query string) как Referer.", rp),
			"Установите: Referrer-Policy: strict-origin-when-cross-origin",
			fmt.Sprintf("curl -sk %s -I '%s' | grep -i referrer", curlAuth, url),
		)
		f.Evidence = fmt.Sprintf("Referrer-Policy: %s", rp)
		store.Add(f)
	}
}

func checkPermissions(headers map[string]string, url, curlAuth string, store *findings.FindingStore) {
	if headers["permissions-policy"] == "" && headers["feature-policy"] == "" {
		f := findings.NewFinding(
			"Отсутствует Permissions-Policy",
			findings.Info,
			"Security Headers",
			"CWE-693",
			url,
			"Permissions-Policy не установлен. Рекомендуется явно ограничивать "+
				"доступ страниц к браузерным API (камера, микрофон, геолокация и пр.).",
			"Добавьте: Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()",
			fmt.Sprintf("curl -sk %s -I '%s' | grep -i permissions-policy", curlAuth, url),
		)
		f.Evidence = "Permissions-Policy отсутствует"
		store.Add(f)
	}
}

func checkServerBanner(headers map[string]string, url string, store *findings.FindingStore) {
	var leaks []string
	for _, h := range []string{"server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime"} {
		if v := headers[h]; v != "" {
			leaks = append(leaks, fmt.Sprintf("%s: %s", h, v))
		}
	}
	if len(leaks) > 0 {
		f := findings.NewFinding(
			"Раскрытие информации о серверном ПО через заголовки",
			findings.Low,
			"Information Disclosure",
			"CWE-200",
			url,
			"HTTP-ответ содержит заголовки, раскрывающие тип и версию серверного ПО. "+
				"Это помогает злоумышленнику подобрать известные CVE.",
			"Скройте или удалите информационные заголовки: "+
				"ServerTokens Prod (Apache), server_tokens off (nginx), removeHeaders в web.config (IIS).",
			fmt.Sprintf("curl -sk -I '%s' | grep -iE 'server|x-powered-by|x-asp'", url),
		)
		f.Evidence = strings.Join(leaks, "\n")
		store.Add(f)
	}
}

func checkCORSWildcard(headers map[string]string, url, curlAuth string, session *httpsession.Session, store *findings.FindingStore) {
	resp, err := session.Get(url, map[string]string{"Origin": "https://evil.example.com"})
	if err != nil {
		return
	}
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))

	if acao == "*" {
		f := findings.NewFinding(
			"CORS: wildcard Access-Control-Allow-Origin",
			findings.Low,
			"CORS",
			"CWE-942",
			url,
			"Сервер возвращает Access-Control-Allow-Origin: * — любой сайт может читать ответы через XHR.",
			"Ограничьте CORS конкретными доменами. Никогда не используйте '*' с credentials.",
			fmt.Sprintf("curl -sk %s -H 'Origin: https://evil.example.com' -I '%s' | grep -i access-control", curlAuth, url),
		)
		f.Evidence = fmt.Sprintf("Access-Control-Allow-Origin: %s", acao)
		store.Add(f)
	} else if acao != "" && acac == "true" {
		f := findings.NewFinding(
			"CORS: отражение Origin с Allow-Credentials: true",
			findings.High,
			"CORS",
			"CWE-942",
			url,
			fmt.Sprintf("Сервер отражает Origin '%s' и устанавливает Allow-Credentials: true. "+
				"Атакующий может совершать аутентифицированные cross-origin запросы.", acao),
			"Проверяйте Origin по белому списку, не используйте отражение произвольного Origin.",
			fmt.Sprintf("curl -sk %s -H 'Origin: https://evil.example.com' -I '%s' | grep -i access-control", curlAuth, url),
		)
		f.Evidence = fmt.Sprintf("ACAO: %s\nACAC: %s", acao, acac)
		store.Add(f)
	}
}

func checkCacheControl(headers map[string]string, url, curlAuth string, store *findings.FindingStore) {
	cc := strings.ToLower(headers["cache-control"])
	ct := strings.ToLower(headers["content-type"])
	if !strings.Contains(ct, "html") && !strings.Contains(ct, "json") {
		return
	}
	if !strings.Contains(cc, "no-store") && !strings.Contains(cc, "no-cache") && !strings.Contains(cc, "private") {
		evidence := cc
		if evidence == "" {
			evidence = "(не задан)"
		}
		f := findings.NewFinding(
			"Отсутствует Cache-Control: no-store на динамической странице",
			findings.Low,
			"Security Headers",
			"CWE-524",
			url,
			"Динамическая страница кэшируется браузером или промежуточными прокси. "+
				"Чувствительные данные (токены, ПДн) могут быть сохранены в кэше.",
			"Добавьте для аутентифицированных страниц: Cache-Control: no-store, no-cache, must-revalidate",
			fmt.Sprintf("curl -sk %s -I '%s' | grep -i cache-control", curlAuth, url),
		)
		f.Evidence = fmt.Sprintf("Cache-Control: %s", evidence)
		store.Add(f)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
