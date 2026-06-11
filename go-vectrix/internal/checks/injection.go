package checks

import (
	"encoding/json"
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

// ── SQL Injection payloads ──────────────────────────────────────────────────

type injPayload struct {
	payload   string
	technique string
}

var sqliErrorPayloads = []injPayload{
	{"'", "SQL error-based (single quote)"},
	{`"`, "SQL error-based (double quote)"},
	{"'--", "SQL comment injection"},
	{"' OR '1'='1", "SQL OR-based bypass"},
	{"1' AND 1=CONVERT(int,@@version)--", "MSSQL version probe"},
	{"1' AND extractvalue(1,concat(0x7e,version()))--", "MySQL extractvalue"},
	{"'||(SELECT 1 FROM dual)--", "Oracle probe"},
}

var sqlErrorSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)SQL syntax.*MySQL`),
	regexp.MustCompile(`(?i)Warning.*mysql_`),
	regexp.MustCompile(`(?i)MySQLSyntaxErrorException`),
	regexp.MustCompile(`ORA-\d{5}`),
	regexp.MustCompile(`(?i)Oracle.*Driver`),
	regexp.MustCompile(`(?i)SQLServer.*Driver`),
	regexp.MustCompile(`(?i)Microsoft SQL Native Client`),
	regexp.MustCompile(`(?i)ODBC SQL Server Driver`),
	regexp.MustCompile(`(?i)PostgreSQL.*ERROR`),
	regexp.MustCompile(`(?i)pg_query\(\)`),
	regexp.MustCompile(`(?i)SQLiteException`),
	regexp.MustCompile(`(?i)SQLITE_ERROR`),
	regexp.MustCompile(`(?i)Syntax error.*SQLite`),
	regexp.MustCompile(`(?i)com\.microsoft\.sqlserver`),
	regexp.MustCompile(`(?i)Unclosed quotation mark`),
	regexp.MustCompile(`(?i)quoted string not properly terminated`),
	regexp.MustCompile(`(?i)You have an error in your SQL`),
	regexp.MustCompile(`(?i)supplied argument is not a valid MySQL`),
	regexp.MustCompile(`(?i)Column count doesn't match`),
}

var sqliTimePayloads = []injPayload{
	{"'; WAITFOR DELAY '0:0:5'--", "MSSQL time-based"},
	{"' AND SLEEP(5)--", "MySQL time-based"},
	{"'; SELECT pg_sleep(5)--", "PostgreSQL time-based"},
	{"' OR 1=1 AND SLEEP(5)--", "MySQL OR time-based"},
}

// ── XSS payloads ─────────────────────────────────────────────────────────────

var xssPayloads = []injPayload{
	{`<script>alert("XSS")</script>`, "basic script tag"},
	{`"><script>alert(1)</script>`, "tag breakout"},
	{"'><img src=x onerror=alert(1)>", "img onerror"},
	{"<svg/onload=alert(1)>", "svg onload"},
	{"javascript:alert(1)", "javascript: URI"},
	{`"><details open ontoggle=alert(1)>`, "HTML5 details tag"},
	{`<iframe srcdoc="<script>alert(1)</script>">`, "iframe srcdoc"},
	{"{{7*7}}", "SSTI probe (also XSS context)"},
}

// ── SSTI payloads ────────────────────────────────────────────────────────────

type sstiPayload struct {
	payload  string
	expected string
	engine   string
}

var sstiPayloads = []sstiPayload{
	{"{{7*7}}", "49", "Jinja2/Twig SSTI"},
	{"${7*7}", "49", "FreeMarker/EL SSTI"},
	{"<%= 7*7 %>", "49", "ERB/JSP SSTI"},
	{"#{7*7}", "49", "Thymeleaf SSTI"},
	{"*{7*7}", "49", "Thymeleaf alternate"},
}

// ── Command Injection ────────────────────────────────────────────────────────

var cmdiPayloads = []injPayload{
	{"; id", "semicolon separation"},
	{"| id", "pipe"},
	{"`id`", "backtick"},
	{"$(id)", "command substitution"},
	{"; sleep 3", "blind time-based (sleep)"},
	{"| sleep 3", "blind time-based pipe"},
}

var cmdiSignatures = []*regexp.Regexp{
	regexp.MustCompile(`uid=\d+\(\w+\)`),
	regexp.MustCompile(`root:\w+:\d+:\d+`),
}

// ── Path Traversal ───────────────────────────────────────────────────────────

var pathTraversalPayloads = []injPayload{
	{"../../../etc/passwd", "Unix LFI"},
	{"..%2F..%2F..%2Fetc%2Fpasswd", "URL-encoded LFI"},
	{"..\\..\\..\\windows\\win.ini", "Windows LFI"},
	{"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "Double URL-encoded"},
	{"....//....//....//etc/passwd", "Filter bypass"},
	{"/etc/passwd", "Absolute path"},
	{"file:///etc/passwd", "file:// URI"},
}

var lfiSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)root:.*:0:0:`),
	regexp.MustCompile(`(?i)\[boot loader\]`),
	regexp.MustCompile(`(?i)\[extensions\]`),
	regexp.MustCompile(`(?i)for 16-bit app support`),
}

// ── CRLF / HTTP Response Splitting ───────────────────────────────────────────

const injCRLFMarker = "X-Vectrix-Crlf-Probe"

var crlfPayloads = []injPayload{
	{"%0d%0a" + injCRLFMarker + ":%20injected", "URL-encoded CRLF"},
	{"%0a" + injCRLFMarker + ":%20injected", "LF only (nginx)"},
	{"%E5%98%8A%E5%98%8D" + injCRLFMarker + ":%20injected", "UTF-8 overlong CRLF"},
	{"%0d%0aSet-Cookie:%20vectrix-session=injected;%20HttpOnly", "CRLF cookie injection"},
}

// ── Open Redirect ─────────────────────────────────────────────────────────────

// redirectParams lists query parameters that commonly carry redirect targets,
// in priority order. Mirrors modules/checks/injection.py REDIRECT_PARAMS —
// order matters since only the first matching param per URL is tested.
var redirectParams = []string{
	"redirect", "redirect_to", "redirect_url", "next", "url",
	"return", "returnTo", "return_url", "rurl", "dest",
	"destination", "go", "goto", "target", "link", "location",
	"continue", "ref", "callback",
}

var redirectPayloads = []string{
	"https://evil.example.com",
	"//evil.example.com",
	"///evil.example.com",
	"/\\evil.example.com",
	"https:evil.example.com",
}

// RunInjection checks SQLi (error-based + time-based), XSS, SSTI, command
// injection, path traversal/LFI, CRLF injection, and open redirect. Mirrors
// modules/checks/injection.py run().
func RunInjection(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, store *findings.FindingStore, timebased bool, deepXSS bool) {
	logging.Println("[*] Checking injection (SQLi/XSS/SSTI/CMDi/...)...")
	if timebased {
		logging.Println("  [*] Time-based blind SQLi включён (медленнее)")
	}
	curlAuth := session.CurlAuthFlags(baseURL)

	for _, ep := range endpoints {
		params := cloneValues(urlValuesFromMap(ep.Params))
		bodyParams := cloneValues(urlValuesFromMap(ep.BodyParams))

		if len(params) == 0 && len(bodyParams) == 0 {
			continue
		}

		injCheckSQLi(session, ep, params, bodyParams, curlAuth, store, timebased)
		injCheckXSS(session, ep, params, bodyParams, curlAuth, store, deepXSS)
		injCheckSSTI(session, ep, params, bodyParams, curlAuth, store)
		injCheckCMDi(session, ep, params, bodyParams, curlAuth, store)
		injCheckPathTraversal(session, ep, params, bodyParams, curlAuth, store)
		injCheckCRLF(session, ep, params, bodyParams, curlAuth, store)
	}

	injCheckOpenRedirect(session, endpoints, curlAuth, store)
}

// urlValuesFromMap converts a map[string]string (Endpoint.Params/BodyParams)
// to url.Values with single-element slices.
func urlValuesFromMap(m map[string]string) url.Values {
	v := make(url.Values, len(m))
	for k, val := range m {
		v[k] = []string{val}
	}
	return v
}

// injTargetParams returns the param list to iterate over: query params if
// non-empty, otherwise body params. Mirrors Python's
// `list(params.items()) or list(body_params.items())`.
func injTargetParams(params, bodyParams url.Values) []string {
	if len(params) > 0 {
		names := make([]string, 0, len(params))
		for k := range params {
			names = append(names, k)
		}
		return names
	}
	names := make([]string, 0, len(bodyParams))
	for k := range bodyParams {
		names = append(names, k)
	}
	return names
}

// ── SQL Injection ─────────────────────────────────────────────────────────────

func injCheckSQLi(session *httpsession.Session, ep crawler.Endpoint, params, bodyParams url.Values, curlAuth string, store *findings.FindingStore, timebased bool) {
	targetParams := injTargetParams(params, bodyParams)

	for _, paramName := range targetParams {
		// Error-based
	errorLoop:
		for _, ip := range sqliErrorPayloads {
			resp, err := injInjectParam(session, ep, paramName, ip.payload, params, bodyParams)
			if err != nil || resp == nil {
				continue
			}
			text := truncate(resp.Body, 5000)
			for _, sig := range sqlErrorSignatures {
				loc := sig.FindStringIndex(text)
				if loc == nil {
					continue
				}
				match := text[loc[0]:loc[1]]
				curlCmd := injMakeCurl(ep, paramName, ip.payload, curlAuth, params, bodyParams)

				f := findings.NewFinding(
					fmt.Sprintf("SQL Injection (Error-based) — параметр '%s'", paramName),
					findings.High,
					"Injection",
					"CWE-89",
					ep.URL,
					fmt.Sprintf("Один payload вызвал в ответе сигнатуру SQL-ошибки в параметре "+
						"'%s' (%s %s).\n"+
						"Техника: %s\n"+
						"Сигнатура в ответе: %s\n"+
						"Единичное совпадение сигнатуры может быть и обычной страницей "+
						"ошибки приложения — нужна дифференциальная проверка true/false условий.",
						paramName, ep.Method, ep.URL, ip.technique, sig.String()),
					fmt.Sprintf("1. Используйте параметризованные запросы / Prepared Statements.\n"+
						"2. Никогда не подставляйте пользовательский ввод напрямую в SQL.\n"+
						"3. Применяйте ORM с экранированием.\n"+
						"4. Запустите sqlmap для полного exploitation: "+
						"sqlmap -u '%s' -p '%s' --dbs", ep.URL, paramName),
					fmt.Sprintf("# Ручная проверка:\n%s\n\n"+
						"# Автоматизация через sqlmap:\n"+
						"sqlmap -u '%s' -p '%s' --cookie '%s' --batch --dbs",
						curlCmd, ep.URL, paramName, session.CookieString(ep.URL)),
				)
				f.Parameter = paramName
				f.Method = ep.Method
				f.Evidence = fmt.Sprintf("Payload: %s\nОтвет содержит: %s", ip.payload, truncate(match, 200))

				probeFn := func(payload string) (*httpsession.Response, error) {
					return injInjectParam(session, ep, paramName, payload, params, bodyParams)
				}

				store.AddCandidate(&findings.Candidate{
					Finding: f,
					Kind:    "sqli",
					Context: map[string]any{
						"probe":     probeFn,
						"parameter": paramName,
					},
				})
				break errorLoop
			}
		}

		// Time-based blind (only in aggressive mode)
		if !timebased {
			continue
		}
		for _, ip := range sqliTimePayloads {
			resp, elapsed, err := injInjectParamTimed(session, ep, paramName, ip.payload, params, bodyParams)
			if err != nil || resp == nil {
				continue
			}
			if elapsed >= 4500*time.Millisecond {
				curlCmd := injMakeCurl(ep, paramName, ip.payload, curlAuth, params, bodyParams)
				f := findings.NewFinding(
					fmt.Sprintf("SQL Injection (Time-based Blind) — параметр '%s'", paramName),
					findings.Critical,
					"Injection",
					"CWE-89",
					ep.URL,
					fmt.Sprintf("Обнаружена слепая SQL-инъекция (задержка %.1fс) "+
						"в параметре '%s'.\nТехника: %s",
						elapsed.Seconds(), paramName, ip.technique),
					"1. Параметризованные запросы / Prepared Statements.\n"+
						"2. Проверьте все точки формирования SQL-запросов.",
					fmt.Sprintf("# Ручная проверка (ожидайте задержку ~5с):\n%s\n\n"+
						"# sqlmap (time-based):\n"+
						"sqlmap -u '%s' -p '%s' --cookie '%s' --technique=T --batch",
						curlCmd, ep.URL, paramName, session.CookieString(ep.URL)),
				)
				f.Parameter = paramName
				f.Method = ep.Method
				f.Evidence = fmt.Sprintf("Payload: %s\nВремя ответа: %.1fс (норма ~%gс timeout)", ip.payload, elapsed.Seconds(), injSessionTimeoutSeconds(session))
				store.Add(f)
				break
			}
		}
	}
}

// ── XSS ────────────────────────────────────────────────────────────────────

func injCheckXSS(session *httpsession.Session, ep crawler.Endpoint, params, bodyParams url.Values, curlAuth string, store *findings.FindingStore, deep bool) {
	targetParams := injTargetParams(params, bodyParams)

	payloads := xssPayloads[:4]
	if deep {
		payloads = xssPayloads
	}

	for _, paramName := range targetParams {
		for _, ip := range payloads {
			resp, err := injInjectParam(session, ep, paramName, ip.payload, params, bodyParams)
			if err != nil || resp == nil {
				continue
			}
			ct := strings.ToLower(resp.Header.Get("Content-Type"))
			if !strings.Contains(ct, "html") && !strings.Contains(ct, "text/") {
				continue
			}
			escaped := strings.ReplaceAll(ip.payload, `"`, "&quot;")
			if strings.Contains(resp.Body, ip.payload) || strings.Contains(resp.Body, escaped) {
				curlCmd := injMakeCurl(ep, paramName, ip.payload, curlAuth, params, bodyParams)
				f := findings.NewFinding(
					fmt.Sprintf("Reflected XSS — параметр '%s'", paramName),
					findings.High,
					"XSS",
					"CWE-79",
					ep.URL,
					fmt.Sprintf("Параметр '%s' отражает введённые данные без экранирования. "+
						"Техника: %s.", paramName, ip.technique),
					"1. Экранируйте вывод в HTML-контексте: htmlspecialchars(), escapeHtml().\n"+
						"2. Используйте Content-Security-Policy с nonces.\n"+
						"3. Атрибут HttpOnly на сессионных cookies.",
					fmt.Sprintf("# Откройте в браузере:\n"+
						"%s?%s=%s\n\n"+
						"# Или через curl:\n%s",
						ep.URL, paramName, ip.payload, curlCmd),
				)
				f.Parameter = paramName
				f.Method = ep.Method
				f.Evidence = fmt.Sprintf("Payload: %s\nНайден в ответе без изменений", ip.payload)
				store.Add(f)
				break
			}
		}
	}
}

// ── SSTI ──────────────────────────────────────────────────────────────────────

func injCheckSSTI(session *httpsession.Session, ep crawler.Endpoint, params, bodyParams url.Values, curlAuth string, store *findings.FindingStore) {
	targetParams := injTargetParams(params, bodyParams)

	for _, paramName := range targetParams {
		for _, sp := range sstiPayloads {
			resp, err := injInjectParam(session, ep, paramName, sp.payload, params, bodyParams)
			if err != nil || resp == nil {
				continue
			}
			if strings.Contains(resp.Body, sp.expected) {
				curlCmd := injMakeCurl(ep, paramName, sp.payload, curlAuth, params, bodyParams)
				f := findings.NewFinding(
					fmt.Sprintf("Server-Side Template Injection (SSTI) — параметр '%s'", paramName),
					findings.Critical,
					"Injection",
					"CWE-94",
					ep.URL,
					fmt.Sprintf("Шаблонное выражение '%s' вычислилось как '%s' "+
						"в параметре '%s'. Движок: %s.\n"+
						"SSTI позволяет выполнять произвольный код на сервере.",
						sp.payload, sp.expected, paramName, sp.engine),
					"1. Никогда не подставляйте пользовательский ввод в шаблон напрямую.\n"+
						"2. Используйте sandbox-окружение шаблонизатора.\n"+
						"3. Валидируйте и нормализуйте входные данные до передачи в шаблон.",
					fmt.Sprintf("# Базовая проверка (ожидаемый ответ: %s):\n"+
						"%s\n\n"+
						"# RCE через Jinja2 (при подтверждённом SSTI):\n"+
						"# Payload: {{''.__class__.__mro__[1].__subclasses__()}}",
						sp.expected, curlCmd),
				)
				f.Parameter = paramName
				f.Method = ep.Method
				f.Evidence = fmt.Sprintf("Payload: %s → ответ содержит: %s", sp.payload, sp.expected)
				store.Add(f)
				break
			}
		}
	}
}

// ── Command Injection ──────────────────────────────────────────────────────────

func injCheckCMDi(session *httpsession.Session, ep crawler.Endpoint, params, bodyParams url.Values, curlAuth string, store *findings.FindingStore) {
	targetParams := injTargetParams(params, bodyParams)

	for _, paramName := range targetParams {
		for _, ip := range cmdiPayloads {
			resp, err := injInjectParam(session, ep, paramName, ip.payload, params, bodyParams)
			if err != nil || resp == nil {
				continue
			}
			for _, sig := range cmdiSignatures {
				loc := sig.FindStringIndex(resp.Body)
				if loc == nil {
					continue
				}
				match := resp.Body[loc[0]:loc[1]]
				curlCmd := injMakeCurl(ep, paramName, ip.payload, curlAuth, params, bodyParams)
				f := findings.NewFinding(
					fmt.Sprintf("Command Injection — параметр '%s'", paramName),
					findings.Critical,
					"Injection",
					"CWE-78",
					ep.URL,
					fmt.Sprintf("Вывод команды '%s' обнаружен в ответе. "+
						"Параметр '%s' передаётся в системный вызов без фильтрации.",
						strings.TrimSpace(ip.payload), paramName),
					"1. Избегайте передачи пользовательского ввода в shell-команды.\n"+
						"2. Используйте execv/execve с массивом аргументов (без shell=True).\n"+
						"3. Белый список допустимых значений параметра.",
					curlCmd,
				)
				f.Parameter = paramName
				f.Method = ep.Method
				f.Evidence = fmt.Sprintf("Payload: %s\nОтвет: %s", ip.payload, truncate(match, 200))
				store.Add(f)
				break
			}
		}
	}
}

// ── Path Traversal / LFI ─────────────────────────────────────────────────────

func injCheckPathTraversal(session *httpsession.Session, ep crawler.Endpoint, params, bodyParams url.Values, curlAuth string, store *findings.FindingStore) {
	targetParams := injTargetParams(params, bodyParams)

	for _, paramName := range targetParams {
		for _, ip := range pathTraversalPayloads {
			resp, err := injInjectParam(session, ep, paramName, ip.payload, params, bodyParams)
			if err != nil || resp == nil {
				continue
			}
			for _, sig := range lfiSignatures {
				loc := sig.FindStringIndex(resp.Body)
				if loc == nil {
					continue
				}
				match := resp.Body[loc[0]:loc[1]]
				curlCmd := injMakeCurl(ep, paramName, ip.payload, curlAuth, params, bodyParams)
				f := findings.NewFinding(
					fmt.Sprintf("Path Traversal / LFI — параметр '%s'", paramName),
					findings.Critical,
					"Injection",
					"CWE-22",
					ep.URL,
					fmt.Sprintf("Параметр '%s' позволяет читать файлы за пределами webroot. "+
						"Техника: %s.", paramName, ip.technique),
					"1. Нормализуйте путь и проверяйте, что он находится внутри разрешённой директории.\n"+
						"2. Используйте basename() перед подстановкой имён файлов.\n"+
						"3. Белый список допустимых файлов.",
					curlCmd,
				)
				f.Parameter = paramName
				f.Method = ep.Method
				f.Evidence = fmt.Sprintf("Payload: %s\nОтвет содержит: %s", ip.payload, truncate(match, 200))
				store.Add(f)
				break
			}
		}
	}
}

// ── CRLF / HTTP Response Splitting ───────────────────────────────────────────

func injCheckCRLF(session *httpsession.Session, ep crawler.Endpoint, params, bodyParams url.Values, curlAuth string, store *findings.FindingStore) {
	targetParams := injTargetParams(params, bodyParams)
	markerLower := strings.ToLower(injCRLFMarker)

	for _, paramName := range targetParams {
		for _, ip := range crlfPayloads {
			resp, err := injInjectParam(session, ep, paramName, ip.payload, params, bodyParams)
			if err != nil || resp == nil {
				continue
			}

			injectedInHeaders := false
			for k, vals := range resp.Header {
				if strings.ToLower(k) == markerLower {
					injectedInHeaders = true
					break
				}
				if strings.ToLower(k) == "vectrix-session" {
					injectedInHeaders = true
					break
				}
				for _, v := range vals {
					if strings.Contains(strings.ToLower(v), markerLower) {
						injectedInHeaders = true
						break
					}
				}
				if injectedInHeaders {
					break
				}
			}

			if !injectedInHeaders {
				location := resp.Header.Get("Location")
				setCookie := resp.Header.Get("Set-Cookie")
				if strings.Contains(location, "\r\n") || strings.Contains(location, "\n") ||
					strings.Contains(strings.ToLower(setCookie), "vectrix") {
					injectedInHeaders = true
				}
			}

			if !injectedInHeaders {
				continue
			}

			curlCmd := injMakeCurl(ep, paramName, ip.payload, curlAuth, params, bodyParams)
			f := findings.NewFinding(
				fmt.Sprintf("CRLF Injection / HTTP Response Splitting — параметр '%s'", paramName),
				findings.High,
				"Injection",
				"CWE-113",
				ep.URL,
				fmt.Sprintf("Параметр '%s' (%s %s) отражается "+
					"в HTTP-заголовках ответа без фильтрации символов CR (\\r) / LF (\\n).\n"+
					"Техника: %s\n\n"+
					"Последствия:\n"+
					"• HTTP Response Splitting → cache poisoning\n"+
					"• Инъекция Set-Cookie (угон сессии, XSS через cookie)\n"+
					"• Обход WAF / security headers\n"+
					"• Log injection (подделка записей в логах)",
					paramName, ep.Method, ep.URL, ip.technique),
				"1. Фильтруйте или отклоняйте CR (\\r, %0d) и LF (\\n, %0a) "+
					"   во всех входных данных, используемых для формирования заголовков.\n"+
					"2. Используйте функции безопасного формирования заголовков фреймворка "+
					"   вместо ручной конкатенации строк.\n"+
					"3. Включите заголовок Content-Security-Policy для ограничения последствий.",
				curlCmd,
			)
			f.Parameter = paramName
			f.Method = ep.Method
			f.Evidence = fmt.Sprintf("Payload: %s\nИнъектированный заголовок найден в ответе", truncate(ip.payload, 100))
			store.Add(f)
			break
		}
	}
}

// ── Open Redirect ─────────────────────────────────────────────────────────────

func injCheckOpenRedirect(session *httpsession.Session, endpoints []crawler.Endpoint, curlAuth string, store *findings.FindingStore) {
	checked := make(map[string]struct{})

	for _, ep := range endpoints {
		parsed, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}
		qs := parsed.Query()

		for _, param := range redirectParams {
			if _, ok := qs[param]; !ok {
				continue
			}
			if _, done := checked[ep.URL]; done {
				continue
			}
			checked[ep.URL] = struct{}{}

			for _, payload := range redirectPayloads {
				newQS := cloneValues(qs)
				newQS.Set(param, payload)
				newU := *parsed
				newU.RawQuery = newQS.Encode()
				newU.Fragment = ""
				newURL := newU.String()

				resp, err := session.Request("GET", newURL, httpsession.Options{AllowRedirects: false, Timeout: 8 * time.Second})
				if err != nil {
					continue
				}
				loc := resp.Header.Get("Location")
				if strings.Contains(loc, "evil.example.com") {
					f := findings.NewFinding(
						fmt.Sprintf("Open Redirect — параметр '%s'", param),
						findings.Medium,
						"Open Redirect",
						"CWE-601",
						ep.URL,
						fmt.Sprintf("Параметр '%s' принимает произвольный URL для редиректа. "+
							"Используется в фишинге: жертва видит ссылку на доверенный домен, "+
							"а затем переадресовывается на вредоносный сайт.", param),
						"1. Разрешайте редирект только на известные пути (relative URLs).\n"+
							"2. Валидируйте домен по белому списку.\n"+
							"3. Предупреждайте пользователя при переходе на внешний ресурс.",
						fmt.Sprintf("curl -sk %s -I '%s'", curlAuth, newURL),
					)
					f.Parameter = param
					f.Evidence = fmt.Sprintf("Location: %s", loc)
					store.Add(f)
					break
				}
			}
		}
	}
}

// injSessionTimeoutSeconds returns the session's configured timeout in
// seconds, defaulting to 15 (mirrors Python's getattr(session, 'timeout', 15)).
func injSessionTimeoutSeconds(session *httpsession.Session) float64 {
	if session.Timeout == 0 {
		return 15
	}
	return session.Timeout.Seconds()
}

// ── Helpers ────────────────────────────────────────────────────────────────────

// injInjectParam re-sends the endpoint's request with paramName replaced by
// payload, either as a query parameter (GET/HEAD) or a body parameter
// (POST/PUT/...). Mirrors Python's _inject_param.
func injInjectParam(session *httpsession.Session, ep crawler.Endpoint, paramName, payload string, params, bodyParams url.Values) (*httpsession.Response, error) {
	if ep.Method == "GET" || ep.Method == "HEAD" || ep.Method == "" {
		newParams := cloneValues(params)
		newParams.Set(paramName, payload)

		parsed, err := url.Parse(ep.URL)
		if err != nil {
			return nil, err
		}
		newU := *parsed
		newU.RawQuery = newParams.Encode()
		newU.Fragment = ""

		method := ep.Method
		if method == "" {
			method = "GET"
		}
		return session.Request(method, newU.String(), httpsession.Options{AllowRedirects: true})
	}

	newBody := cloneValues(bodyParams)
	newBody.Set(paramName, payload)

	ct := ep.ContentType
	if ct == "" {
		ct = "application/x-www-form-urlencoded"
	}

	if strings.Contains(strings.ToLower(ct), "json") {
		jsonBody := make(map[string]string, len(newBody))
		for k, vals := range newBody {
			if len(vals) > 0 {
				jsonBody[k] = vals[0]
			}
		}
		b, err := json.Marshal(jsonBody)
		if err != nil {
			return nil, err
		}
		return session.Request(ep.Method, ep.URL, httpsession.Options{
			Headers:        map[string]string{"Content-Type": "application/json"},
			Body:           strings.NewReader(string(b)),
			AllowRedirects: true,
		})
	}

	return session.Request(ep.Method, ep.URL, httpsession.Options{
		Headers:        map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:           strings.NewReader(newBody.Encode()),
		AllowRedirects: true,
	})
}

// injInjectParamTimed performs injInjectParam while measuring elapsed time,
// using an extended timeout (base + 6s) to allow time-based payloads to
// complete. Mirrors Python's _inject_param_timed.
func injInjectParamTimed(session *httpsession.Session, ep crawler.Endpoint, paramName, payload string, params, bodyParams url.Values) (*httpsession.Response, time.Duration, error) {
	timeout := session.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	timeout += 6 * time.Second

	start := time.Now()

	var resp *httpsession.Response
	var err error
	if ep.Method == "GET" || ep.Method == "HEAD" || ep.Method == "" {
		newParams := cloneValues(params)
		newParams.Set(paramName, payload)

		parsed, perr := url.Parse(ep.URL)
		if perr != nil {
			return nil, 0, perr
		}
		newU := *parsed
		newU.RawQuery = newParams.Encode()
		newU.Fragment = ""

		method := ep.Method
		if method == "" {
			method = "GET"
		}
		resp, err = session.Request(method, newU.String(), httpsession.Options{AllowRedirects: true, Timeout: timeout})
	} else {
		newBody := cloneValues(bodyParams)
		newBody.Set(paramName, payload)

		ct := ep.ContentType
		if ct == "" {
			ct = "application/x-www-form-urlencoded"
		}
		if strings.Contains(strings.ToLower(ct), "json") {
			jsonBody := make(map[string]string, len(newBody))
			for k, vals := range newBody {
				if len(vals) > 0 {
					jsonBody[k] = vals[0]
				}
			}
			b, jerr := json.Marshal(jsonBody)
			if jerr != nil {
				return nil, 0, jerr
			}
			resp, err = session.Request(ep.Method, ep.URL, httpsession.Options{
				Headers:        map[string]string{"Content-Type": "application/json"},
				Body:           strings.NewReader(string(b)),
				AllowRedirects: true,
				Timeout:        timeout,
			})
		} else {
			resp, err = session.Request(ep.Method, ep.URL, httpsession.Options{
				Headers:        map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
				Body:           strings.NewReader(newBody.Encode()),
				AllowRedirects: true,
				Timeout:        timeout,
			})
		}
	}

	elapsed := time.Since(start)
	return resp, elapsed, err
}

// injMakeCurl builds a curl reproduction command for the given param/payload
// substitution. Mirrors Python's _make_curl.
func injMakeCurl(ep crawler.Endpoint, paramName, payload, curlAuth string, params, bodyParams url.Values) string {
	if ep.Method == "GET" || ep.Method == "" || len(bodyParams) == 0 {
		p := cloneValues(params)
		p.Set(paramName, payload)
		parsed, err := url.Parse(ep.URL)
		if err != nil {
			return fmt.Sprintf("curl -sk %s '%s'", curlAuth, ep.URL)
		}
		newU := *parsed
		newU.RawQuery = p.Encode()
		newU.Fragment = ""
		return fmt.Sprintf("curl -sk %s '%s'", curlAuth, newU.String())
	}

	body := cloneValues(bodyParams)
	body.Set(paramName, payload)
	return fmt.Sprintf("curl -sk %s -X %s -d '%s' '%s'", curlAuth, ep.Method, body.Encode(), ep.URL)
}
