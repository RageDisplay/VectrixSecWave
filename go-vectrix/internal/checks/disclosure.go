package checks

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"vectrixgo/internal/crawler"
	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
)

type sensitivePath struct {
	path  string
	label string
}

// sensitivePaths is checked against base_url. Order mirrors
// modules/checks/disclosure.py SENSITIVE_PATHS (dict insertion order).
var sensitivePaths = []sensitivePath{
	{"/swagger.json", "Swagger JSON (API schema)"},
	{"/swagger.yaml", "Swagger YAML"},
	{"/swagger-ui.html", "Swagger UI"},
	{"/swagger-ui/", "Swagger UI"},
	{"/api-docs", "API docs"},
	{"/openapi.json", "OpenAPI schema"},
	{"/openapi.yaml", "OpenAPI schema"},
	{"/graphql", "GraphQL endpoint"},
	{"/graphiql", "GraphiQL IDE"},
	{"/v1/api-docs", "Spring API docs"},
	{"/v2/api-docs", "Spring API docs v2"},
	{"/actuator", "Spring Boot Actuator"},
	{"/actuator/env", "Spring Boot env (env vars!)"},
	{"/actuator/health", "Spring Boot health"},
	{"/actuator/metrics", "Spring Boot metrics"},
	{"/actuator/beans", "Spring Boot beans"},
	{"/actuator/mappings", "Spring Boot mappings"},
	{"/actuator/trace", "Spring Boot request trace"},
	{"/actuator/httptrace", "Spring Boot HTTP trace"},
	{"/actuator/logfile", "Spring Boot logfile"},
	{"/actuator/threaddump", "Spring Boot thread dump"},
	{"/actuator/heapdump", "Spring Boot heap dump!"},
	{"/actuator/sessions", "Spring Boot sessions"},
	{"/actuator/scheduledtasks", "Spring Boot scheduled tasks"},
	{"/debug", "debug endpoint"},
	{"/console", "debug console"},
	{"/phpinfo.php", "PHP info"},
	{"/info.php", "PHP info"},
	{"/test.php", "PHP test file"},
	{"/.env", ".env file"},
	{"/.env.local", ".env.local"},
	{"/.env.development", ".env.development"},
	{"/.env.production", ".env.production"},
	{"/.git/config", "Git config"},
	{"/.git/HEAD", "Git HEAD"},
	{"/.svn/entries", "SVN entries"},
	{"/web.config", "IIS web.config"},
	{"/.htaccess", "Apache .htaccess"},
	{"/config.json", "config.json"},
	{"/config.yaml", "config.yaml"},
	{"/settings.json", "settings.json"},
	{"/app.config", "app.config"},
	{"/backup.zip", "backup archive"},
	{"/backup.sql", "SQL dump"},
	{"/db.sql", "SQL dump"},
	{"/dump.sql", "SQL dump"},
	{"/credentials.json", "credentials"},
	{"/secrets.json", "secrets"},
	{"/private.key", "private key"},
	{"/server.key", "SSL private key"},
	{"/metrics", "metrics endpoint"},
	{"/prometheus", "Prometheus metrics"},
	{"/health", "health check"},
	{"/status", "status endpoint"},
	{"/ping", "ping"},
	{"/admin", "admin panel"},
	{"/admin/login", "admin login"},
	{"/administrator", "administrator panel"},
	{"/manage", "management panel"},
	{"/wp-admin", "WordPress admin"},
	{"/phpmyadmin", "phpMyAdmin"},
}

// errorTriggers — only the first 3 are used (mirrors ERROR_TRIGGERS[:3]).
var errorTriggers = []string{
	`/'"<>{}[]()`,
	"../../../../../etc/passwd",
	"undefined",
	"\x00",
	"' OR 1=1--",
}

var verboseErrorSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Traceback \(most recent call last\)`),
	regexp.MustCompile(`(?i)at .+\([\w.]+:\d+\)`),
	regexp.MustCompile(`(?i)NullPointerException`),
	regexp.MustCompile(`(?i)ClassNotFoundException`),
	regexp.MustCompile(`(?i)Exception in thread`),
	regexp.MustCompile(`(?i)PHP Fatal error`),
	regexp.MustCompile(`(?i)PHP Warning`),
	regexp.MustCompile(`(?i)PHP Notice`),
	regexp.MustCompile(`(?i)Parse error:.*PHP`),
	regexp.MustCompile(`(?i)Warning:.*on line \d+`),
	regexp.MustCompile(`(?i)include\(.*\): failed to open stream`),
	regexp.MustCompile(`(?i)Microsoft.*ODBC.*Driver`),
	regexp.MustCompile(`(?i)ORA-\d{5}:`),
	regexp.MustCompile(`(?i)SQLSTATE\[`),
	regexp.MustCompile(`(?i)You have an error in your SQL syntax`),
	regexp.MustCompile(`(?i)Uncaught Error:`),
	regexp.MustCompile(`(?i)Unhandled Promise Rejection`),
	regexp.MustCompile(`(?i)undefined is not a function`),
	regexp.MustCompile(`(?i)Cannot read property .* of undefined`),
	regexp.MustCompile(`(?i)Error: ENOENT: no such file`),
	regexp.MustCompile(`(?i)ActiveRecord::.*Error`),
	regexp.MustCompile(`(?i)PG::.*Error`),
	regexp.MustCompile(`(?i)django\.core\.exceptions`),
	regexp.MustCompile(`(?i)WSGI Application Error`),
}

type secretPattern struct {
	name string
	re   *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS Secret Key", regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*([A-Za-z0-9/+]{40})`)},
	{"Private Key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`)},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"Stripe Key", regexp.MustCompile(`sk_(live|test)_[0-9a-zA-Z]{24,}`)},
	{"GitHub Token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,255}`)},
	{"JWT Secret", regexp.MustCompile(`(?i)(jwt[_-]?secret|secret[_-]?key)\s*[=:]\s*['"]([^'"]{8,})`)},
	{"Database URL", regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis)://[^@\s]{4,}@[^\s"']+`)},
}

// RunDisclosure checks for exposed sensitive paths, verbose error messages,
// secrets leaked in responses, and GraphQL introspection/batch issues.
// Mirrors modules/checks/disclosure.py run().
func RunDisclosure(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, store *findings.FindingStore) {
	logging.Println("[*] Checking information disclosure...")
	curlAuth := session.CurlAuthFlags(baseURL)

	checkSensitivePaths(session, baseURL, curlAuth, store)
	checkVerboseErrors(session, baseURL, endpoints, curlAuth, store)
	checkSecretsInResponses(session, endpoints, store)
	checkGraphQL(session, baseURL, curlAuth, store)
}

type fallbackBaseline struct {
	status int
	body   string
}

// getFallbackBaseline requests a guaranteed-nonexistent path so SPA catch-all
// routing (200 + identical body for any path) can be filtered out.
func getFallbackBaseline(session *httpsession.Session, baseURL string) *fallbackBaseline {
	b := make([]byte, 16)
	rand.Read(b)
	probePath := "/__nonexistent_" + hex.EncodeToString(b) + "__"
	u := strings.TrimRight(baseURL, "/") + probePath
	resp, err := session.Request("GET", u, httpsession.Options{AllowRedirects: true, Timeout: 8 * time.Second})
	if err != nil {
		return nil
	}
	return &fallbackBaseline{status: resp.StatusCode, body: resp.Body}
}

func looksLikeFallback(resp *httpsession.Response, baseline *fallbackBaseline) bool {
	if baseline == nil {
		return false
	}
	return resp.StatusCode == baseline.status && resp.Body == baseline.body
}

func checkSensitivePaths(session *httpsession.Session, baseURL, curlAuth string, store *findings.FindingStore) {
	baseline := getFallbackBaseline(session, baseURL)

	for _, sp := range sensitivePaths {
		u := strings.TrimRight(baseURL, "/") + sp.path
		resp, err := session.Request("GET", u, httpsession.Options{AllowRedirects: true, Timeout: 8 * time.Second})
		if err != nil {
			continue
		}

		if resp.StatusCode == 404 || resp.StatusCode == 410 || resp.StatusCode == 501 {
			continue
		}
		if looksLikeFallback(resp, baseline) {
			continue
		}

		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		bodySnippet := strings.ReplaceAll(truncate(resp.Body, 300), "\n", " ")

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			f := findings.NewFinding(
				fmt.Sprintf("Обнаружен защищённый путь: %s (%s)", sp.path, sp.label),
				findings.Info,
				"Information Disclosure",
				"CWE-200",
				u,
				fmt.Sprintf("URL '%s' существует и возвращает HTTP %d "+
					"(требует авторизации).\nРесурс: %s", u, resp.StatusCode, sp.label),
				fmt.Sprintf("Путь %s закрыт авторизацией — это ожидаемое поведение, "+
					"дополнительных действий не требуется. Убедитесь, что 401/403 "+
					"не отдаёт лишних деталей о структуре приложения.", sp.path),
				fmt.Sprintf("curl -sk %s '%s'", curlAuth, u),
			)
			f.Evidence = fmt.Sprintf("HTTP %d\n%s", resp.StatusCode, bodySnippet)
			store.Add(f)
			continue
		}

		ctDisplay := ct
		if ctDisplay == "" {
			ctDisplay = "не указан"
		}
		f := findings.NewFinding(
			fmt.Sprintf("Доступен чувствительный путь: %s (%s)", sp.path, sp.label),
			findings.Medium,
			"Information Disclosure",
			"CWE-200",
			u,
			fmt.Sprintf("URL '%s' возвращает HTTP %d и отличается от "+
				"стандартного fallback-ответа сервера.\n"+
				"Ресурс: %s\n"+
				"Content-Type: %s\n"+
				"Сам по себе нестандартный ответ ещё не доказывает утечку — "+
				"требуется проверка содержимого на признаки реального секрета/исходника.",
				u, resp.StatusCode, sp.label, ctDisplay),
			fmt.Sprintf("1. Закройте доступ к %s на уровне веб-сервера / файрвола.\n"+
				"2. Удалите чувствительные файлы из webroot.\n"+
				"3. Ограничьте Actuator-эндпоинты (management.endpoints.web.exposure.include).", sp.path),
			fmt.Sprintf("curl -sk %s '%s'", curlAuth, u),
		)
		f.Evidence = fmt.Sprintf("HTTP %d\n%s", resp.StatusCode, bodySnippet)

		store.AddCandidate(&findings.Candidate{
			Finding: f,
			Kind:    "disclosure",
			Context: map[string]any{"path": sp.path, "url": u, "label": sp.label},
		})
	}
}

func checkVerboseErrors(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, curlAuth string, store *findings.FindingStore) {
	tested := make(map[string]struct{})
	targets := []string{baseURL}
	count := 0
	for _, ep := range endpoints {
		if ep.Method == "GET" {
			targets = append(targets, ep.URL)
			count++
			if count >= 20 {
				break
			}
		}
	}

	for _, url := range targets {
		if _, ok := tested[url]; ok {
			continue
		}
		tested[url] = struct{}{}

		for _, trigger := range errorTriggers[:3] {
			var testURL string
			if !strings.Contains(url, "?") {
				testURL = url + trigger
			} else {
				testURL = url + "&err=" + trigger
			}
			resp, err := session.Request("GET", testURL, httpsession.Options{AllowRedirects: true, Timeout: 8 * time.Second})
			if err != nil {
				continue
			}

			for _, sig := range verboseErrorSignatures {
				loc := sig.FindStringIndex(resp.Body)
				if loc == nil {
					continue
				}
				start := loc[0] - 100
				if start < 0 {
					start = 0
				}
				end := loc[1] + 200
				if end > len(resp.Body) {
					end = len(resp.Body)
				}
				snippet := resp.Body[start:end]

				f := findings.NewFinding(
					"Verbose error messages — утечка стектрейса",
					findings.Medium,
					"Information Disclosure",
					"CWE-209",
					testURL,
					fmt.Sprintf("Приложение возвращает подробные сообщения об ошибках.\n"+
						"Паттерн: %s\n"+
						"Это раскрывает технологический стек, пути файлов и детали реализации.", sig.String()),
					"1. Настройте production error handler: возвращайте только generic сообщение.\n"+
						"2. Логируйте детали ошибки только на сервере.\n"+
						"3. DEBUG=False (Django), displayErrors: false, error_reporting(0) (PHP).",
					fmt.Sprintf("curl -sk %s '%s'", curlAuth, testURL),
				)
				f.Evidence = fmt.Sprintf("...%s...", snippet)
				store.Add(f)
				tested[url] = struct{}{}
				break
			}
			break // one trigger per URL is enough for detection
		}
	}
}

func checkSecretsInResponses(session *httpsession.Session, endpoints []crawler.Endpoint, store *findings.FindingStore) {
	limit := len(endpoints)
	if limit > 30 {
		limit = 30
	}
	for _, ep := range endpoints[:limit] {
		if ep.Method != "GET" && ep.Method != "HEAD" {
			continue
		}
		resp, err := session.Get(ep.URL, nil)
		if err != nil || resp.StatusCode != 200 {
			continue
		}

		for _, sp := range secretPatterns {
			loc := sp.re.FindStringIndex(resp.Body)
			if loc == nil {
				continue
			}
			match := resp.Body[loc[0]:loc[1]]
			f := findings.NewFinding(
				fmt.Sprintf("Секрет в HTTP-ответе: %s", sp.name),
				findings.Critical,
				"Information Disclosure",
				"CWE-312",
				ep.URL,
				fmt.Sprintf("В ответе '%s' обнаружен %s.\n"+
					"Утечка credentials в HTTP-ответах критична для безопасности.", ep.URL, sp.name),
				"1. Немедленно ротируйте скомпрометированные credentials.\n"+
					"2. Не возвращайте секреты в API-ответах.\n"+
					"3. Используйте secret management (Vault, AWS Secrets Manager).\n"+
					"4. Проверьте git-историю на предмет закоммиченных секретов.",
				fmt.Sprintf("curl -sk '%s' | grep -oE '<pattern>'", ep.URL),
			)
			f.Evidence = fmt.Sprintf("Найдено: %s...", truncate(match, 80))
			store.Add(f)
		}
	}
}

var graphqlEndpoints = []string{"/graphql", "/api/graphql", "/graphiql", "/gql", "/query"}

func checkGraphQL(session *httpsession.Session, baseURL, curlAuth string, store *findings.FindingStore) {
	for _, path := range graphqlEndpoints {
		u := strings.TrimRight(baseURL, "/") + path

		probe, err := session.Request("GET", u, httpsession.Options{AllowRedirects: true, Timeout: 8 * time.Second})
		if err != nil {
			continue
		}
		if probe.StatusCode == 404 || probe.StatusCode == 410 {
			continue
		}

		introspection := map[string]any{"query": "{ __schema { types { name fields { name } } } }"}
		resp, err := session.PostJSON(u, introspection, nil)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 && strings.Contains(resp.Body, "__schema") {
			f := findings.NewFinding(
				"GraphQL: introspection включена (schema disclosure)",
				findings.Medium,
				"Information Disclosure",
				"CWE-200",
				u,
				fmt.Sprintf("GraphQL endpoint '%s' возвращает полную схему через introspection.\n"+
					"Атакующий может восстановить всю структуру API, включая мутации и аргументы.", u),
				"1. Отключите introspection в production:\n"+
					"   GraphQL Shield, depth-limit или параметр disableIntrospection.\n"+
					"2. Если introspection нужна — ограничьте по IP или роли.",
				fmt.Sprintf("curl -sk %s -X POST '%s' \\\n"+
					"  -H 'Content-Type: application/json' \\\n"+
					"  -d '{\"query\":\"{ __schema { types { name } } }\"}", curlAuth, u),
			)
			f.Evidence = "__schema присутствует в ответе на introspection-запрос"
			store.Add(f)
		}

		batchQuery := []map[string]any{introspection, introspection, introspection}
		respBatch, err := session.PostJSON(u, batchQuery, nil)
		if err != nil {
			continue
		}
		if respBatch.StatusCode == 200 {
			var arr []any
			if json.Unmarshal([]byte(respBatch.Body), &arr) == nil {
				f := findings.NewFinding(
					"GraphQL: batch queries включены",
					findings.Low,
					"API Security",
					"CWE-770",
					u,
					"GraphQL endpoint принимает batch-запросы (массив операций в одном HTTP-запросе). "+
						"Это может использоваться для обхода rate limiting или брутфорса.",
					"Ограничьте глубину и количество операций в одном запросе. Отключите batch если не используется.",
					fmt.Sprintf("curl -sk %s -X POST '%s' \\\n"+
						"  -H 'Content-Type: application/json' \\\n"+
						"  -d '[{\"query\":\"{me{id}}\"},{\"query\":\"{me{id}}\"},{\"query\":\"{me{id}}\"}]'", curlAuth, u),
				)
				f.Evidence = fmt.Sprintf("Batch ответ: %s", truncate(respBatch.Body, 200))
				store.Add(f)
			}
		}
	}
}
