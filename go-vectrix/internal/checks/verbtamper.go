package checks

import (
	"encoding/json"
	"fmt"
	"strings"

	"vectrixgo/internal/crawler"
	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
)

// verbTraceProbeHeader is the header injected during the TRACE/XST probe.
const verbTraceProbeHeader = "X-Vectrix-Trace-Probe"

// verbAdminPaths mirrors verbtamper.py ADMIN_PATHS.
var verbAdminPaths = []string{
	"/admin", "/admin/users", "/admin/settings",
	"/api/admin", "/api/v1/admin", "/api/v2/admin",
	"/management", "/manage", "/dashboard/admin",
	"/api/users", "/api/v1/users", "/api/v2/users",
	"/api/config", "/api/settings",
}

// verbMethodOverrideHeaders mirrors verbtamper.py METHOD_OVERRIDE_HEADERS.
var verbMethodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-Method-Override",
	"X-HTTP-Method",
	"_method",
}

// verbMassAssignProbe mirrors verbtamper.py MASS_ASSIGN_PROBE.
var verbMassAssignProbe = map[string]any{
	"is_admin":     true,
	"isAdmin":      true,
	"role":         "admin",
	"admin":        true,
	"is_superuser": true,
	"privilege":    "admin",
	"account_type": "admin",
	"user_type":    "admin",
	"permissions":  []string{"admin"},
	"price":        0,
	"amount":       -1,
	"discount":     100,
	"balance":      99999,
	"credit":       99999,
}

// verbMassAssignConfirmKeys mirrors verbtamper.py MASS_ASSIGN_CONFIRM_KEYS.
// Order matters for the "first 3 reflected" slice in the title, so we keep a
// deterministic ordered slice (Python uses a set, but iteration order there
// is also effectively unordered — we pick a stable order here).
var verbMassAssignConfirmKeys = []string{
	"is_admin", "isAdmin", "role", "admin",
	"is_superuser", "privilege", "account_type",
	"user_type", "permissions", "price", "discount",
}

// RunVerbTamper checks for HTTP TRACE/XST, verb tampering, method override,
// and mass assignment vulnerabilities. Mirrors modules/checks/verbtamper.py run().
func RunVerbTamper(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, store *findings.FindingStore) {
	logging.Println("[*] Checking HTTP verb tampering / mass assignment...")
	curlAuth := session.CurlAuthFlags(baseURL)

	verbCheckTrace(session, baseURL, curlAuth, store)
	verbCheckVerbTampering(session, baseURL, endpoints, curlAuth, store)
	verbCheckMethodOverride(session, baseURL, endpoints, curlAuth, store)
	verbCheckMassAssignment(session, endpoints, curlAuth, store)
}

// ── TRACE / XST ─────────────────────────────────────────────────────────────

func verbCheckTrace(session *httpsession.Session, baseURL, curlAuth string, store *findings.FindingStore) {
	resp, err := session.Request("TRACE", baseURL, httpsession.Options{
		Headers:        map[string]string{verbTraceProbeHeader: "vectrix-xst-probe"},
		AllowRedirects: true,
	})
	if err != nil {
		return
	}

	if resp.StatusCode == 200 && strings.Contains(resp.Body, "vectrix-xst-probe") {
		f := findings.NewFinding(
			"HTTP TRACE включён — Cross-Site Tracing (XST) возможен",
			findings.Low,
			"Security Headers",
			"CWE-16",
			baseURL,
			"Сервер принимает HTTP TRACE и возвращает заголовки запроса в теле ответа.\n"+
				"В сочетании с XSS это позволяет атакующему читать HttpOnly-куки через XST:\n"+
				"1. Встраивает JavaScript с XHR TRACE-запросом на целевой сайт\n"+
				"2. В теле ответа появляются все заголовки, включая HttpOnly Cookie\n"+
				"3. Cookie отправляется на сервер атакующего",
			"Отключите TRACE во всех компонентах стека:\n"+
				"  nginx:  limit_except GET POST { deny all; }\n"+
				"  Apache: TraceEnable off\n"+
				"  IIS:    <verbs allowUnlisted='false'> в web.config\n"+
				"  Node/Express: app.disable('x-powered-by'); + явная блокировка TRACE",
			fmt.Sprintf("curl -sk %s -X TRACE -H '%s: vectrix-xst-probe' '%s'", curlAuth, verbTraceProbeHeader, baseURL),
		)
		f.Method = "TRACE"
		f.Evidence = fmt.Sprintf("TRACE ответ содержит инъектированный заголовок %s", verbTraceProbeHeader)
		store.Add(f)
	}
}

// ── Verb tampering ──────────────────────────────────────────────────────────

func verbCheckVerbTampering(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, curlAuth string, store *findings.FindingStore) {
	// Collect restricted-ish paths: admin paths + any endpoint that returned 4xx on crawl
	candidateSet := make(map[string]struct{})
	var candidateOrder []string

	add := func(u string) {
		if _, ok := candidateSet[u]; !ok {
			candidateSet[u] = struct{}{}
			candidateOrder = append(candidateOrder, u)
		}
	}

	trimmedBase := strings.TrimRight(baseURL, "/")
	for _, path := range verbAdminPaths {
		add(trimmedBase + path)
	}
	for _, ep := range endpoints {
		lower := strings.ToLower(ep.URL)
		if strings.Contains(lower, "/admin") || strings.Contains(lower, "/manage") {
			add(ep.URL)
		}
	}

	if len(candidateOrder) > 20 {
		candidateOrder = candidateOrder[:20]
	}

	altMethods := []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}

	for _, u := range candidateOrder {
		baseline, err := session.Request("GET", u, httpsession.Options{AllowRedirects: false})
		if err != nil {
			continue
		}

		if baseline.StatusCode == 200 {
			continue // Already accessible — not a tampering bypass
		}

		baselineCode := baseline.StatusCode

		for _, method := range altMethods {
			resp, err := session.Request(method, u, httpsession.Options{AllowRedirects: false})
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 && len(resp.Body) > 100 {
				f := findings.NewFinding(
					fmt.Sprintf("HTTP Verb Tampering — %s даёт доступ к %s", method, u),
					findings.High,
					"Access Control",
					"CWE-650",
					u,
					fmt.Sprintf("Endpoint %s недоступен через GET (HTTP %d), но возвращает HTTP 200 "+
						"при %s-запросе (%d байт).\n\n"+
						"Контроль доступа реализован только для определённых методов, "+
						"что позволяет атакующему обойти ограничения, изменив HTTP-метод.",
						u, baselineCode, method, len(resp.Body)),
					"1. Применяйте авторизацию ко всем HTTP-методам, а не только GET/POST.\n"+
						"2. Явно запрещайте ненужные методы (405 Method Not Allowed).\n"+
						"3. Spring Security: .requestMatchers('/**').hasRole('ADMIN') "+
						"применяется ко всем методам.\n"+
						"4. Express/Koa: middleware авторизации на router.use(), "+
						"не только на router.get().",
					fmt.Sprintf("curl -sk %s -X %s '%s'", curlAuth, method, u),
				)
				f.Method = method
				f.Evidence = fmt.Sprintf("GET → HTTP %d\n%s → HTTP 200 (%d байт)", baselineCode, method, len(resp.Body))
				store.Add(f)
				break // one finding per endpoint
			}
		}
	}
}

// ── Method override ─────────────────────────────────────────────────────────

func verbCheckMethodOverride(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, curlAuth string, store *findings.FindingStore) {
	trimmedBase := strings.TrimRight(baseURL, "/")

	paths := verbAdminPaths
	if len(paths) > 8 {
		paths = paths[:8]
	}

	for _, path := range paths {
		u := trimmedBase + path
		baseline, err := session.Request("GET", u, httpsession.Options{AllowRedirects: false})
		if err != nil {
			continue
		}

		if baseline.StatusCode == 200 || baseline.StatusCode == 404 || baseline.StatusCode == 410 {
			continue
		}

		for _, hdr := range verbMethodOverrideHeaders {
			for _, overrideMethod := range []string{"GET", "DELETE"} {
				resp, err := session.Request("POST", u, httpsession.Options{
					Headers:        map[string]string{hdr: overrideMethod},
					AllowRedirects: false,
				})
				if err != nil {
					continue
				}

				if resp.StatusCode == 200 && len(resp.Body) > 100 {
					f := findings.NewFinding(
						fmt.Sprintf("HTTP Method Override bypass — '%s: %s'", hdr, overrideMethod),
						findings.High,
						"Access Control",
						"CWE-650",
						u,
						fmt.Sprintf("Заголовок '%s: %s' позволяет обойти ограничение доступа к %s.\n"+
							"Baseline GET → HTTP %d, POST + %s → HTTP 200.\n\n"+
							"Фреймворки (Rails, Laravel, некоторые SPA) поддерживают _method/override "+
							"для обратной совместимости с HTML-формами. Если middleware применяет "+
							"авторизацию по реальному методу, а роутер — по override, возникает gap.",
							hdr, overrideMethod, u, baseline.StatusCode, hdr),
						"1. Проверяйте авторизацию по реальному HTTP-методу, "+
							"   а не только по переопределённому.\n"+
							"2. Ограничьте список методов, допустимых через override.\n"+
							"3. Rails: config.action_dispatch.perform_deep_munge — "+
							"   отключите _method для privileged endpoints.",
						fmt.Sprintf("curl -sk %s -X POST -H '%s: %s' '%s'", curlAuth, hdr, overrideMethod, u),
					)
					f.Method = "POST"
					f.Evidence = fmt.Sprintf("Baseline GET: HTTP %d\nPOST + %s: %s → HTTP 200", baseline.StatusCode, hdr, overrideMethod)
					store.Add(f)
					return
				}
			}
		}
	}
}

// ── Mass assignment ──────────────────────────────────────────────────────────

func verbCheckMassAssignment(session *httpsession.Session, endpoints []crawler.Endpoint, curlAuth string, store *findings.FindingStore) {
	// Target JSON endpoints that mutate state
	var mutable []crawler.Endpoint
	for _, ep := range endpoints {
		if (ep.Method == "POST" || ep.Method == "PUT" || ep.Method == "PATCH") && len(ep.BodyParams) > 0 {
			mutable = append(mutable, ep)
		}
	}

	if len(mutable) > 25 {
		mutable = mutable[:25]
	}

	checked := make(map[string]struct{})
	for _, ep := range mutable {
		key := ep.Method + ":" + ep.URL
		if _, ok := checked[key]; ok {
			continue
		}
		checked[key] = struct{}{}

		// Send normal request first to get baseline status
		baseline, err := session.Request(ep.Method, ep.URL, httpsession.Options{
			Headers:        map[string]string{"Content-Type": "application/json"},
			Body:           jsonReader(bodyParamsToMap(ep.BodyParams)),
			AllowRedirects: false,
		})
		if err != nil {
			continue
		}

		if baseline.StatusCode >= 500 {
			continue
		}

		// Inject mass-assignment bait fields
		baitPayload := make(map[string]any, len(ep.BodyParams)+len(verbMassAssignProbe))
		for k, v := range ep.BodyParams {
			baitPayload[k] = v
		}
		for k, v := range verbMassAssignProbe {
			baitPayload[k] = v
		}

		resp, err := session.Request(ep.Method, ep.URL, httpsession.Options{
			Headers:        map[string]string{"Content-Type": "application/json"},
			Body:           jsonReader(baitPayload),
			AllowRedirects: false,
		})
		if err != nil {
			continue
		}

		if resp.StatusCode >= 400 {
			continue
		}

		// Parse JSON response and look for injected admin fields
		var reflected []string
		var respData any
		if jsonErr := json.Unmarshal([]byte(resp.Body), &respData); jsonErr == nil {
			respStr := strings.ToLower(resp.Body)
			for _, k := range verbMassAssignConfirmKeys {
				if strings.Contains(respStr, strings.ToLower(k)) {
					injectedVal, ok := verbMassAssignProbe[k]
					if !ok {
						continue
					}
					injectedStr := strings.ToLower(fmt.Sprintf("%v", injectedVal))
					if strings.Contains(respStr, injectedStr) {
						reflected = append(reflected, k)
					}
				}
			}
		} else {
			// Non-JSON response: look for string matches
			respStr := strings.ToLower(resp.Body)
			for _, k := range []string{"is_admin", "admin", "role"} {
				if strings.Contains(respStr, k) && strings.Contains(respStr, "true") {
					reflected = append(reflected, k)
				}
			}
		}

		if len(reflected) == 0 {
			continue
		}

		samplePayload := make(map[string]any, len(ep.BodyParams)+2)
		for k, v := range ep.BodyParams {
			samplePayload[k] = v
		}
		samplePayload["is_admin"] = true
		samplePayload["role"] = "admin"
		samplePayloadJSON, _ := json.Marshal(samplePayload)

		reflectedDisplay := reflected
		if len(reflectedDisplay) > 3 {
			reflectedDisplay = reflectedDisplay[:3]
		}

		f := findings.NewFinding(
			fmt.Sprintf("Mass Assignment — поля %s приняты и отражены", formatStringSlice(reflectedDisplay)),
			findings.High,
			"Access Control",
			"CWE-915",
			ep.URL,
			fmt.Sprintf("Endpoint %s (%s) принял и вернул в ответе "+
				"инъектированные привилегированные поля: %s.\n\n"+
				"Mass Assignment позволяет атакующему установить произвольные "+
				"атрибуты объекта (например, is_admin=true), которые сервер "+
				"не должен принимать от пользователя.",
				ep.URL, ep.Method, formatStringSlice(reflected)),
			"1. Используйте строгий whitelist принимаемых полей (DTO, Serializer):\n"+
				"   Django: явно указывайте fields= в Serializer\n"+
				"   Laravel: $fillable вместо $guarded\n"+
				"   Rails:   Strong Parameters (permit только нужные поля)\n"+
				"   Spring:  @JsonIgnore / @JsonProperty(access = READ_ONLY)\n"+
				"2. Никогда не передавайте request body напрямую в ORM/ActiveRecord.\n"+
				"3. Разделяйте входные DTO и доменные модели.",
			fmt.Sprintf("curl -sk %s -X %s -H 'Content-Type: application/json' -d '%s' '%s'",
				curlAuth, ep.Method, string(samplePayloadJSON), ep.URL),
		)
		f.Method = ep.Method
		f.Evidence = fmt.Sprintf("Инъектированные поля: %s\nHTTP %d (baseline: %d)",
			formatStringSlice(reflected), resp.StatusCode, baseline.StatusCode)
		store.Add(f)
	}
}

// formatStringSlice renders a []string the way Python's repr does for a list
// of strings, e.g. ['a', 'b', 'c'], to keep evidence/title text close to the
// original Python output.
func formatStringSlice(items []string) string {
	quoted := make([]string, len(items))
	for i, it := range items {
		quoted[i] = "'" + it + "'"
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// bodyParamsToMap converts crawler.Endpoint.BodyParams (map[string]string)
// into a map[string]any suitable for JSON marshaling.
func bodyParamsToMap(params map[string]string) map[string]any {
	out := make(map[string]any, len(params))
	for k, v := range params {
		out[k] = v
	}
	return out
}

// jsonReader marshals v to JSON and returns a reader over the bytes.
func jsonReader(v any) *strings.Reader {
	b, err := json.Marshal(v)
	if err != nil {
		return strings.NewReader("{}")
	}
	return strings.NewReader(string(b))
}
