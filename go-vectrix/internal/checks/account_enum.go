package checks

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"vectrixgo/internal/crawler"
	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
)

// acctFakeUser is a clearly non-existent sentinel username.
const acctFakeUser = "vectrix_nosuchuser_97zq"

// acctFakeEmail mirrors account_enum.py FAKE_EMAIL.
const acctFakeEmail = acctFakeUser + "@vectrix-probe-no-reply.invalid"

// acctCandidateUsers mirrors account_enum.py CANDIDATE_USERS.
var acctCandidateUsers = []string{"admin", "administrator", "user", "test", "support", "info"}

// acctLoginPaths mirrors account_enum.py LOGIN_PATHS.
var acctLoginPaths = []string{
	"/login", "/signin", "/api/login", "/api/signin",
	"/api/auth/login", "/api/auth/token", "/api/token",
	"/api/v1/login", "/api/v2/login", "/api/v1/auth/login",
	"/auth/local", "/auth/login",
}

// acctRegisterPaths mirrors account_enum.py REGISTER_PATHS.
var acctRegisterPaths = []string{
	"/register", "/signup", "/api/register", "/api/signup",
	"/api/v1/register", "/api/v2/register", "/api/users",
	"/api/v1/users",
}

// acctResetPaths mirrors account_enum.py RESET_PATHS.
var acctResetPaths = []string{
	"/forgot-password", "/forgot_password", "/password/reset",
	"/password-reset", "/api/password/reset", "/api/auth/forgot",
	"/api/v1/auth/password/forgot", "/api/auth/password",
	"/reset-password", "/account/forgot",
}

const (
	acctSizeDiffThreshold = 0.12 // 12% body size difference → suspicious
	acctTimingDiffSec     = 0.4  // 400ms difference → suspicious
)

// acctAccountExistsPatterns mirrors account_enum.py ACCOUNT_EXISTS_PATTERNS.
var acctAccountExistsPatterns = regexp.MustCompile(
	`(?i)already (registered|taken|exists|in use)|` +
		`email.{0,20}already|` +
		`(username|account|user).{0,20}already|` +
		`is taken|address is already`,
)

// acctAccountNotFoundPatterns mirrors account_enum.py ACCOUNT_NOT_FOUND_PATTERNS.
var acctAccountNotFoundPatterns = regexp.MustCompile(
	`(?i)(user(name)?|email|account).{0,30}(not found|doesn.?t? exist|not registered|invalid)|` +
		`no account.{0,20}(with|found|for).{0,20}email|` +
		`we couldn.?t find|` +
		`incorrect (username|email)|` +
		`(invalid|unknown) (user|email|username|account)`,
)

// RunAccountEnum checks login/register/password-reset endpoints for
// observable differences between known and non-existent accounts (status
// code, body size, error message, response timing). Mirrors
// modules/checks/account_enum.py run().
func RunAccountEnum(session *httpsession.Session, baseURL string, endpoints []crawler.Endpoint, store *findings.FindingStore) {
	logging.Println("[*] Checking account enumeration...")
	curlAuth := session.CurlAuthFlags(baseURL)

	loginURLs := acctCollect(baseURL, endpoints, acctLoginPaths)
	if len(loginURLs) > 4 {
		loginURLs = loginURLs[:4]
	}
	for _, u := range loginURLs {
		acctCheckLogin(session, u, curlAuth, store)
	}

	registerURLs := acctCollect(baseURL, endpoints, acctRegisterPaths)
	if len(registerURLs) > 3 {
		registerURLs = registerURLs[:3]
	}
	for _, u := range registerURLs {
		acctCheckRegister(session, u, curlAuth, store)
	}

	resetURLs := acctCollect(baseURL, endpoints, acctResetPaths)
	if len(resetURLs) > 3 {
		resetURLs = resetURLs[:3]
	}
	for _, u := range resetURLs {
		acctCheckReset(session, u, curlAuth, store)
	}
}

// acctCollect builds candidate URLs by joining base_url with each path,
// plus any crawled endpoint whose URL contains one of the given paths.
// Mirrors the implicit `_collect` helper referenced by account_enum.py run().
func acctCollect(baseURL string, endpoints []crawler.Endpoint, paths []string) []string {
	seen := make(map[string]struct{})
	var out []string

	add := func(u string) {
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}

	trimmedBase := strings.TrimRight(baseURL, "/")
	for _, path := range paths {
		add(trimmedBase + path)
	}
	for _, ep := range endpoints {
		lowerURL := strings.ToLower(ep.URL)
		for _, path := range paths {
			if strings.Contains(lowerURL, strings.ToLower(path)) {
				add(ep.URL)
				break
			}
		}
	}
	return out
}

// acctTimedResult holds the outcome of a probe request.
type acctTimedResult struct {
	status  int
	size    int
	body    string
	elapsed float64 // seconds
}

// ── Per-endpoint checks ──────────────────────────────────────────────────────

// acctCheckLogin compares login response for known-candidate vs clearly-fake username.
func acctCheckLogin(session *httpsession.Session, url, curlAuth string, store *findings.FindingStore) {
	type namedResult struct {
		username string
		res      acctTimedResult
	}
	var results []namedResult

	for _, username := range []string{acctCandidateUsers[0], acctFakeUser} {
		payloads := []map[string]any{
			{"username": username, "password": "VectrixWrong!999"},
			{"email": username + "@example.com", "password": "VectrixWrong!999"},
			{"login": username, "password": "VectrixWrong!999"},
		}
		if r, ok := acctPostTimed(session, url, payloads); ok {
			results = append(results, namedResult{username: username, res: r})
		}
	}

	if len(results) < 2 {
		return
	}

	known := results[0].res
	fake := results[1].res

	if acctReportIfDifferent(url, curlAuth, store, "login", known, fake) {
		return
	}

	// Explicit "invalid username" message absent for fake user but different for known
	if acctAccountNotFoundPatterns.MatchString(fake.body) && !acctAccountNotFoundPatterns.MatchString(known.body) {
		m := acctAccountNotFoundPatterns.FindString(fake.body)
		acctAddFinding(store, url, curlAuth, "Login — error message",
			fmt.Sprintf("Для несуществующего пользователя: «%s»", truncate(m, 100)))
	}
}

// acctCheckRegister compares registration response for taken vs fresh email.
func acctCheckRegister(session *httpsession.Session, url, curlAuth string, store *findings.FindingStore) {
	takenEmail := "admin@example.com"
	freshEmail := acctFakeEmail

	type namedResult struct {
		email string
		res   acctTimedResult
	}
	var results []namedResult

	for _, email := range []string{takenEmail, freshEmail} {
		username := strings.SplitN(email, "@", 2)[0]
		payloads := []map[string]any{
			{"email": email, "username": username, "password": "Test@Vectrix99"},
			{"email": email, "password": "Test@Vectrix99"},
		}
		if r, ok := acctPostTimed(session, url, payloads); ok {
			results = append(results, namedResult{email: email, res: r})
		}
	}

	if len(results) < 2 {
		return
	}

	taken := results[0].res
	fresh := results[1].res

	// Status differs → direct leak
	if taken.status != fresh.status && taken.status != 404 && taken.status != 500 {
		acctAddFinding(store, url, curlAuth, "Registration — HTTP status",
			fmt.Sprintf("Существующий email: HTTP %d, Новый email: HTTP %d", taken.status, fresh.status))
		return
	}

	// "Already taken" message only for existing email
	if acctAccountExistsPatterns.MatchString(taken.body) && !acctAccountExistsPatterns.MatchString(fresh.body) {
		m := acctAccountExistsPatterns.FindString(taken.body)
		acctAddFinding(store, url, curlAuth, "Registration — error message",
			fmt.Sprintf("«%s» только для существующего аккаунта", truncate(m, 100)))
	}
}

// acctCheckReset checks if password reset reveals whether email is registered.
func acctCheckReset(session *httpsession.Session, url, curlAuth string, store *findings.FindingStore) {
	type namedResult struct {
		email string
		res   acctTimedResult
	}
	var results []namedResult

	for _, email := range []string{"admin@example.com", acctFakeEmail} {
		payloads := []map[string]any{
			{"email": email},
			{"username": email},
			{"email": email, "g-recaptcha-response": ""}, // common field
		}
		if r, ok := acctPostTimed(session, url, payloads); ok {
			results = append(results, namedResult{email: email, res: r})
		}
	}

	if len(results) < 2 {
		return
	}

	real := results[0].res
	fake := results[1].res

	acctReportIfDifferent(url, curlAuth, store, "password reset", real, fake)

	if acctAccountNotFoundPatterns.MatchString(fake.body) && !acctAccountNotFoundPatterns.MatchString(real.body) {
		m := acctAccountNotFoundPatterns.FindString(fake.body)
		acctAddFinding(store, url, curlAuth, "Password reset — error message",
			fmt.Sprintf("Сброс пароля раскрывает отсутствие аккаунта: «%s»", truncate(m, 100)))
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// acctPostTimed tries each payload in turn; returns the first response whose
// status is not 404/405/501, along with its timing. Mirrors _post_timed.
func acctPostTimed(session *httpsession.Session, url string, payloads []map[string]any) (acctTimedResult, bool) {
	for _, payload := range payloads {
		start := time.Now()
		resp, err := session.PostJSON(url, payload, nil)
		elapsed := time.Since(start).Seconds()
		if err != nil {
			continue
		}
		if resp.StatusCode != 404 && resp.StatusCode != 405 && resp.StatusCode != 501 {
			body := resp.Body
			if len(body) > 600 {
				body = body[:600]
			}
			return acctTimedResult{
				status:  resp.StatusCode,
				size:    len(resp.Body),
				body:    body,
				elapsed: elapsed,
			}, true
		}
	}
	return acctTimedResult{}, false
}

// acctReportIfDifferent compares two timed results (status code, body size,
// timing) and adds a finding for the first observed difference. Returns true
// if a finding was added. Mirrors _report_if_different.
func acctReportIfDifferent(url, curlAuth string, store *findings.FindingStore, kind string, a, b acctTimedResult) bool {
	titleKind := acctTitleCase(kind)

	// Status code
	if a.status != b.status && b.status != 404 && b.status != 500 {
		acctAddFinding(store, url, curlAuth, fmt.Sprintf("%s — HTTP status", titleKind),
			fmt.Sprintf("Существующий: HTTP %d | Несуществующий: HTTP %d", a.status, b.status))
		return true
	}

	// Body size
	maxSize := a.size
	if b.size > maxSize {
		maxSize = b.size
	}
	if maxSize < 1 {
		maxSize = 1
	}
	diff := a.size - b.size
	if diff < 0 {
		diff = -diff
	}
	if float64(diff)/float64(maxSize) > acctSizeDiffThreshold && maxSize > 50 {
		pct := float64(diff) / float64(maxSize) * 100
		acctAddFinding(store, url, curlAuth, fmt.Sprintf("%s — размер ответа", titleKind),
			fmt.Sprintf("Существующий: %d байт | Несуществующий: %d байт (%.0f%% разница)", a.size, b.size, pct))
		return true
	}

	// Timing
	timeDiff := a.elapsed - b.elapsed
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff > acctTimingDiffSec {
		acctAddFinding(store, url, curlAuth, fmt.Sprintf("%s — время ответа (timing attack)", titleKind),
			fmt.Sprintf("Существующий: %.2fс | Несуществующий: %.2fс (Δ %.2fс)", a.elapsed, b.elapsed, timeDiff))
		return true
	}

	return false
}

// acctTitleCase capitalizes the first letter of every word, mirroring
// Python's str.title() for the simple ASCII labels used here
// (e.g. "password reset" -> "Password Reset").
func acctTitleCase(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		if w == "" {
			continue
		}
		runes := []rune(w)
		runes[0] = unicode.ToUpper(runes[0])
		for j := 1; j < len(runes); j++ {
			runes[j] = unicode.ToLower(runes[j])
		}
		words[i] = string(runes)
	}
	return strings.Join(words, " ")
}

// acctAddFinding mirrors _add_finding.
func acctAddFinding(store *findings.FindingStore, url, curlAuth, method, evidence string) {
	f := findings.NewFinding(
		fmt.Sprintf("Перебор аккаунтов (%s)", method),
		findings.Medium,
		"Authentication",
		"CWE-204",
		url,
		fmt.Sprintf("Endpoint %s возвращает различные ответы для существующих "+
			"и несуществующих аккаунтов.\n"+
			"Метод обнаружения: %s\n\n"+
			"Атакующий может составить список зарегистрированных email/username методом перебора, "+
			"что упрощает последующие атаки (credential stuffing, spear phishing, brute force).",
			url, method),
		"1. Всегда возвращайте одинаковые ответы (тело, статус, время) для "+
			"   существующих и несуществующих аккаунтов.\n"+
			"2. Для reset: «Если этот email зарегистрирован, вы получите письмо» — "+
			"   без указания факта существования.\n"+
			"3. Применяйте constant-time операции при поиске пользователя, "+
			"   чтобы устранить timing-атаку.\n"+
			"4. После N неудачных попыток — CAPTCHA или временная блокировка IP.",
		fmt.Sprintf("# Сравните ответы:\n"+
			"curl -sk %s -X POST -H 'Content-Type: application/json' "+
			"-d '{\"email\":\"admin@example.com\",\"password\":\"wrong\"}' '%s'\n"+
			"curl -sk %s -X POST -H 'Content-Type: application/json' "+
			"-d '{\"email\":\"%s\",\"password\":\"wrong\"}' '%s'",
			curlAuth, url, curlAuth, acctFakeEmail, url),
	)
	f.Method = "POST"
	f.Evidence = evidence
	store.Add(f)
}
