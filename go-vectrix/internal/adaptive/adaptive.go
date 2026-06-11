// Package adaptive implements the adaptive confirmation engine.
//
// Check modules can flag a *weak* signal (single regex match, response-size
// delta, status-code change, ...) as a findings.Candidate instead of
// publishing it directly. RunConfirmationPass then digs into each candidate
// with a class-specific follow-up probe and decides whether to confirm it
// (with extra evidence and, where useful, dumped artifacts), discard it as a
// false positive, or — if the target stops cooperating — pass it through as
// "unverified" with a hedged severity so a human still sees it.
//
// Mirrors modules/adaptive.py.
package adaptive

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
	"vectrixgo/internal/tools"
)

// ── Outcomes & data structures ──────────────────────────────────────────────

type outcome string

const (
	outcomeConfirmed    outcome = "confirmed"
	outcomeDiscarded    outcome = "discarded"
	outcomeInconclusive outcome = "inconclusive"
)

type artifactFile struct {
	filename string
	content  string
}

type verdict struct {
	outcome       outcome
	extraEvidence string
	artifacts     []artifactFile
	newSeverity   *findings.Severity
	reason        string
}

// ── Artifact dumping ─────────────────────────────────────────────────────────

var unsafeFilenameRe = regexp.MustCompile(`[^\w.\-]`)

// DumpArtifact writes content under artifactRoot/findingID/filename and
// returns a path relative to artifactRoot's parent directory (so HTML <a
// href> links resolve from the report directory). Mirrors
// modules/adaptive.py _dump_artifact.
func DumpArtifact(artifactRoot, findingID, filename, content string) (string, error) {
	targetDir := filepath.Join(artifactRoot, findingID)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", err
	}
	safeName := unsafeFilenameRe.ReplaceAllString(filename, "_")
	if len(safeName) > 120 {
		safeName = safeName[:120]
	}
	if safeName == "" {
		safeName = "artifact.txt"
	}
	path := filepath.Join(targetDir, safeName)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", err
	}
	rel, err := filepath.Rel(filepath.Dir(artifactRoot), path)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

// ── Secret-signature scanning (used by the disclosure verifier) ─────────────

type secretSignature struct {
	pattern *regexp.Regexp
	label   string
}

// secretSignatures mirrors modules/adaptive.py SECRET_SIGNATURES.
var secretSignatures = []secretSignature{
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "AWS Access Key ID"},
	{regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), "Приватный ключ"},
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "JWT"},
	{regexp.MustCompile(`(?im)^\s*(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|API_KEY|AWS_SECRET_ACCESS_KEY)\s*=\s*\S+`), "Секрет в .env-стиле конфига"},
	{regexp.MustCompile(`(?i)mysql://[^\s"']+|postgres(?:ql)?://[^\s"']+|mongodb(?:\+srv)?://[^\s"']+`), "Строка подключения к БД"},
	{regexp.MustCompile(`(?m)^ref:\s*refs/`), "Git HEAD ref"},
	{regexp.MustCompile(`\[core\]|\[remote "origin"\]`), `Git config секция`},
}

type secretHit struct {
	label   string
	pattern string
	snippet string
}

// scanForSecrets returns every signature found in text. Mirrors
// modules/adaptive.py _scan_for_secrets.
func scanForSecrets(text string) []secretHit {
	var hits []secretHit
	for _, sig := range secretSignatures {
		loc := sig.pattern.FindStringIndex(text)
		if loc == nil {
			continue
		}
		match := text[loc[0]:loc[1]]
		if len(match) > 200 {
			match = match[:200]
		}
		hits = append(hits, secretHit{label: sig.label, pattern: sig.pattern.String(), snippet: match})
	}
	return hits
}

// ── Generated nuclei templates (deep-dive sibling probes) ───────────────────

type siblingProbe struct {
	path        string
	matcherType string // "regex" or "word"
	values      []string
	label       string
}

// siblingProbes mirrors modules/adaptive.py SIBLING_PROBES. The double
// backslashes in the regex values are intentional: the generated YAML is
// double-quoted, so `\\s` in the YAML source decodes to a single `\s` in the
// regex nuclei evaluates — exactly mirroring the Python raw strings.
var siblingProbes = map[string][]siblingProbe{
	"/.git/config": {
		{path: "/.git/HEAD", matcherType: "regex", values: []string{`^ref:\\s*refs/`}, label: "git-head-ref"},
		{path: "/.git/index", matcherType: "word", values: []string{"DIRC"}, label: "git-index-signature"},
		{path: "/.git/logs/HEAD", matcherType: "regex", values: []string{`^[0-9a-f]{40}\\s`}, label: "git-reflog-entry"},
	},
	"/.env": {
		{path: "/.env.local", matcherType: "regex", values: []string{`(?i)(DB_PASSWORD|SECRET_KEY|API_KEY)\\s*=`}, label: "env-local-secret"},
		{path: "/.env.production", matcherType: "regex", values: []string{`(?i)(DB_PASSWORD|SECRET_KEY|API_KEY)\\s*=`}, label: "env-production-secret"},
		{path: "/config/.env", matcherType: "regex", values: []string{`(?i)(DB_PASSWORD|SECRET_KEY|API_KEY)\\s*=`}, label: "config-env-secret"},
	},
}

// buildNucleiTemplate mirrors modules/adaptive.py _build_nuclei_template.
func buildNucleiTemplate(templateID, name string, probes []siblingProbe) string {
	blocks := make([]string, 0, len(probes))
	for _, p := range probes {
		matcherKey := "words"
		if p.matcherType == "regex" {
			matcherKey = "regex"
		}
		valueLines := make([]string, 0, len(p.values))
		for _, v := range p.values {
			valueLines = append(valueLines, fmt.Sprintf(`          - "%s"`, v))
		}
		block := fmt.Sprintf(
			"  - method: GET\n"+
				"    path:\n"+
				"      - \"{{BaseURL}}%s\"\n"+
				"    matchers:\n"+
				"      - type: %s\n"+
				"        part: body\n"+
				"        %s:\n"+
				"%s\n"+
				"        name: \"%s\"\n",
			p.path, p.matcherType, matcherKey, strings.Join(valueLines, "\n"), p.label,
		)
		blocks = append(blocks, block)
	}
	return fmt.Sprintf("id: %s\ninfo:\n  name: \"%s\"\n  author: vectrixsecwave-adaptive\n  severity: info\nhttp:\n%s",
		templateID, name, strings.Join(blocks, "\n"))
}

// ── Per-class verifiers ──────────────────────────────────────────────────────
// Every verifier has the signature
// (session, baseURL, candidate, artifactRoot, deepDive) -> verdict
// even when it doesn't need every argument, so the dispatch table stays uniform.

var identityRe = regexp.MustCompile(`(?i)[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}|"(?:username|user_?name|login|full_?name|email|name)"\s*:\s*"([^"]{2,60})"`)

// identityTokens mirrors modules/adaptive.py _identity_tokens.
func identityTokens(text string) map[string]struct{} {
	tokens := make(map[string]struct{})
	for _, m := range identityRe.FindAllStringSubmatch(text, -1) {
		if m[1] != "" {
			tokens[m[1]] = struct{}{}
		} else {
			tokens[m[0]] = struct{}{}
		}
	}
	return tokens
}

func setsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
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

// joinSortedTruncated joins the sorted set elements with ", " and truncates
// to n bytes — mirrors `', '.join(sorted(s))[:n]`.
func joinSortedTruncated(set map[string]struct{}, n int) string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s := strings.Join(keys, ", ")
	if len(s) > n {
		s = s[:n]
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func appendQueryParam(rawurl, key, value string) string {
	sep := "?"
	if strings.Contains(rawurl, "?") {
		sep = "&"
	}
	return rawurl + sep + key + "=" + value
}

// verifyIDOR mirrors modules/adaptive.py _verify_idor.
func verifyIDOR(session *httpsession.Session, baseURL string, candidate *findings.Candidate, artifactRoot string, deepDive bool) verdict {
	ctx := candidate.Context
	originalResp, _ := ctx["original_resp"].(*httpsession.Response)
	probeResp, _ := ctx["probe_resp"].(*httpsession.Response)
	if originalResp == nil || probeResp == nil {
		return verdict{outcome: outcomeInconclusive, reason: "нет сохранённых ответов для повторного анализа"}
	}

	originalTokens := identityTokens(originalResp.Body)
	probeTokens := identityTokens(probeResp.Body)

	if len(originalTokens) == 0 || len(probeTokens) == 0 {
		return verdict{
			outcome: outcomeInconclusive,
			reason: "в ответах не найдено идентифицирующих полей (email/username/...) " +
				"для автоматического сравнения — нужна ручная проверка",
		}
	}

	if !setsEqual(originalTokens, probeTokens) {
		return verdict{
			outcome: outcomeConfirmed,
			extraEvidence: fmt.Sprintf(
				"Повторный анализ содержимого подтвердил, что это разные объекты:\n"+
					"  Идентификаторы в оригинале: %s\n"+
					"  Идентификаторы в зонде:     %s\n"+
					"Содержимое отличается не только по объёму, но и по фактическим данным "+
					"— похоже на доступ к чужому объекту.",
				joinSortedTruncated(originalTokens, 200), joinSortedTruncated(probeTokens, 200)),
		}
	}

	return verdict{
		outcome: outcomeDiscarded,
		reason: "идентифицирующие поля в обоих ответах совпадают — вероятно, тот же объект " +
			"или одна и та же шаблонная страница",
	}
}

// verifyInjection mirrors modules/adaptive.py _verify_injection.
func verifyInjection(session *httpsession.Session, baseURL string, candidate *findings.Candidate, artifactRoot string, deepDive bool) verdict {
	ctx := candidate.Context
	probe, _ := ctx["probe"].(func(string) (*httpsession.Response, error))
	if probe == nil {
		return verdict{outcome: outcomeInconclusive, reason: "нет функции для повторной отправки payload'ов"}
	}

	marker := randomHex(6)
	truePayload := fmt.Sprintf("' OR '%s'='%s' -- -", marker, marker)
	falsePayload := fmt.Sprintf("' AND '%s'='%s_no_match' -- -", marker, marker)

	trueResp, err := probe(truePayload)
	if err != nil {
		return verdict{outcome: outcomeInconclusive, reason: fmt.Sprintf("ошибка при повторной отправке payload'ов: %v", err)}
	}
	falseResp, err := probe(falsePayload)
	if err != nil {
		return verdict{outcome: outcomeInconclusive, reason: fmt.Sprintf("ошибка при повторной отправке payload'ов: %v", err)}
	}
	if trueResp == nil || falseResp == nil {
		return verdict{outcome: outcomeInconclusive, reason: "сервер не ответил на повторные запросы"}
	}

	trueLen, falseLen := len(trueResp.Body), len(falseResp.Body)
	sameStatus := trueResp.StatusCode == falseResp.StatusCode
	similarLen := falseLen == 0 || math.Abs(float64(trueLen-falseLen))/math.Max(float64(falseLen), 1) < 0.03

	if sameStatus && similarLen {
		return verdict{
			outcome: outcomeDiscarded,
			reason: fmt.Sprintf("TRUE- и FALSE-условие дали неразличимые ответы "+
				"(status %d==%d, длина %d≈%d) — похоже на статичную страницу ошибки, "+
				"а не на реальную инъекцию",
				trueResp.StatusCode, falseResp.StatusCode, trueLen, falseLen),
		}
	}

	return verdict{
		outcome: outcomeConfirmed,
		extraEvidence: fmt.Sprintf(
			"Дифференциальная boolean-проверка подтвердила инъекцию:\n"+
				"  TRUE-условие  (%s): HTTP %d, %d байт\n"+
				"  FALSE-условие (%s): HTTP %d, %d байт\n"+
				"Ответы заметно различаются — сервер по-разному обрабатывает true/false условия "+
				"внутри SQL-запроса.",
			truePayload, trueResp.StatusCode, trueLen, falsePayload, falseResp.StatusCode, falseLen),
	}
}

// verifySSRF mirrors modules/adaptive.py _verify_ssrf.
func verifySSRF(session *httpsession.Session, baseURL string, candidate *findings.Candidate, artifactRoot string, deepDive bool) verdict {
	ctx := candidate.Context
	probe, _ := ctx["probe"].(func(string) (*httpsession.Response, error))
	payload, _ := ctx["payload"].(string)
	if probe == nil {
		return verdict{outcome: outcomeInconclusive, reason: "нет функции для повторной отправки SSRF-payload'ов"}
	}

	const controlPayload = "http://127.0.0.1:1/__vsw_unlikely_port__"

	respA, err := probe(payload)
	if err != nil {
		return verdict{outcome: outcomeInconclusive, reason: fmt.Sprintf("ошибка при повторных запросах: %v", err)}
	}
	respB, err := probe(controlPayload)
	if err != nil {
		return verdict{outcome: outcomeInconclusive, reason: fmt.Sprintf("ошибка при повторных запросах: %v", err)}
	}
	if respA == nil || respB == nil {
		return verdict{outcome: outcomeInconclusive, reason: "сервер не ответил на повторные запросы"}
	}

	lenA, lenB := len(respA.Body), len(respB.Body)
	sameStatus := respA.StatusCode == respB.StatusCode
	similarLen := lenB == 0 || math.Abs(float64(lenA-lenB))/math.Max(float64(lenB), 1) < 0.05

	if sameStatus && similarLen {
		return verdict{
			outcome: outcomeDiscarded,
			reason: fmt.Sprintf("ответ на исходный payload неотличим от ответа на заведомо нерабочий адрес "+
				"(status %d==%d, длина %d≈%d) "+
				"— сервер, видимо, не делает запрос по адресу из параметра",
				respA.StatusCode, respB.StatusCode, lenA, lenB),
		}
	}

	return verdict{
		outcome: outcomeConfirmed,
		extraEvidence: fmt.Sprintf(
			"Дифференциальная проверка: ответ на исходный SSRF-payload заметно отличается "+
				"от ответа на заведомо недостижимый адрес (%s):\n"+
				"  Payload:  HTTP %d, %d байт\n"+
				"  Контроль: HTTP %d, %d байт\n"+
				"Сервер по-разному обрабатывает разные адреса назначения — похоже на реальный "+
				"исходящий запрос с сервера.",
			controlPayload, respA.StatusCode, lenA, respB.StatusCode, lenB),
	}
}

// AdminMarkers detects admin-specific UI/JSON markers in a response. Exported
// so the chains package can reuse it. Mirrors modules/adaptive.py _ADMIN_MARKERS.
var AdminMarkers = regexp.MustCompile(`(?i)(панель\s+администратора|admin\s*panel|dashboard|logout|выйти из|welcome,?\s*admin|"role"\s*:\s*"admin"|"is_admin"\s*:\s*true)`)

// verifyAuthBypass mirrors modules/adaptive.py _verify_auth_bypass.
func verifyAuthBypass(session *httpsession.Session, baseURL string, candidate *findings.Candidate, artifactRoot string, deepDive bool) verdict {
	ctx := candidate.Context
	probe, _ := ctx["probe"].(func() (*httpsession.Response, error))
	baselineResp, _ := ctx["baseline_resp"].(*httpsession.Response)
	header, _ := ctx["header"].(string)
	value, _ := ctx["value"].(string)
	if probe == nil || baselineResp == nil {
		return verdict{outcome: outcomeInconclusive, reason: "нет сохранённого контекста для повторной проверки"}
	}

	resp, err := probe()
	if err != nil {
		return verdict{outcome: outcomeInconclusive, reason: fmt.Sprintf("повторный запрос с заголовком не удался: %v", err)}
	}
	if resp == nil {
		return verdict{outcome: outcomeInconclusive, reason: "сервер не ответил на повторный запрос"}
	}

	baselineMarkers := setFromMatches(AdminMarkers.FindAllString(baselineResp.Body, -1))
	bypassMarkers := setFromMatches(AdminMarkers.FindAllString(resp.Body, -1))
	newMarkers := setDifference(bypassMarkers, baselineMarkers)

	if resp.StatusCode == 200 && len(newMarkers) > 0 {
		return verdict{
			outcome: outcomeConfirmed,
			extraEvidence: fmt.Sprintf(
				"Повторная проверка с заголовком '%s: %s':\n"+
					"HTTP %d, обнаружены admin-специфичные маркеры, "+
					"отсутствующие в базовом (без заголовка) ответе: %s",
				header, value, resp.StatusCode, joinSortedTruncated(newMarkers, 300)),
		}
	}

	return verdict{
		outcome: outcomeDiscarded,
		reason: "ответ отличается по размеру, но не содержит admin-специфичных маркеров " +
			"(нет признаков попадания на защищённую страницу) — вероятно, просто другая " +
			"страница того же роутинга, не реальный обход авторизации",
	}
}

var nonAlnumRe = regexp.MustCompile(`[^A-Za-z0-9]+`)

// verifyDisclosure mirrors modules/adaptive.py _verify_disclosure.
func verifyDisclosure(session *httpsession.Session, baseURL string, candidate *findings.Candidate, artifactRoot string, deepDive bool) verdict {
	finding := candidate.Finding
	ctx := candidate.Context
	path, _ := ctx["path"].(string)
	u, _ := ctx["url"].(string)
	if u == "" {
		u = strings.TrimRight(baseURL, "/") + path
	}

	testURL := appendQueryParam(u, "_vsw", randomHex(8))
	resp, err := session.Request("GET", testURL, httpsession.Options{AllowRedirects: true, Timeout: 10 * time.Second})
	if err != nil {
		return verdict{outcome: outcomeInconclusive, reason: fmt.Sprintf("повторный запрос не удался: %v", err)}
	}

	hits := scanForSecrets(resp.Body)
	if len(hits) == 0 {
		return verdict{
			outcome: outcomeDiscarded,
			reason: "содержимое отличается от baseline, но не содержит распознаваемых сигнатур " +
				"секретов/исходного кода — вероятно, не настоящая утечка, а просто иной шаблон " +
				"ответа (страница ошибки, листинг и т.п.)",
		}
	}

	evidenceLines := []string{fmt.Sprintf("Повторный запрос к '%s' (с anti-cache параметром) подтвердил содержимое:", path)}
	artifacts := make([]artifactFile, 0, len(hits))
	for _, hit := range hits {
		evidenceLines = append(evidenceLines, fmt.Sprintf("  - %s: %s", hit.label, hit.snippet))
		artifactName := strings.Trim(nonAlnumRe.ReplaceAllString(hit.label, "_"), "_") + ".txt"
		content := fmt.Sprintf("URL: %s\nСигнатура: %s\nPattern: %s\n\n--- Фрагмент ответа (4000 байт) ---\n%s",
			u, hit.label, hit.pattern, truncate(resp.Body, 4000))
		artifacts = append(artifacts, artifactFile{filename: artifactName, content: content})
	}

	extraEvidence := strings.Join(evidenceLines, "\n")

	if deepDive {
		if siblings, ok := siblingProbes[path]; ok {
			templateYAML := buildNucleiTemplate("adaptive-"+finding.ID, "Adaptive follow-up for "+path, siblings)
			matches := tools.RunCustomNucleiTemplate(session, baseURL, templateYAML, path)
			if len(matches) > 0 {
				lines := []string{fmt.Sprintf("Сгенерированный nuclei-шаблон нашёл %d связанных совпадений "+
					"(карта соседних утечек по той же сигнатуре):", len(matches))}
				limit := len(matches)
				if limit > 8 {
					limit = 8
				}
				for _, m := range matches[:limit] {
					matcherName, _ := m["matcher-name"].(string)
					if matcherName == "" {
						if info, ok := m["info"].(map[string]any); ok {
							matcherName, _ = info["name"].(string)
						}
					}
					matchedAt, _ := m["matched-at"].(string)
					lines = append(lines, fmt.Sprintf("  - %s: %s", matcherName, matchedAt))
				}
				extraEvidence += "\n\n" + strings.Join(lines, "\n")
			}
		}
	}

	crit := findings.Critical
	return verdict{outcome: outcomeConfirmed, extraEvidence: extraEvidence, artifacts: artifacts, newSeverity: &crit}
}

type verifierFunc func(session *httpsession.Session, baseURL string, candidate *findings.Candidate, artifactRoot string, deepDive bool) verdict

// verifiers mirrors modules/adaptive.py VERIFIERS.
var verifiers = map[string]verifierFunc{
	"idor":        verifyIDOR,
	"sqli":        verifyInjection,
	"ssrf":        verifySSRF,
	"auth_bypass": verifyAuthBypass,
	"disclosure":  verifyDisclosure,
}

// ── The confirmation pass ─────────────────────────────────────────────────────

// RunConfirmationPass pops every pending candidate from store, dispatches it
// to the verifier matching its Kind, and either confirms it (with extra
// evidence/artifacts and an upgraded confidence/status), discards it, or
// marks it "unverified" with a downgraded severity. Mirrors
// modules/adaptive.py run_confirmation_pass.
func RunConfirmationPass(session *httpsession.Session, baseURL string, store *findings.FindingStore, artifactRoot string, deepDive bool, verbose bool) {
	candidates := store.PopCandidates()
	if len(candidates) == 0 {
		return
	}

	logging.Printf("[*] Адаптивная проверка: %d кандидат(ов) на углублённый анализ...", len(candidates))

	for _, candidate := range candidates {
		finding := candidate.Finding
		verifier, ok := verifiers[candidate.Kind]

		var v verdict
		if !ok {
			v = verdict{outcome: outcomeInconclusive, reason: fmt.Sprintf("нет верификатора для типа '%s'", candidate.Kind)}
		} else {
			v = func() (result verdict) {
				defer func() {
					if r := recover(); r != nil {
						result = verdict{outcome: outcomeInconclusive, reason: fmt.Sprintf("верификация завершилась с ошибкой: %v", r)}
					}
				}()
				return verifier(session, baseURL, candidate, artifactRoot, deepDive)
			}()
		}

		switch v.outcome {
		case outcomeConfirmed:
			finding.Status = "confirmed-deep-dive"
			finding.Kind = candidate.Kind
			if finding.Confidence < 0.85 {
				finding.Confidence = 0.85
			}
			if v.newSeverity != nil {
				finding.Severity = *v.newSeverity
			}
			if v.extraEvidence != "" {
				prefix := ""
				if finding.Evidence != "" {
					prefix = finding.Evidence + "\n\n"
				}
				finding.Evidence = prefix + "[Подтверждено доп. проверкой]\n" + v.extraEvidence
			}
			finding.VerificationLog = append(finding.VerificationLog,
				fmt.Sprintf("CONFIRMED (%s): углублённая проверка подтвердила находку", candidate.Kind))
			for _, art := range v.artifacts {
				relPath, err := DumpArtifact(artifactRoot, finding.ID, art.filename, art.content)
				if err != nil {
					if verbose {
						logging.Printf("  [!] не удалось сохранить артефакт %s: %v", art.filename, err)
					}
					continue
				}
				finding.Artifacts = append(finding.Artifacts, relPath)
			}
			store.Add(finding)
			logging.Printf("  [+] CONFIRMED: %s", finding.Title)

		case outcomeDiscarded:
			store.AddDiscarded(findings.DiscardedCandidate{Title: finding.Title, Kind: candidate.Kind, Reason: v.reason})
			if verbose {
				logging.Printf("  [-] DISCARDED: %s — %s", finding.Title, v.reason)
			}

		default: // inconclusive
			finding.Status = "unverified"
			finding.Kind = candidate.Kind
			if finding.Confidence > 0.5 {
				finding.Confidence = 0.5
			}
			finding.Severity = finding.Severity.Downgrade()
			finding.VerificationLog = append(finding.VerificationLog, fmt.Sprintf("UNVERIFIED (%s): %s", candidate.Kind, v.reason))
			store.Add(finding)
			if verbose {
				logging.Printf("  [?] UNVERIFIED: %s — %s", finding.Title, v.reason)
			}
		}
	}

	confirmed, unverified := 0, 0
	for _, f := range store.All() {
		switch f.Status {
		case "confirmed-deep-dive":
			confirmed++
		case "unverified":
			unverified++
		}
	}
	logging.Printf("[+] Адаптивная проверка завершена: подтверждено — %d, отброшено — %d, требуют ручной проверки — %d",
		confirmed, len(store.Discarded()), unverified)
}
