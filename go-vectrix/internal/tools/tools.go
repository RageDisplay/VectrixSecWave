// Package tools wraps OS-installed external pentest tools (whatweb, wafw00f,
// nikto, nuclei, gobuster, sqlmap) via os/exec, mirroring modules/tools.py.
// Every wrapper is a no-op if the tool is not present on PATH.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
)

// Available reports whether name is on PATH.
func Available(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// externalTools lists every OS tool the toolkit can invoke, mirroring the
// _tool_available() call sites in modules/tools.py (whatweb, wafw00f, nikto,
// nuclei, gobuster, sqlmap).
var externalTools = []struct {
	name        string
	description string
	installHint string
}{
	{"whatweb", "сбор технологий стека (whatweb)", "apt install whatweb (или gem install whatweb)"},
	{"wafw00f", "обнаружение WAF (wafw00f)", "pip install wafw00f"},
	{"nikto", "сканер веб-уязвимостей (nikto)", "apt install nikto"},
	{"nuclei", "сканирование по шаблонам (nuclei)", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
	{"gobuster", "брутфорс директорий/файлов (gobuster)", "apt install gobuster (или go install github.com/OJ/gobuster/v3@latest)"},
	{"sqlmap", "эксплуатация SQL-инъекций (sqlmap)", "apt install sqlmap (или pip install sqlmap)"},
}

// ToolStatus is the availability of one external tool for the current run.
type ToolStatus struct {
	Name        string
	Description string
	InstallHint string
	Available   bool
	Required    bool
}

// CheckAvailability reports the availability of every external tool the
// toolkit can call. needed maps a tool name to whether the active profile
// actually uses it.
func CheckAvailability(needed map[string]bool) []ToolStatus {
	statuses := make([]ToolStatus, 0, len(externalTools))
	for _, t := range externalTools {
		statuses = append(statuses, ToolStatus{
			Name:        t.name,
			Description: t.description,
			InstallHint: t.installHint,
			Available:   Available(t.name),
			Required:    needed[t.name],
		})
	}
	return statuses
}

// PrintAvailability logs a pre-flight summary of which external tools are
// installed on the OS, marking which ones the active profile needs but
// cannot find. This is an upfront overview shown before the scan starts; the
// existing per-call Available() checks inside each Run* function still apply
// and skip gracefully regardless of this summary.
func PrintAvailability(needed map[string]bool) {
	logging.Println("[*] Проверка внешних инструментов ОС:")
	missing := 0
	for _, ts := range CheckAvailability(needed) {
		switch {
		case ts.Available:
			logging.Printf("  [+] %-9s — найден (%s)", ts.Name, ts.Description)
		case ts.Required:
			logging.Printf("  [!] %-9s — НЕ найден (%s) — проверка будет пропущена. Установка: %s",
				ts.Name, ts.Description, ts.InstallHint)
			missing++
		default:
			logging.Printf("  [ ] %-9s — не найден, не требуется в этом режиме (%s)", ts.Name, ts.Description)
		}
	}
	if missing > 0 {
		logging.Printf("[!] %d инструмент(ов), используемых в этом режиме, не найдено в PATH — соответствующие проверки будут пропущены.", missing)
	}
	logging.Println()
}

// run executes cmd with a timeout, returning combined-by-stream output.
// Mirrors modules/tools.py _run().
func run(args []string, timeout time.Duration) (stdout, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	runErr := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Sprintf("Timeout: %v", args), ctx.Err()
	}
	if runErr != nil {
		if _, ok := runErr.(*exec.Error); ok {
			return "", fmt.Sprintf("Tool not found: %s", args[0]), runErr
		}
	}
	return outBuf.String(), errBuf.String(), nil
}

// RunAllTools runs whatweb, wafw00f, nikto and nuclei against baseURL and
// returns the lower-cased technology names whatweb fingerprinted (used by
// RunNuclei to pick technology-specific tags).
func RunAllTools(session *httpsession.Session, baseURL string, store *findings.FindingStore) []string {
	logging.Println("[*] Running external Kali tools...")
	cookieStr := session.CookieString(baseURL)
	authHeader := session.AuthorizationHeader()

	techNames := RunWhatweb(baseURL, cookieStr, store)
	RunWafw00f(baseURL, store)
	RunNikto(baseURL, cookieStr, authHeader, store)
	RunNuclei(session, baseURL, store, nil, nil, 30, true)
	return techNames
}

var whatwebTechRe = regexp.MustCompile(`([A-Za-z][\w\-.]*)\[`)

func RunWhatweb(baseURL, cookieStr string, store *findings.FindingStore) []string {
	if !Available("whatweb") {
		return nil
	}
	logging.Println("  [*] whatweb — технология...")
	cmd := []string{"whatweb", "--colour=never", "-a", "3", baseURL}
	if cookieStr != "" {
		cmd = append(cmd, "--cookie", cookieStr)
	}
	stdout, _, _ := run(cmd, 60*time.Second)

	var techNames []string
	if strings.TrimSpace(stdout) != "" {
		seen := make(map[string]struct{})
		for _, m := range whatwebTechRe.FindAllStringSubmatch(stdout, -1) {
			seen[strings.ToLower(m[1])] = struct{}{}
		}
		for n := range seen {
			techNames = append(techNames, n)
		}
		sort.Strings(techNames)

		f := findings.NewFinding(
			"Обнаружение технологий (whatweb)",
			findings.Info,
			"Reconnaissance",
			"",
			baseURL,
			"Результаты fingerprinting технологий приложения.",
			"Скройте информацию о серверном ПО и версиях:\nServer: ; X-Powered-By: (удалить или обобщить)",
			fmt.Sprintf("whatweb --colour=never -a 3 '%s'", baseURL),
		)
		f.Evidence = truncate(strings.TrimSpace(stdout), 1000)
		store.Add(f)
	}
	return techNames
}

func RunWafw00f(baseURL string, store *findings.FindingStore) {
	if !Available("wafw00f") {
		return
	}
	logging.Println("  [*] wafw00f — WAF detection...")
	stdout, _, _ := run([]string{"wafw00f", baseURL, "--format", "json"}, 30*time.Second)
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return
	}

	var entries []map[string]any
	if err := json.Unmarshal([]byte(stdout), &entries); err != nil {
		var single map[string]any
		if err2 := json.Unmarshal([]byte(stdout), &single); err2 == nil {
			entries = []map[string]any{single}
		} else {
			lower := strings.ToLower(stdout)
			if strings.Contains(lower, "no waf") || strings.Contains(lower, "not detected") {
				f := findings.NewFinding(
					"WAF не обнаружен",
					findings.Low,
					"Reconnaissance",
					"",
					baseURL,
					"Приложение не защищено WAF.",
					"Рассмотрите развёртывание WAF.",
					fmt.Sprintf("wafw00f '%s'", baseURL),
				)
				f.Evidence = truncate(stdout, 200)
				store.Add(f)
			}
			return
		}
	}

	for _, entry := range entries {
		firewall, _ := entry["firewall"].(string)
		if firewall == "" {
			firewall, _ = entry["waf"].(string)
		}
		detected, _ := entry["detected"].(bool)
		if firewall != "" && detected {
			f := findings.NewFinding(
				fmt.Sprintf("WAF обнаружен: %s", firewall),
				findings.Info,
				"Reconnaissance",
				"",
				baseURL,
				fmt.Sprintf("Web Application Firewall '%s' обнаружен перед приложением. "+
					"WAF может блокировать некоторые векторы атак, но не заменяет secure coding.", firewall),
				"",
				fmt.Sprintf("wafw00f '%s'", baseURL),
			)
			f.Evidence = fmt.Sprintf("wafw00f: %s", firewall)
			store.Add(f)
		} else if !detected {
			f := findings.NewFinding(
				"WAF не обнаружен",
				findings.Low,
				"Reconnaissance",
				"",
				baseURL,
				"wafw00f не обнаружил WAF. Приложение может быть напрямую доступно без дополнительного защитного экрана.",
				"Рассмотрите развёртывание WAF (ModSecurity, AWS WAF, CloudFlare) как дополнительный уровень защиты.",
				fmt.Sprintf("wafw00f '%s'", baseURL),
			)
			f.Evidence = "wafw00f: no WAF detected"
			store.Add(f)
		}
	}
}

func RunNikto(baseURL, cookieStr, authHeader string, store *findings.FindingStore) {
	if !Available("nikto") {
		return
	}
	logging.Println("  [*] nikto — веб-сканер...")

	u, err := url.Parse(baseURL)
	if err != nil {
		return
	}
	host := u.Hostname()
	port := u.Port()
	sslFlag := ""
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
			sslFlag = "-ssl"
		} else {
			port = "80"
		}
	} else if u.Scheme == "https" {
		sslFlag = "-ssl"
	}

	cmd := []string{
		"nikto", "-host", host, "-port", port,
		"-nointeractive", "-Format", "csv",
		"-Tuning", "x6",
	}
	if sslFlag != "" {
		cmd = append(cmd, sslFlag)
	}
	if cookieStr != "" {
		cmd = append(cmd, "-cookies", cookieStr)
	}
	if authHeader != "" {
		token := authHeader
		if len(token) > 50 {
			token = token[:50]
		}
		cmd = append(cmd, "-useragent", fmt.Sprintf("Mozilla/5.0 -auth-token %s", token))
	}

	logging.Println("  [*] nikto запущен (может занять 2-5 минут)...")
	stdout, _, _ := run(cmd, 300*time.Second)

	reproduction := fmt.Sprintf("nikto -host '%s' -port %s %s", host, port, sslFlag)
	findingCount := 0
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "host,") {
			continue
		}
		parts := strings.SplitN(line, ",", 7)
		if len(parts) >= 6 {
			vulnDesc := parts[len(parts)-1]
			vulnDesc = strings.Trim(strings.TrimSpace(vulnDesc), `"`)
			if vulnDesc == "" || vulnDesc == "OSVDB" {
				continue
			}

			sev := findings.Medium
			descLower := strings.ToLower(vulnDesc)
			switch {
			case containsAny(descLower, "sql", "injection", "rce", "execute"):
				sev = findings.High
			case containsAny(descLower, "xss", "cross-site"):
				sev = findings.Medium
			case containsAny(descLower, "info", "version", "server", "banner"):
				sev = findings.Low
			}

			title := vulnDesc
			if len(title) > 100 {
				title = title[:100]
			}
			f := findings.NewFinding(
				fmt.Sprintf("Nikto: %s", title),
				sev,
				"Nikto Scan",
				"",
				baseURL,
				fmt.Sprintf("Результат сканирования nikto:\n%s", vulnDesc),
				"Изучите подробности находки и примените соответствующие меры.",
				reproduction,
			)
			f.Evidence = fmt.Sprintf("Nikto CSV: %s", truncate(line, 200))
			store.Add(f)
			findingCount++
		}
	}

	if findingCount == 0 && stdout != "" {
		for _, raw := range strings.Split(stdout, "\n") {
			line := strings.TrimSpace(raw)
			if strings.Contains(raw, "+ ") && len(raw) > 20 && strings.HasPrefix(line, "+") {
				title := line
				if len(title) > 80 {
					title = title[:80]
				}
				if len(title) > 2 {
					title = title[2:]
				}
				f := findings.NewFinding(
					fmt.Sprintf("Nikto: %s", title),
					findings.Low,
					"Nikto Scan",
					"",
					baseURL,
					line,
					"",
					fmt.Sprintf("nikto -host '%s' -port %s", host, port),
				)
				f.Evidence = truncate(line, 300)
				store.Add(f)
			}
		}
	}
}

// techToNucleiTags maps detected technology names (whatweb plugin names,
// lower-cased) to nuclei tags. Mirrors modules/tools.py TECH_TO_NUCLEI_TAGS.
var techToNucleiTags = map[string][]string{
	"wordpress": {"wordpress", "wp-plugin"},
	"drupal":    {"drupal"},
	"joomla":    {"joomla"},
	"jenkins":   {"jenkins"},
	"gitlab":    {"gitlab"},
	"grafana":   {"grafana"},
	"jira":      {"jira", "atlassian"},
	"confluence": {"confluence", "atlassian"},
	"tomcat":    {"tomcat", "apache"},
	"spring":    {"springboot", "spring"},
	"laravel":   {"laravel", "php"},
	"django":    {"django", "python"},
	"magento":   {"magento"},
	"nginx":     {"nginx"},
	"apache":    {"apache"},
	"iis":       {"iis", "microsoft"},
	"php":       {"php"},
}

// TechTags maps detected technology names to nuclei tags, deduplicated and
// order-preserving.
func TechTags(techNames []string) []string {
	seen := make(map[string]struct{})
	var tags []string
	for _, name := range techNames {
		for _, tag := range techToNucleiTags[name] {
			if _, ok := seen[tag]; !ok {
				seen[tag] = struct{}{}
				tags = append(tags, tag)
			}
		}
	}
	return tags
}

type nucleiInfo struct {
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Remediation string   `json:"remediation"`
}

type nucleiResult struct {
	TemplateID  string     `json:"template-id"`
	Info        nucleiInfo `json:"info"`
	MatchedAt   string     `json:"matched-at"`
	CurlCommand string     `json:"curl-command"`
}

// RunNuclei runs nuclei against baseURL plus the (deduplicated) base URLs of
// extraURLs, up to maxTargets total targets. fullTags adds the broader
// "oast"/"token" tags used for the initial recon pass.
func RunNuclei(session *httpsession.Session, baseURL string, store *findings.FindingStore,
	extraURLs []string, extraTags []string, maxTargets int, fullTags bool) {

	if !Available("nuclei") {
		return
	}
	logging.Println("  [*] nuclei — template-based scanner...")

	cookieStr := session.CookieString(baseURL)
	authHeader := session.AuthorizationHeader()

	baseTags := []string{"cve", "exposure", "misconfig"}
	if fullTags {
		baseTags = []string{"cve", "oast", "exposure", "misconfig", "token"}
	}
	tagSeen := make(map[string]struct{})
	var tags []string
	for _, t := range append(baseTags, extraTags...) {
		if _, ok := tagSeen[t]; !ok {
			tagSeen[t] = struct{}{}
			tags = append(tags, t)
		}
	}

	cmd := []string{
		"nuclei",
		"-severity", "critical,high,medium",
		"-silent",
		"-json",
		"-timeout", "10",
		"-c", "20",
		"-rl", "50",
		"-tags", strings.Join(tags, ","),
		"-no-color",
	}

	targetURLs := []string{baseURL}
	seen := map[string]struct{}{baseURL: {}}
	for _, u := range extraURLs {
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			targetURLs = append(targetURLs, u)
		}
		if len(targetURLs) >= maxTargets {
			break
		}
	}

	var targetsFile string
	if len(targetURLs) > 1 {
		f, err := os.CreateTemp("", "nuclei-targets-*.txt")
		if err == nil {
			f.WriteString(strings.Join(targetURLs, "\n"))
			f.Close()
			targetsFile = f.Name()
			cmd = append(cmd, "-l", targetsFile)
		} else {
			cmd = append(cmd, "-u", baseURL)
		}
	} else {
		cmd = append(cmd, "-u", baseURL)
	}
	if targetsFile != "" {
		defer os.Remove(targetsFile)
	}

	if cookieStr != "" {
		cmd = append(cmd, "-H", fmt.Sprintf("Cookie: %s", cookieStr))
	}
	if authHeader != "" {
		cmd = append(cmd, "-H", fmt.Sprintf("Authorization: %s", authHeader))
	}

	logging.Printf("  [*] nuclei запущен на %d цел(ях), теги: %s (может занять 5-10 минут)...",
		len(targetURLs), strings.Join(tags, ","))
	stdout, _, _ := run(cmd, 600*time.Second)

	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var data nucleiResult
		if err := json.Unmarshal([]byte(line), &data); err != nil {
			continue
		}

		templateID := data.TemplateID
		if templateID == "" {
			templateID = "unknown"
		}
		name := data.Info.Name
		if name == "" {
			name = templateID
		}
		matchedAt := data.MatchedAt
		if matchedAt == "" {
			matchedAt = baseURL
		}
		var cve string
		for _, t := range data.Info.Tags {
			if strings.HasPrefix(strings.ToUpper(t), "CVE-") {
				cve = t
				break
			}
		}
		remediation := data.Info.Remediation
		if remediation == "" {
			remediation = "Изучите шаблон nuclei для деталей."
		}
		reproduction := data.CurlCommand
		if reproduction == "" {
			reproduction = fmt.Sprintf("nuclei -u '%s' -t %s", matchedAt, templateID)
		}

		sev := parseSeverity(data.Info.Severity)

		f := findings.NewFinding(
			fmt.Sprintf("Nuclei [%s]: %s", templateID, name),
			sev,
			"Nuclei",
			cve,
			matchedAt,
			fmt.Sprintf("%s\n\nTemplate: %s\nTags: %s", data.Info.Description, templateID, strings.Join(data.Info.Tags, ", ")),
			remediation,
			reproduction,
		)
		f.Evidence = fmt.Sprintf("nuclei matched: %s", matchedAt)
		store.Add(f)
	}
}

func parseSeverity(s string) findings.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return findings.Critical
	case "HIGH":
		return findings.High
	case "MEDIUM":
		return findings.Medium
	case "LOW":
		return findings.Low
	default:
		return findings.Info
	}
}

// RunCustomNucleiTemplate runs nuclei with a dynamically generated template
// (used by adaptive confirmation in Phase 2). Returns the raw parsed JSON
// matches; the caller decides how to turn them into findings/candidates.
func RunCustomNucleiTemplate(session *httpsession.Session, baseURL, templateYAML, label string) []map[string]any {
	if !Available("nuclei") {
		return nil
	}

	cookieStr := session.CookieString(baseURL)
	authHeader := session.AuthorizationHeader()

	f, err := os.CreateTemp("", "nuclei-template-*.yaml")
	if err != nil {
		return nil
	}
	templatePath := f.Name()
	f.WriteString(templateYAML)
	f.Close()
	defer os.Remove(templatePath)

	cmd := []string{
		"nuclei", "-u", baseURL, "-t", templatePath,
		"-json", "-silent", "-no-color", "-timeout", "10",
	}
	if cookieStr != "" {
		cmd = append(cmd, "-H", fmt.Sprintf("Cookie: %s", cookieStr))
	}
	if authHeader != "" {
		cmd = append(cmd, "-H", fmt.Sprintf("Authorization: %s", authHeader))
	}

	if label != "" {
		logging.Printf("  [*] nuclei (сгенерированный шаблон для %s)...", label)
	} else {
		logging.Println("  [*] nuclei (сгенерированный шаблон)...")
	}
	stdout, _, _ := run(cmd, 120*time.Second)

	var matches []map[string]any
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err == nil {
			matches = append(matches, m)
		}
	}
	return matches
}

var gobusterWordlists = []string{
	"/usr/share/wordlists/dirb/common.txt",
	"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
	"/usr/share/dirb/wordlists/common.txt",
}

var gobusterLineRe = regexp.MustCompile(`^(/\S+)\s+\(Status: (\d+)\)`)

// RunGobuster runs gobuster dir-mode discovery and returns the discovered
// URLs.
func RunGobuster(session *httpsession.Session, baseURL string, store *findings.FindingStore) []string {
	if !Available("gobuster") {
		logging.Println("  [!] gobuster not found, skipping directory brute-force")
		return nil
	}

	var wordlist string
	for _, w := range gobusterWordlists {
		if _, err := os.Stat(w); err == nil {
			wordlist = w
			break
		}
	}
	if wordlist == "" {
		logging.Println("  [!] No wordlist found for gobuster")
		return nil
	}

	logging.Printf("  [*] gobuster dir (%s)...", wordlist)
	cookieStr := session.CookieString(baseURL)
	authHeader := session.AuthorizationHeader()

	outFile, err := os.CreateTemp("", "gobuster_*.txt")
	if err != nil {
		return nil
	}
	outPath := outFile.Name()
	outFile.Close()
	defer os.Remove(outPath)

	cmd := []string{
		"gobuster", "dir",
		"-u", baseURL,
		"-w", wordlist,
		"-q",
		"-t", "30",
		"--no-error",
		"-o", outPath,
		"-x", "php,asp,aspx,jsp,json,yaml,xml,bak,old,txt",
		"--timeout", "10s",
	}
	if cookieStr != "" {
		cmd = append(cmd, "-c", cookieStr)
	}
	if authHeader != "" {
		cmd = append(cmd, "-H", fmt.Sprintf("Authorization: %s", authHeader))
	}
	if u, err := url.Parse(baseURL); err == nil && u.Scheme == "https" {
		cmd = append(cmd, "-k")
	}

	run(cmd, 300*time.Second)

	var found []string
	data, err := os.ReadFile(outPath)
	if err != nil {
		return found
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		m := gobusterLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		path := m[1]
		status, _ := strconv.Atoi(m[2])
		fullURL := strings.TrimRight(baseURL, "/") + path
		found = append(found, fullURL)
		if status != 404 && status != 403 {
			f := findings.NewFinding(
				fmt.Sprintf("Gobuster: обнаружен путь [%d] %s", status, path),
				findings.Info,
				"Directory Enumeration",
				"",
				fullURL,
				fmt.Sprintf("Gobuster нашёл доступный путь: %s (HTTP %d)", path, status),
				"Убедитесь что обнаруженные пути не содержат чувствительной информации.",
				fmt.Sprintf("curl -sk '%s'", fullURL),
			)
			f.Evidence = fmt.Sprintf("HTTP %d", status)
			store.Add(f)
		}
	}
	return found
}

// RunSqlmap runs a deep SQL-injection check against url/param via sqlmap.
func RunSqlmap(session *httpsession.Session, rawurl, param string, store *findings.FindingStore) {
	if !Available("sqlmap") {
		return
	}

	cookieStr := session.CookieString(rawurl)
	logging.Printf("  [*] sqlmap → %s (param: %s)", rawurl, param)

	outDir, err := os.MkdirTemp("", "sqlmap_")
	if err != nil {
		return
	}

	cmd := []string{
		"sqlmap", "-u", rawurl,
		"-p", param,
		"--batch",
		"--level", "3",
		"--risk", "2",
		"--timeout", "10",
		"--retries", "2",
		"--output-dir", outDir,
		"--forms",
		"--crawl=2",
	}
	if cookieStr != "" {
		cmd = append(cmd, "--cookie", cookieStr)
	}
	if auth := session.AuthorizationHeader(); auth != "" {
		cmd = append(cmd, "--headers", fmt.Sprintf("Authorization: %s", auth))
	}

	stdout, _, _ := run(cmd, 300*time.Second)

	lower := strings.ToLower(stdout)
	if strings.Contains(lower, "injectable") || strings.Contains(lower, "sqlmap identified") {
		f := findings.NewFinding(
			fmt.Sprintf("SQLMap подтвердил SQL Injection: %s (param: %s)", rawurl, param),
			findings.Critical,
			"Injection",
			"CWE-89",
			rawurl,
			fmt.Sprintf("sqlmap подтвердил SQL-инъекцию в параметре '%s'.\nПолный вывод sqlmap в %s/", param, outDir),
			"1. Параметризованные запросы / Prepared Statements.\n2. ORM с экранированием.\n3. Валидация входных данных.",
			fmt.Sprintf("sqlmap -u '%s' -p '%s' --cookie '%s' --batch --dbs", rawurl, param, cookieStr),
		)
		f.Parameter = param
		f.Evidence = truncate(stdout, 500)
		store.Add(f)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
