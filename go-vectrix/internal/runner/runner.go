// Package runner wires CLI flags or GUI form fields into a full scan run:
// session setup, target probing, checkpoint/resume, the per-target scan
// loop and the combined multi-target report. It is the shared body behind
// both cmd/vectrix (CLI) and cmd/vectrix-gui (Fyne GUI), mirroring
// pentest.py main().
package runner

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vectrixgo/internal/checkpoint"
	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
	"vectrixgo/internal/report"
	"vectrixgo/internal/scanner"
	"vectrixgo/internal/tools"
)

// Config holds every user-configurable scan setting, regardless of whether
// it came from CLI flags or GUI form fields.
type Config struct {
	Targets []string // raw target strings (URLs or bare hostnames)
	Mode    string   // safe | medium | aggressive

	Cookie     string
	CookieFile string
	Token      string
	BasicAuth  string
	Headers    []string // "Name: value"

	Proxy     string
	Depth     int // 0 = use profile default
	MaxPages  int // 0 = use profile default
	Timeout   int // seconds, 0 = default 15
	Excludes  []string

	Delay   float64
	Jitter  float64
	Retries int // 0 = default 3
	Workers int // 0 = default 4

	Verbose        bool
	NoExpiryDetect bool

	OutputDir string
	Resume    bool
}

// Run executes the full scan pipeline for cfg, writing all progress output
// to out. It returns an error only for setup failures (bad mode, no
// reachable targets, ...); per-target scan errors are logged and the run
// continues with the remaining targets.
//
// If ctx is cancelled, the run stops after the current target finishes.
func Run(ctx context.Context, cfg Config, out io.Writer) error {
	logging.SetOutput(out)

	if len(cfg.Targets) == 0 {
		return fmt.Errorf("список целей пуст")
	}

	profile, ok := scanner.Profiles[cfg.Mode]
	if !ok {
		return fmt.Errorf("неизвестный режим: %s (safe|medium|aggressive)", cfg.Mode)
	}
	p := *profile
	if cfg.Depth > 0 {
		p.CrawlDepth = cfg.Depth
	}
	if cfg.MaxPages > 0 {
		p.MaxPages = cfg.MaxPages
	}

	scanner.Banner(&p, len(cfg.Targets))

	tools.PrintAvailability(map[string]bool{
		"whatweb":  p.RunWhatweb,
		"wafw00f":  p.RunWafw00f,
		"nikto":    p.RunNikto,
		"nuclei":   p.RunNuclei,
		"gobuster": p.RunGobuster,
		"sqlmap":   p.RunSqlmap,
	})

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15
	}
	retries := cfg.Retries
	if retries <= 0 {
		retries = 3
	}
	workers := cfg.Workers
	if workers <= 0 {
		workers = 4
	}

	session := httpsession.New()
	session.Timeout = time.Duration(timeout) * time.Second
	session.Delay = time.Duration(cfg.Delay * float64(time.Second))
	session.Jitter = time.Duration(cfg.Jitter * float64(time.Second))
	session.MaxRetries = retries
	session.DetectSessionExpiry = !cfg.NoExpiryDetect
	session.Verbose = cfg.Verbose
	if cfg.Proxy != "" {
		session.SetProxy(cfg.Proxy)
	}
	for _, h := range cfg.Headers {
		if k, v, ok := strings.Cut(h, ":"); ok {
			session.SetHeader(strings.TrimSpace(k), strings.TrimSpace(v))
			session.AuthConfigured = true
		}
	}
	if cfg.Token != "" {
		session.SetBearerToken(cfg.Token)
	}
	if cfg.BasicAuth != "" {
		if u, pw, ok := strings.Cut(cfg.BasicAuth, ":"); ok {
			session.SetBasicAuth(u, pw)
		}
	}
	if cfg.Cookie != "" || cfg.CookieFile != "" {
		session.AuthConfigured = true
	}

	outputDir := cfg.OutputDir
	if outputDir == "" {
		outputDir = "./reports"
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("не удалось создать output-dir: %w", err)
	}

	logging.Println("[*] Проверка доступности целей...")
	var targetURLs []string
	for _, raw := range cfg.Targets {
		if u := probeURL(session, raw, timeout); u != "" {
			targetURLs = append(targetURLs, u)
		} else {
			logging.Printf("[!] Пропускаем недоступную цель: %s", raw)
		}
	}
	if len(targetURLs) == 0 {
		return fmt.Errorf("ни одна цель не доступна")
	}

	// Apply cookie auth to every reachable target's domain.
	for _, t := range targetURLs {
		tu, err := url.Parse(t)
		if err != nil {
			continue
		}
		if cfg.Cookie != "" {
			session.SetCookiesForURL(tu, parseCookieString(cfg.Cookie))
		}
		if cfg.CookieFile != "" {
			if err := session.LoadCookieFile(cfg.CookieFile, tu); err != nil {
				logging.Printf("[!] Cookie file not found: %s", cfg.CookieFile)
			}
		}
	}

	ckpt := checkpoint.New(outputDir, p.Name)
	if cfg.Resume {
		ckpt.Load()
		pending := ckpt.Pending(targetURLs)
		skipped := len(targetURLs) - len(pending)
		if skipped > 0 {
			logging.Printf("[*] Resume: пропускаем %d уже завершённых целей, осталось %d.", skipped, len(pending))
		}
		targetURLs = pending
		if len(targetURLs) == 0 {
			logging.Println("[+] Все цели уже просканированы (resume). Нечего делать.")
			return nil
		}
	} else {
		ckpt.Reset(targetURLs)
	}

	opts := scanner.ScanOptions{Verbose: cfg.Verbose, Workers: workers, ExcludePatterns: cfg.Excludes}

	globalStart := time.Now()
	var allResults []report.AllResultsEntry

	for _, target := range targetURLs {
		select {
		case <-ctx.Done():
			logging.Println("[!] Сканирование остановлено пользователем.")
		default:
			result, err := scanner.ScanSingleTarget(opts, &p, target, session, outputDir)
			if err != nil {
				logging.Printf("[!] Ошибка при сканировании %s: %v", target, err)
				ckpt.MarkDone(target, targetURLs)
				continue
			}
			allResults = append(allResults, report.AllResultsEntry{
				TargetURL: target, Store: result.Store, Endpoints: result.Endpoints, Meta: result.Meta,
			})
			ckpt.MarkDone(target, targetURLs)
			continue
		}
		break
	}

	if remaining := ckpt.Pending(targetURLs); len(remaining) > 0 {
		logging.Printf("[*] Прогресс сохранён. Осталось целей: %d. Продолжить: включите Resume и запустите снова.", len(remaining))
	} else {
		ckpt.Clear()
	}

	if len(allResults) == 0 {
		logging.Println("[!] Нет результатов для отчёта.")
		return nil
	}

	if len(allResults) > 1 {
		globalElapsed := time.Since(globalStart).Seconds()
		ts := globalStart.Format("20060102_150405")
		targets := make([]string, 0, len(allResults))
		for _, r := range allResults {
			targets = append(targets, r.TargetURL)
		}
		globalMeta := map[string]any{
			"targets":                targets,
			"mode":                   p.Name,
			"date":                   globalStart.Format("2006-01-02 15:04:05"),
			"total_duration_seconds": math.Round(globalElapsed*10) / 10,
			"targets_scanned":        len(allResults),
		}

		combinedBase := fmt.Sprintf("pentest_combined_%s_%s", p.Name, ts)
		if err := report.SaveCombinedJSON(allResults, filepath.Join(outputDir, combinedBase+".json"), globalMeta); err != nil {
			logging.Printf("[!] Ошибка сохранения combined JSON: %v", err)
		}
		if err := report.SaveCombinedHTML(allResults, filepath.Join(outputDir, combinedBase+".html"), globalMeta); err != nil {
			logging.Printf("[!] Ошибка сохранения combined HTML: %v", err)
		}

		var totalFindings int
		for _, r := range allResults {
			totalFindings += r.Store.Len()
		}
		logging.Println(strings.Repeat("=", 60))
		logging.Printf("[+] ИТОГО по всем целям: %d доменов, %d находок", len(allResults), totalFindings)
		for _, r := range allResults {
			c := r.Store.Counts()
			logging.Printf("    %s: CRIT:%d HIGH:%d MED:%d LOW:%d",
				r.TargetURL, c[findings.Critical], c[findings.High], c[findings.Medium], c[findings.Low])
		}
		logging.Printf("[+] Объединённый отчёт: %s", filepath.Join(outputDir, combinedBase+".html"))
		logging.Println(strings.Repeat("=", 60))
	}

	return nil
}

// normalizeURL adds an https:// scheme if none is present and strips a
// trailing slash, mirroring pentest.py normalize_url().
func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	return strings.TrimRight(raw, "/")
}

// probeURL returns a reachable URL for raw, trying HTTPS first then HTTP
// (only if no scheme was supplied), mirroring pentest.py probe_url().
func probeURL(session *httpsession.Session, raw string, timeout int) string {
	trimmed := strings.TrimSpace(raw)
	hadScheme := strings.Contains(trimmed, "://")
	candidates := []string{normalizeURL(trimmed)}
	if !hadScheme && strings.HasPrefix(candidates[0], "https://") {
		candidates = append(candidates, "http://"+strings.TrimRight(trimmed, "/"))
	}

	for _, u := range candidates {
		resp, err := session.Get(u, nil)
		if err != nil {
			logging.Printf("  [!] %s: %v", u, err)
			continue
		}
		logging.Printf("[+] Цель доступна: %s  HTTP %d", u, resp.StatusCode)
		return u
	}
	return ""
}

// LoadTargetsFile reads one target per line, skipping blanks and #-comments,
// mirroring pentest.py load_targets_file().
func LoadTargetsFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var targets []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	return targets, nil
}

// parseCookieString turns "name=val; name2=val2" into cookies for
// SetCookiesForURL.
func parseCookieString(s string) []*http.Cookie {
	var cookies []*http.Cookie
	for _, pair := range strings.Split(s, ";") {
		pair = strings.TrimSpace(pair)
		if k, v, ok := strings.Cut(pair, "="); ok {
			cookies = append(cookies, &http.Cookie{Name: strings.TrimSpace(k), Value: strings.TrimSpace(v), Path: "/"})
		}
	}
	return cookies
}
