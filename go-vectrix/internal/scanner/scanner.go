package scanner

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vectrixgo/internal/adaptive"
	"vectrixgo/internal/chains"
	"vectrixgo/internal/checks"
	"vectrixgo/internal/crawler"
	"vectrixgo/internal/findings"
	"vectrixgo/internal/httpsession"
	"vectrixgo/internal/logging"
	"vectrixgo/internal/report"
	"vectrixgo/internal/tools"
)

const banner = `
 __        __   _       ____            _            _
 \ \      / /__| |__   |  _ \ ___ _ __ | |_ ___  ___| |_
  \ \ /\ / / _ \ '_ \  | |_) / _ \ '_ \| __/ _ \/ __| __|
   \ V  V /  __/ |_) | |  __/  __/ | | | ||  __/\__ \ |_
    \_/\_/ \___|_.__/  |_|   \___|_| |_|\__\___||___/\__|

         AppSec Web Pentest Toolkit  |  Go port`

// Banner prints the toolkit banner and the profile summary, mirroring
// pentest.py banner().
func Banner(profile *Profile, targetCount int) {
	logging.Println(banner)
	logging.Printf("  Режим: %s", profile.Label)
	if targetCount > 1 {
		logging.Printf("  Целей: %d", targetCount)
	}
	logging.Println()
	PrintProfileSummary(profile)
}

// PrintProfileSummary describes which checks and external tools a profile
// enables, mirroring pentest.py _print_profile_summary().
func PrintProfileSummary(p *Profile) {
	var checkNames []string
	if p.CheckHeaders {
		checkNames = append(checkNames, "Headers")
	}
	if p.CheckSSL {
		checkNames = append(checkNames, "SSL/TLS")
	}
	if p.CheckAuth {
		checkNames = append(checkNames, "Auth/JWT/CSRF")
	}
	if p.CheckCORS {
		checkNames = append(checkNames, "CORS")
	}
	if p.CheckDisclosure {
		checkNames = append(checkNames, "Disclosure")
	}
	if p.CheckInjection {
		name := "Injection"
		if p.InjectionTimebased {
			name += " +timebased"
		}
		checkNames = append(checkNames, name)
	}
	if p.CheckIDOR {
		checkNames = append(checkNames, "IDOR/BOLA")
	}
	if p.CheckSSRF {
		checkNames = append(checkNames, "SSRF")
	}
	if p.CheckXXE {
		checkNames = append(checkNames, "XXE")
	}
	if p.CheckHostInject {
		checkNames = append(checkNames, "Host Injection")
	}
	if p.CheckAccountEnum {
		checkNames = append(checkNames, "Account Enum")
	}
	if p.CheckVerbTamper {
		checkNames = append(checkNames, "Verb Tamper/Mass Assign")
	}

	var toolNames []string
	if p.RunWhatweb {
		toolNames = append(toolNames, "whatweb")
	}
	if p.RunWafw00f {
		toolNames = append(toolNames, "wafw00f")
	}
	if p.RunNikto {
		toolNames = append(toolNames, "nikto")
	}
	if p.RunNuclei {
		toolNames = append(toolNames, "nuclei")
	}
	if p.RunGobuster {
		toolNames = append(toolNames, "gobuster")
	}
	if p.RunSqlmap {
		toolNames = append(toolNames, "sqlmap")
	}

	toolsLabel := "—"
	if len(toolNames) > 0 {
		toolsLabel = strings.Join(toolNames, ", ")
	}

	logging.Printf("  Проверки:  %s", strings.Join(checkNames, ", "))
	logging.Printf("  Инструменты: %s", toolsLabel)
	logging.Printf("  Краулинг:  depth=%d, max=%d страниц\n", p.CrawlDepth, p.MaxPages)
}

// ScanOptions are run-wide settings that apply to every target, mirroring the
// CLI flags consumed by scan_single_target in pentest.py.
type ScanOptions struct {
	Verbose         bool
	Workers         int
	ExcludePatterns []string
}

// ScanResult is everything a single-target scan produced, used by the caller
// to build per-target and combined reports.
type ScanResult struct {
	Store     *findings.FindingStore
	Endpoints []crawler.Endpoint
	Meta      map[string]any
}

// nucleiExtraURLs returns the base URL (no query/fragment) of every endpoint,
// for nuclei's extra-targets list. RunNuclei deduplicates against baseURL and
// itself, so no dedup is needed here.
func nucleiExtraURLs(endpoints []crawler.Endpoint) []string {
	urls := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		urls = append(urls, ep.BaseURL())
	}
	return urls
}

// ScanSingleTarget runs the full scan pipeline for one target: crawl,
// external tools, security checks, adaptive-candidate downgrade, sqlmap
// deep-dive, and per-target report generation. Mirrors
// pentest.py scan_single_target().
func ScanSingleTarget(opts ScanOptions, profile *Profile, targetURL string, session *httpsession.Session, outputDir string) (*ScanResult, error) {
	logging.Println()
	logging.Println(strings.Repeat("=", 60))
	logging.Printf("[*] Target: %s", targetURL)
	logging.Println(strings.Repeat("=", 60))

	store := findings.NewFindingStore()
	startTime := time.Now()

	timestamp := startTime.Format("20060102_150405")
	safeHost := strings.ReplaceAll(targetURL, "https://", "")
	safeHost = strings.ReplaceAll(safeHost, "http://", "")
	for _, ch := range []string{"/", ":", "\\", "*", "?", "\"", "<", ">", "|"} {
		safeHost = strings.ReplaceAll(safeHost, ch, "_")
	}
	if len(safeHost) > 40 {
		safeHost = safeHost[:40]
	}
	baseName := fmt.Sprintf("pentest_%s_%s_%s", safeHost, profile.Name, timestamp)

	// ── Phase 1: Crawl ───────────────────────────────────────────────────────
	cr := crawler.New(session, targetURL, profile.CrawlDepth, profile.MaxPages, opts.Verbose, opts.ExcludePatterns)
	endpoints := cr.Crawl()

	if profile.RunGobuster {
		extra := tools.RunGobuster(session, targetURL, store)
		known := make(map[string]struct{}, len(endpoints))
		for _, ep := range endpoints {
			known[ep.URL] = struct{}{}
		}
		for _, u := range extra {
			if _, ok := known[u]; !ok {
				endpoints = append(endpoints, crawler.Endpoint{URL: u, Method: "GET", Source: "gobuster"})
				known[u] = struct{}{}
			}
		}
	}

	// ── Phase 2: External tools ─────────────────────────────────────────────
	logging.Println("\n[*] === External Tools ===")
	var techNames []string
	if profile.RunWhatweb {
		techNames = tools.RunWhatweb(targetURL, session.CookieString(targetURL), store)
	}
	if profile.RunWafw00f {
		tools.RunWafw00f(targetURL, store)
	}
	if profile.RunNikto {
		tools.RunNikto(targetURL, session.CookieString(targetURL), session.AuthorizationHeader(), store)
	}
	if profile.RunNuclei {
		maxTargets := 15
		if profile.NucleiFull {
			maxTargets = 40
		}
		tools.RunNuclei(session, targetURL, store, nucleiExtraURLs(endpoints), tools.TechTags(techNames), maxTargets, profile.NucleiFull)
	}

	// ── Phase 3: Security checks ────────────────────────────────────────────
	type checkItem struct {
		name string
		fn   func()
	}
	var checksToRun []checkItem
	if profile.CheckHeaders {
		checksToRun = append(checksToRun, checkItem{"Headers", func() { checks.RunHeaders(session, targetURL, endpoints, store) }})
	}
	if profile.CheckSSL {
		checksToRun = append(checksToRun, checkItem{"SSL/TLS", func() { checks.RunSSL(session, targetURL, endpoints, store) }})
	}
	if profile.CheckAuth {
		checksToRun = append(checksToRun, checkItem{"Auth/Session", func() { checks.RunAuth(session, targetURL, endpoints, store) }})
	}
	if profile.CheckCORS {
		checksToRun = append(checksToRun, checkItem{"CORS", func() { checks.RunCORS(session, targetURL, endpoints, store) }})
	}
	if profile.CheckDisclosure {
		checksToRun = append(checksToRun, checkItem{"Disclosure", func() { checks.RunDisclosure(session, targetURL, endpoints, store) }})
	}
	if profile.CheckIDOR {
		checksToRun = append(checksToRun, checkItem{"IDOR/BOLA", func() { checks.RunIDOR(session, targetURL, endpoints, store) }})
	}
	if profile.CheckSSRF {
		checksToRun = append(checksToRun, checkItem{"SSRF", func() { checks.RunSSRF(session, targetURL, endpoints, store) }})
	}
	if profile.CheckInjection {
		checksToRun = append(checksToRun, checkItem{"Injection", func() {
			checks.RunInjection(session, targetURL, endpoints, store, profile.InjectionTimebased, profile.InjectionDeepXSS)
		}})
	}
	if profile.CheckXXE {
		checksToRun = append(checksToRun, checkItem{"XXE", func() { checks.RunXXE(session, targetURL, endpoints, store) }})
	}
	if profile.CheckHostInject {
		checksToRun = append(checksToRun, checkItem{"Host Inject", func() { checks.RunHostInjection(session, targetURL, endpoints, store) }})
	}
	if profile.CheckAccountEnum {
		checksToRun = append(checksToRun, checkItem{"Acct Enum", func() { checks.RunAccountEnum(session, targetURL, endpoints, store) }})
	}
	if profile.CheckVerbTamper {
		checksToRun = append(checksToRun, checkItem{"Verb Tamper", func() { checks.RunVerbTamper(session, targetURL, endpoints, store) }})
	}

	workers := opts.Workers
	if workers < 1 {
		workers = 1
	}
	if workers == 1 {
		for _, item := range checksToRun {
			logging.Printf("[*] === %s ===", item.name)
			item.fn()
		}
	} else {
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		for _, item := range checksToRun {
			wg.Add(1)
			sem <- struct{}{}
			go func(it checkItem) {
				defer wg.Done()
				defer func() { <-sem }()
				logging.Printf("[*] === %s ===", it.name)
				it.fn()
			}(item)
		}
		wg.Wait()
	}

	artifactRoot := filepath.Join(outputDir, baseName+"_artifacts")

	// ── Phase 3.5: Adaptive confirmation ────────────────────────────────────
	if profile.AdaptiveConfirm {
		logging.Println("\n[*] === Адаптивная проверка кандидатов ===")
		adaptive.RunConfirmationPass(session, targetURL, store, artifactRoot, profile.AdaptiveDeepDive, opts.Verbose)
	} else {
		for _, candidate := range store.PopCandidates() {
			f := candidate.Finding
			f.Status = "unverified"
			if f.Confidence > 0.5 {
				f.Confidence = 0.5
			}
			f.Severity = f.Severity.Downgrade()
			f.VerificationLog = append(f.VerificationLog,
				"UNVERIFIED: автоматическая проверка отключена в safe-режиме")
			store.Add(f)
		}
	}

	// ── Phase 3.6: Attack-chain analysis ────────────────────────────────────
	if profile.ChainAnalysis {
		logging.Println("\n[*] === Анализ цепочек атак ===")
		chains.RunChainAnalysis(session, targetURL, store, endpoints, artifactRoot, profile.AdaptiveDeepDive, profile.ChainActiveExploit, opts.Verbose)
	}

	// sqlmap deep-dive (aggressive only).
	if profile.RunSqlmap {
		var sqliFindings []*findings.Finding
		for _, f := range store.All() {
			if strings.Contains(f.Title, "SQL Injection") && f.Parameter != "" {
				sqliFindings = append(sqliFindings, f)
				if len(sqliFindings) >= 3 {
					break
				}
			}
		}
		for _, f := range sqliFindings {
			tools.RunSqlmap(session, f.URL, f.Parameter, store)
		}
	}

	// Tag every finding with the target hostname.
	for _, f := range store.All() {
		if f.Target == "" {
			f.Target = targetURL
		}
	}

	elapsed := time.Since(startTime).Seconds()
	logging.Printf("\n[*] %s — сканирование завершено за %.1fс", targetURL, elapsed)

	meta := map[string]any{
		"target":               targetURL,
		"mode":                 profile.Name,
		"date":                 startTime.Format("2006-01-02 15:04:05"),
		"duration_seconds":     roundTo1(elapsed),
		"endpoints_discovered": len(endpoints),
		"request_stats":        session.Stats,
	}

	report.PrintFindings(store, opts.Verbose)

	counts := store.Counts()
	logging.Printf("[+] %s: %d находок (CRITICAL:%d HIGH:%d MEDIUM:%d LOW:%d)",
		targetURL, store.Len(), counts[findings.Critical], counts[findings.High], counts[findings.Medium], counts[findings.Low])

	if err := report.SaveJSON(store, filepath.Join(outputDir, baseName+".json"), meta); err != nil {
		logging.Printf("[!] Ошибка сохранения JSON-отчёта: %v", err)
	}
	if err := report.SaveHTML(store, filepath.Join(outputDir, baseName+".html"), meta, endpoints); err != nil {
		logging.Printf("[!] Ошибка сохранения HTML-отчёта: %v", err)
	}

	return &ScanResult{Store: store, Endpoints: endpoints, Meta: meta}, nil
}

func roundTo1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}
