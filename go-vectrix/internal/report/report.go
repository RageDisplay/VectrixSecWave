// Package report renders scan results as console output, JSON and HTML
// reports. Mirrors modules/report.py.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"vectrixgo/internal/crawler"
	"vectrixgo/internal/findings"
	"vectrixgo/internal/logging"
)

// UseColor controls whether console output includes ANSI colour codes.
// The CLI entrypoint enables it when stdout is a real terminal; the GUI
// leaves it disabled so escape codes don't leak into the log widget.
var UseColor = false

const (
	resetCode = "\033[0m"
	boldCode  = "\033[1m"
)

var severityColors = map[findings.Severity]string{
	findings.Critical: "\033[91m",
	findings.High:     "\033[31m",
	findings.Medium:   "\033[33m",
	findings.Low:      "\033[34m",
	findings.Info:     "\033[36m",
}

func c(code string) string {
	if !UseColor {
		return ""
	}
	return code
}

var statusLabels = map[string]string{
	"confirmed":           "",
	"confirmed-deep-dive": "✓ Подтверждено доп. проверкой",
	"unverified":          "⚠ Не подтверждено автоматически — требуется ручная проверка",
}

// AllResultsEntry is one target's results, used by the combined report
// functions for multi-target scans.
type AllResultsEntry struct {
	TargetURL string
	Store     *findings.FindingStore
	Endpoints []crawler.Endpoint
	Meta      map[string]any
}

// ── Console output ──────────────────────────────────────────────────────────

// PrintFindings prints a summary and every finding (skipping INFO unless
// verbose) to the logging sink. Mirrors print_findings().
func PrintFindings(store *findings.FindingStore, verbose bool) {
	all := store.All()
	counts := store.Counts()

	logging.Println(strings.Repeat("=", 70))
	logging.Printf("%s  РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ%s", c(boldCode), c(resetCode))
	logging.Println(strings.Repeat("=", 70))
	logging.Printf("  %sCRITICAL: %d%s  %sHIGH: %d%s  %sMEDIUM: %d%s  %sLOW: %d%s  %sINFO: %d%s",
		c(severityColors[findings.Critical]), counts[findings.Critical], c(resetCode),
		c(severityColors[findings.High]), counts[findings.High], c(resetCode),
		c(severityColors[findings.Medium]), counts[findings.Medium], c(resetCode),
		c(severityColors[findings.Low]), counts[findings.Low], c(resetCode),
		c(severityColors[findings.Info]), counts[findings.Info], c(resetCode),
	)

	owaspCounts := store.OWASPCounts()
	if len(owaspCounts) > 0 {
		logging.Println("\n  OWASP Top 10:")
		ids := make([]string, 0, len(owaspCounts))
		for oid := range owaspCounts {
			ids = append(ids, oid)
		}
		sort.Strings(ids)
		for _, oid := range ids {
			logging.Printf("    %s %s: %d", oid, findings.OWASPFullNames[oid], owaspCounts[oid])
		}
	}

	logging.Println(strings.Repeat("=", 70) + "\n")

	for _, f := range all {
		if !verbose && f.Severity == findings.Info {
			continue
		}
		printFinding(f)
	}
}

func printFinding(f *findings.Finding) {
	color := c(severityColors[f.Severity])
	reset := c(resetCode)
	bold := c(boldCode)

	logging.Printf("%s%s%s", color, strings.Repeat("─", 70), reset)
	owaspID, owaspName := f.OWASP()
	logging.Printf("%s%s[%s]%s %s%s%s", color, bold, f.Severity, reset, bold, f.Title, reset)

	cwe := f.CWE
	if cwe == "" {
		cwe = "N/A"
	}
	logging.Printf("  %sID:%s %s  |  %sOWASP:%s %s %s  |  %sCWE:%s %s",
		color, reset, f.ID, color, reset, owaspID, owaspName, color, reset, cwe)

	if f.Target != "" {
		logging.Printf("  %sTarget:%s %s", color, reset, f.Target)
	}
	logging.Printf("  %sURL:%s %s", color, reset, f.URL)
	if f.Parameter != "" {
		logging.Printf("  %sParameter:%s %s", color, reset, f.Parameter)
	}
	if label := statusLabels[f.Status]; label != "" {
		logging.Printf("  %sСтатус проверки:%s %s (confidence: %.2f)", color, reset, label, f.Confidence)
	}
	logging.Println()
	logging.Printf("  %sОписание:%s", bold, reset)
	for _, line := range strings.Split(f.Description, "\n") {
		logging.Printf("    %s", line)
	}
	if f.Evidence != "" {
		logging.Printf("\n  %sДоказательства:%s", bold, reset)
		for _, line := range strings.Split(f.Evidence, "\n") {
			logging.Printf("    %s", line)
		}
	}
	if len(f.VerificationLog) > 0 {
		logging.Printf("\n  %sЖурнал доп. проверки:%s", bold, reset)
		for _, line := range f.VerificationLog {
			logging.Printf("    - %s", line)
		}
	}
	if len(f.Artifacts) > 0 {
		logging.Printf("\n  %sИзвлечённые артефакты:%s", bold, reset)
		for _, a := range f.Artifacts {
			logging.Printf("    - %s", a)
		}
	}
	logging.Printf("\n  %sКак воспроизвести:%s", bold, reset)
	for _, line := range strings.Split(f.Reproduction, "\n") {
		logging.Printf("    %s", line)
	}
	logging.Printf("\n  %sРекомендации:%s", bold, reset)
	for _, line := range strings.Split(f.Remediation, "\n") {
		logging.Printf("    %s", line)
	}
	logging.Println()
}

// ── JSON ─────────────────────────────────────────────────────────────────────

type findingJSON struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Severity        string   `json:"severity"`
	OWASPID         string   `json:"owasp_id"`
	OWASPName       string   `json:"owasp_name"`
	Category        string   `json:"category"`
	CWE             string   `json:"cwe"`
	Target          string   `json:"target"`
	URL             string   `json:"url"`
	Parameter       string   `json:"parameter"`
	Method          string   `json:"method"`
	Description     string   `json:"description"`
	Evidence        string   `json:"evidence"`
	Reproduction    string   `json:"reproduction"`
	Remediation     string   `json:"remediation"`
	Status          string   `json:"status"`
	Confidence      float64  `json:"confidence"`
	VerificationLog []string `json:"verification_log"`
	Artifacts       []string `json:"artifacts"`
}

type discardedJSON struct {
	Title  string `json:"title"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func toFindingJSON(f *findings.Finding) findingJSON {
	oid, oname := f.OWASP()
	return findingJSON{
		ID:              f.ID,
		Title:           f.Title,
		Severity:        string(f.Severity),
		OWASPID:         oid,
		OWASPName:       oname,
		Category:        f.Category,
		CWE:             f.CWE,
		Target:          f.Target,
		URL:             f.URL,
		Parameter:       f.Parameter,
		Method:          f.Method,
		Description:     f.Description,
		Evidence:        f.Evidence,
		Reproduction:    f.Reproduction,
		Remediation:     f.Remediation,
		Status:          f.Status,
		Confidence:      f.Confidence,
		VerificationLog: nonNil(f.VerificationLog),
		Artifacts:       nonNil(f.Artifacts),
	}
}

// marshalJSON encodes v as indented JSON without HTML-escaping (matching
// Python's json.dumps(..., ensure_ascii=False, indent=2)).
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// SaveJSON writes a single-target JSON report. Mirrors save_json().
func SaveJSON(store *findings.FindingStore, path string, meta map[string]any) error {
	all := store.All()
	findingsJSON := make([]findingJSON, 0, len(all))
	for _, f := range all {
		findingsJSON = append(findingsJSON, toFindingJSON(f))
	}

	discarded := store.Discarded()
	discardedJSONs := make([]discardedJSON, 0, len(discarded))
	for _, d := range discarded {
		discardedJSONs = append(discardedJSONs, discardedJSON{Title: d.Title, Kind: d.Kind, Reason: d.Reason})
	}

	data := map[string]any{
		"scan_meta":            meta,
		"summary":              store.Counts(),
		"owasp_summary":        store.OWASPCounts(),
		"total":                store.Len(),
		"findings":             findingsJSON,
		"discarded_candidates": discardedJSONs,
	}

	b, err := marshalJSON(data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	logging.Printf("[+] JSON-отчёт сохранён: %s", path)
	return nil
}

// SaveCombinedJSON writes a single JSON report covering multiple targets.
// Mirrors save_combined_json().
func SaveCombinedJSON(allResults []AllResultsEntry, path string, globalMeta map[string]any) error {
	combinedCounts := map[findings.Severity]int{
		findings.Critical: 0, findings.High: 0, findings.Medium: 0, findings.Low: 0, findings.Info: 0,
	}
	combinedOWASP := make(map[string]int)
	targetsSummary := make([]map[string]any, 0, len(allResults))
	allFindings := make([]findingJSON, 0)

	for _, r := range allResults {
		counts := r.Store.Counts()
		for k, v := range counts {
			combinedCounts[k] += v
		}
		for oid, cnt := range r.Store.OWASPCounts() {
			combinedOWASP[oid] += cnt
		}
		targetsSummary = append(targetsSummary, map[string]any{
			"target":               r.TargetURL,
			"findings":             r.Store.Len(),
			"counts":               counts,
			"owasp":                r.Store.OWASPCounts(),
			"duration_seconds":     r.Meta["duration_seconds"],
			"endpoints_discovered": len(r.Endpoints),
		})
		for _, f := range r.Store.All() {
			allFindings = append(allFindings, toFindingJSON(f))
		}
	}

	weight := map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
	sort.SliceStable(allFindings, func(i, j int) bool {
		return weight[allFindings[i].Severity] > weight[allFindings[j].Severity]
	})

	data := map[string]any{
		"scan_meta":       globalMeta,
		"targets_summary": targetsSummary,
		"combined_counts": combinedCounts,
		"combined_owasp":  combinedOWASP,
		"total":           len(allFindings),
		"findings":        allFindings,
	}

	b, err := marshalJSON(data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	logging.Printf("[+] Объединённый JSON-отчёт сохранён: %s", path)
	return nil
}

// ── HTML helpers ─────────────────────────────────────────────────────────────

func esc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}

// hostOf returns the host[:port] portion of a URL, or the input unchanged if
// it has none. Mirrors `urlparse(u).netloc or u`.
func hostOf(rawurl string) string {
	if u, err := url.Parse(rawurl); err == nil && u.Host != "" {
		return u.Host
	}
	return rawurl
}

func owaspSummaryHTML(owaspCounts map[string]int) string {
	if len(owaspCounts) == 0 {
		return ""
	}
	ids := make([]string, 0, len(owaspCounts))
	for oid := range owaspCounts {
		ids = append(ids, oid)
	}
	sort.Strings(ids)

	var cards strings.Builder
	for _, oid := range ids {
		fmt.Fprintf(&cards,
			`<div class="owasp-card" data-owasp="%s" onclick="filterOWASP('%s')">`+
				`<div class="owasp-id">%s</div>`+
				`<div class="owasp-name">%s</div>`+
				`<div class="owasp-count">%d</div>`+
				`</div>`,
			esc(oid), esc(oid), esc(oid), esc(findings.OWASPFullNames[oid]), owaspCounts[oid])
	}
	return `<div class="section-title">OWASP Top 10 — распределение находок ` +
		`<span style="font-size:0.75em;color:var(--text2)">(кликните для фильтра)</span></div>` +
		`<div class="owasp-grid">` + cards.String() + `</div>`
}

func targetsSummaryHTML(allResults []AllResultsEntry) string {
	if len(allResults) <= 1 {
		return ""
	}
	var rows strings.Builder
	for _, r := range allResults {
		counts := r.Store.Counts()
		fmt.Fprintf(&rows,
			`<tr class="target-row" onclick="filterTarget('%s')" style="cursor:pointer">`+
				`<td class="url-pill">%s</td>`+
				`<td style="color:var(--c-critical)">%d</td>`+
				`<td style="color:var(--c-high)">%d</td>`+
				`<td style="color:var(--c-medium)">%d</td>`+
				`<td style="color:var(--c-low)">%d</td>`+
				`<td>%d</td>`+
				`</tr>`,
			esc(r.TargetURL), esc(hostOf(r.TargetURL)),
			counts[findings.Critical], counts[findings.High], counts[findings.Medium], counts[findings.Low],
			len(r.Endpoints))
	}
	return `<div class="section-title">Цели сканирования</div>` +
		`<div class="endpoints-section" style="overflow-x:auto">` +
		`<table style="width:100%;border-collapse:collapse;font-size:0.9em">` +
		`<thead><tr style="color:var(--text2);text-align:left">` +
		`<th style="padding:6px 10px">Домен</th>` +
		`<th style="padding:6px 10px;color:var(--c-critical)">CRIT</th>` +
		`<th style="padding:6px 10px;color:var(--c-high)">HIGH</th>` +
		`<th style="padding:6px 10px;color:var(--c-medium)">MED</th>` +
		`<th style="padding:6px 10px;color:var(--c-low)">LOW</th>` +
		`<th style="padding:6px 10px">Endpoints</th>` +
		`</tr></thead>` +
		`<tbody>` + rows.String() + `</tbody>` +
		`</table>` +
		`</div>`
}

func targetFilterButtonsHTML(targets []string) string {
	if len(targets) <= 1 {
		return ""
	}
	buttons := []string{`<button class="filter-btn all active" onclick="filterTarget('all')">Все цели</button>`}
	for _, t := range targets {
		buttons = append(buttons, fmt.Sprintf(
			`<button class="filter-btn" onclick="filterTarget('%s')">%s</button>`,
			esc(t), esc(hostOf(t))))
	}
	return `<span style="color:var(--text2);font-size:0.85em;margin-left:16px">Цель:</span> ` + strings.Join(buttons, " ")
}

// ── HTML templates ───────────────────────────────────────────────────────────

const htmlTemplate = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pentest Report — {title}</title>
<style>
  :root {
    --c-critical: #dc2626; --c-high: #ea580c; --c-medium: #d97706;
    --c-low: #2563eb; --c-info: #0891b2; --bg: #0f172a; --bg2: #1e293b;
    --bg3: #334155; --text: #e2e8f0; --text2: #94a3b8; --border: #475569;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
  .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
  .header { background: var(--bg2); border-radius: 12px; padding: 30px; margin-bottom: 24px; border-left: 5px solid #dc2626; }
  .header h1 { font-size: 2em; color: #f8fafc; margin-bottom: 8px; }
  .header .meta { color: var(--text2); font-size: 0.9em; }
  .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; }
  .sev-card { background: var(--bg2); border-radius: 10px; padding: 20px; text-align: center; border-top: 4px solid; }
  .sev-card.critical { border-color: var(--c-critical); } .sev-card.high { border-color: var(--c-high); }
  .sev-card.medium { border-color: var(--c-medium); } .sev-card.low { border-color: var(--c-low); }
  .sev-card.info { border-color: var(--c-info); }
  .sev-card .count { font-size: 2.5em; font-weight: 700; }
  .sev-card .label { color: var(--text2); font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }
  .critical .count { color: var(--c-critical); } .high .count { color: var(--c-high); }
  .medium .count { color: var(--c-medium); } .low .count { color: var(--c-low); }
  .info .count { color: var(--c-info); }
  /* OWASP grid */
  .owasp-grid { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 24px; }
  .owasp-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 10px;
    padding: 12px 16px; cursor: pointer; transition: border-color .2s; min-width: 160px; flex: 1; }
  .owasp-card:hover, .owasp-card.active { border-color: #38bdf8; }
  .owasp-id { font-size: 0.75em; font-weight: 700; color: #38bdf8; letter-spacing: 1px; }
  .owasp-name { font-size: 0.8em; color: var(--text2); margin: 2px 0 6px; }
  .owasp-count { font-size: 1.6em; font-weight: 700; color: var(--text); }
  /* section */
  .section-title { font-size: 1.3em; font-weight: 600; color: var(--text2); text-transform: uppercase;
    letter-spacing: 1px; margin: 24px 0 12px; }
  .finding { background: var(--bg2); border-radius: 10px; margin-bottom: 16px; overflow: hidden; border: 1px solid var(--border); }
  .finding-header { padding: 16px 20px; display: flex; align-items: center; gap: 12px; cursor: pointer; user-select: none; }
  .finding-header:hover { background: var(--bg3); }
  .badge { padding: 3px 10px; border-radius: 20px; font-size: 0.75em; font-weight: 700; text-transform: uppercase; color: #fff; }
  .badge.critical { background: var(--c-critical); } .badge.high { background: var(--c-high); }
  .badge.medium { background: var(--c-medium); } .badge.low { background: var(--c-low); }
  .badge.info { background: var(--c-info); }
  .badge.owasp { background: #1e40af; font-size: 0.7em; }
  .finding-title { font-weight: 600; flex: 1; }
  .finding-meta { color: var(--text2); font-size: 0.8em; }
  .finding-body { padding: 20px; border-top: 1px solid var(--border); display: none; }
  .finding-body.open { display: block; }
  .field-label { font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px; color: var(--text2); margin-top: 16px; margin-bottom: 4px; font-weight: 600; }
  .field-value { color: var(--text); }
  pre, code { background: #0f172a; border-radius: 6px; padding: 12px; overflow-x: auto;
    font-family: 'Fira Code', 'Cascadia Code', monospace; font-size: 0.85em; color: #a3e635;
    white-space: pre-wrap; word-break: break-all; border: 1px solid var(--border); }
  .url-pill { display: inline-block; background: var(--bg3); border-radius: 4px; padding: 2px 8px;
    font-family: monospace; font-size: 0.85em; word-break: break-all; }
  .filter-bar { background: var(--bg2); border-radius: 10px; padding: 16px 20px; margin-bottom: 16px;
    display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
  .filter-btn { padding: 6px 14px; border-radius: 20px; border: 2px solid var(--border); background: transparent;
    color: var(--text); cursor: pointer; font-size: 0.85em; transition: all 0.2s; }
  .filter-btn:hover, .filter-btn.active { border-color: currentColor; background: rgba(255,255,255,.05); }
  .filter-btn.critical { color: var(--c-critical); } .filter-btn.high { color: var(--c-high); }
  .filter-btn.medium { color: var(--c-medium); } .filter-btn.low { color: var(--c-low); }
  .filter-btn.info { color: var(--c-info); } .filter-btn.all { color: var(--text); }
  .endpoints-section { background: var(--bg2); border-radius: 10px; padding: 20px; margin-bottom: 16px; }
  .endpoint-list { max-height: 300px; overflow-y: auto; }
  .endpoint-item { padding: 6px 0; border-bottom: 1px solid var(--border); font-family: monospace; font-size: 0.85em; color: var(--text2); }
  .endpoint-item .method { display: inline-block; width: 50px; color: #a3e635; font-weight: bold; }
  .verify-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: 600; margin-top: 12px; }
  .verify-badge.confirmed { background: rgba(34,197,94,0.15); color: #4ade80; border: 1px solid #4ade80; }
  .verify-badge.unverified { background: rgba(217,119,6,0.15); color: #fbbf24; border: 1px solid #fbbf24; }
  .verify-log { margin: 6px 0 0 18px; color: var(--text2); font-size: 0.85em; }
  .verify-log li { margin-bottom: 4px; }
  .artifact-list { list-style: none; margin-top: 4px; }
  .artifact-list li { margin-bottom: 4px; }
  .artifact-list a { color: #38bdf8; font-family: monospace; font-size: 0.85em; word-break: break-all; }
  .discarded-section { background: var(--bg2); border-radius: 10px; margin-bottom: 16px; border: 1px solid var(--border); overflow: hidden; }
  .discarded-header { padding: 14px 20px; cursor: pointer; user-select: none; color: var(--text2); font-weight: 600; }
  .discarded-header:hover { background: var(--bg3); }
  .discarded-body { padding: 0 20px 16px; display: none; }
  .discarded-body.open { display: block; }
  .discarded-item { padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 0.85em; }
  .discarded-item .d-title { color: var(--text); font-weight: 600; }
  .discarded-item .d-reason { color: var(--text2); }
  .target-row:hover td { background: var(--bg3); }
  .target-row td { padding: 8px 10px; border-bottom: 1px solid var(--border); }
  @media (max-width: 768px) { .summary { grid-template-columns: repeat(3, 1fr); } .owasp-grid { flex-direction: column; } }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>Отчёт о тестировании безопасности</h1>
    <div class="meta">
      <strong>Цель:</strong> {header_target} &nbsp;|&nbsp;
      <strong>Дата:</strong> {date} &nbsp;|&nbsp;
      <strong>Всего находок:</strong> {total}
    </div>
  </div>

  <div class="summary">
    <div class="sev-card critical"><div class="count">{c_critical}</div><div class="label">Critical</div></div>
    <div class="sev-card high"><div class="count">{c_high}</div><div class="label">High</div></div>
    <div class="sev-card medium"><div class="count">{c_medium}</div><div class="label">Medium</div></div>
    <div class="sev-card low"><div class="count">{c_low}</div><div class="label">Low</div></div>
    <div class="sev-card info"><div class="count">{c_info}</div><div class="label">Info</div></div>
  </div>

  {owasp_section}

  {targets_section}

  {endpoints_section}

  {discarded_section}

  <div class="filter-bar">
    <span style="color:var(--text2);font-size:0.85em;">Severity:</span>
    <button class="filter-btn all active" onclick="filterSev('all')">Все</button>
    <button class="filter-btn critical" onclick="filterSev('critical')">Critical</button>
    <button class="filter-btn high" onclick="filterSev('high')">High</button>
    <button class="filter-btn medium" onclick="filterSev('medium')">Medium</button>
    <button class="filter-btn low" onclick="filterSev('low')">Low</button>
    <button class="filter-btn info" onclick="filterSev('info')">Info</button>
    {target_filter_buttons}
  </div>

  <div id="findings-list">
    {findings_html}
  </div>
</div>

<script>
var activeSev = 'all';
var activeOWASP = 'all';
var activeTarget = 'all';

function applyFilters() {
  document.querySelectorAll('.finding').forEach(function(el) {
    var sevOk    = activeSev    === 'all' || el.dataset.sev    === activeSev;
    var owaspOk  = activeOWASP  === 'all' || el.dataset.owasp  === activeOWASP;
    var targetOk = activeTarget === 'all' || el.dataset.target === activeTarget;
    el.style.display = (sevOk && owaspOk && targetOk) ? '' : 'none';
  });
}

function filterSev(sev) {
  activeSev = sev;
  document.querySelectorAll('.filter-btn.critical,.filter-btn.high,.filter-btn.medium,.filter-btn.low,.filter-btn.info,.filter-btn.all').forEach(function(b) { b.classList.remove('active'); });
  var sel = sev === 'all' ? '.filter-btn.all' : '.filter-btn.' + sev;
  var btn = document.querySelector(sel);
  if (btn) btn.classList.add('active');
  applyFilters();
}

function filterOWASP(oid) {
  if (activeOWASP === oid) { activeOWASP = 'all'; } else { activeOWASP = oid; }
  document.querySelectorAll('.owasp-card').forEach(function(c) { c.classList.remove('active'); });
  if (activeOWASP !== 'all') {
    var card = document.querySelector('[data-owasp="' + oid + '"]');
    if (card) card.classList.add('active');
  }
  applyFilters();
}

function filterTarget(t) {
  activeTarget = t;
  document.querySelectorAll('.filter-btn').forEach(function(b) {
    if (b.textContent === 'Все цели' && t === 'all') b.classList.add('active');
    else b.classList.remove('active');
  });
  applyFilters();
}

function toggleFinding(id) {
  var body = document.getElementById('body-' + id);
  if (body) body.classList.toggle('open');
}

function toggleDiscarded() {
  var body = document.getElementById('discarded-body');
  if (body) body.classList.toggle('open');
}
</script>
</body>
</html>
`

const findingTemplate = `
<div class="finding" data-sev="{sev_lower}" data-owasp="{owasp_id}" data-target="{target_escaped}">
  <div class="finding-header" onclick="toggleFinding('{fid}')">
    <span class="badge {sev_lower}">{sev}</span>
    <span class="badge owasp">{owasp_id}</span>
    <span class="finding-title">{title}</span>
    <span class="finding-meta">{category} | {fid}{target_label}</span>
  </div>
  <div class="finding-body" id="body-{fid}">
    <div class="field-label">URL</div>
    <div class="url-pill">{url}</div>
    {param_block}
    <div class="field-label">OWASP</div>
    <div class="field-value">{owasp_id} — {owasp_name}</div>
    <div class="field-label">CWE</div>
    <div class="field-value">{cwe}</div>
    <div class="field-label">Описание</div>
    <div class="field-value">{description}</div>
    <div class="field-label">Доказательства</div>
    <pre>{evidence}</pre>
    {verify_block}
    {artifacts_block}
    <div class="field-label">Как воспроизвести</div>
    <pre>{reproduction}</pre>
    <div class="field-label">Рекомендации</div>
    <div class="field-value">{remediation}</div>
  </div>
</div>
`

func renderTemplate(tmpl string, values map[string]string) string {
	pairs := make([]string, 0, len(values)*2)
	for k, v := range values {
		pairs = append(pairs, "{"+k+"}", v)
	}
	return strings.NewReplacer(pairs...).Replace(tmpl)
}

// ── HTML save functions ──────────────────────────────────────────────────────

func buildFindingHTML(f *findings.Finding) string {
	paramBlock := ""
	if f.Parameter != "" {
		paramBlock = fmt.Sprintf(
			`<div class="field-label">Параметр</div><div class="url-pill">%s</div>`,
			esc(f.Parameter))
	}

	verifyBlock := ""
	if badgeLabel := statusLabels[f.Status]; badgeLabel != "" {
		badgeClass := "unverified"
		if f.Status == "confirmed-deep-dive" {
			badgeClass = "confirmed"
		}
		verifyBlock = fmt.Sprintf(`<span class="verify-badge %s">%s (confidence: %.2f)</span>`,
			badgeClass, esc(badgeLabel), f.Confidence)
		if len(f.VerificationLog) > 0 {
			items := make([]string, len(f.VerificationLog))
			for i, line := range f.VerificationLog {
				items[i] = "<li>" + esc(line) + "</li>"
			}
			verifyBlock += `<ul class="verify-log">` + strings.Join(items, "\n") + `</ul>`
		}
	}

	artifactsBlock := ""
	if len(f.Artifacts) > 0 {
		items := make([]string, len(f.Artifacts))
		for i, a := range f.Artifacts {
			items[i] = fmt.Sprintf(`<li><a href="%s" target="_blank">%s</a></li>`, esc(a), esc(a))
		}
		artifactsBlock = `<div class="field-label">Извлечённые артефакты</div><ul class="artifact-list">` +
			strings.Join(items, "\n") + `</ul>`
	}

	owaspID, owaspName := f.OWASP()

	targetLabel := ""
	if f.Target != "" {
		targetLabel = " | " + esc(hostOf(f.Target))
	}

	cwe := f.CWE
	if cwe == "" {
		cwe = "N/A"
	}
	evidence := f.Evidence
	if evidence == "" {
		evidence = "—"
	}
	reproduction := f.Reproduction
	if reproduction == "" {
		reproduction = "—"
	}

	return renderTemplate(findingTemplate, map[string]string{
		"sev_lower":        strings.ToLower(string(f.Severity)),
		"sev":              string(f.Severity),
		"fid":              f.ID,
		"title":            esc(f.Title),
		"category":         esc(f.Category),
		"owasp_id":         esc(owaspID),
		"owasp_name":       esc(owaspName),
		"cwe":              esc(cwe),
		"url":              esc(f.URL),
		"target_escaped":   esc(f.Target),
		"target_label":     esc(targetLabel),
		"param_block":      paramBlock,
		"description":      strings.ReplaceAll(esc(f.Description), "\n", "<br>"),
		"evidence":         esc(evidence),
		"verify_block":     verifyBlock,
		"artifacts_block":  artifactsBlock,
		"reproduction":     esc(reproduction),
		"remediation":      strings.ReplaceAll(esc(f.Remediation), "\n", "<br>"),
	})
}

func endpointItemsHTML(endpoints []crawler.Endpoint, limit int) string {
	if len(endpoints) > limit {
		endpoints = endpoints[:limit]
	}
	items := make([]string, len(endpoints))
	for i, ep := range endpoints {
		items[i] = fmt.Sprintf(`<div class="endpoint-item"><span class="method">%s</span> %s</div>`,
			esc(ep.Method), esc(ep.URL))
	}
	return strings.Join(items, "\n")
}

// SaveHTML writes a single-target HTML report. Mirrors save_html().
func SaveHTML(store *findings.FindingStore, path string, meta map[string]any, endpoints []crawler.Endpoint) error {
	counts := store.Counts()
	owaspCounts := store.OWASPCounts()

	all := store.All()
	findingsHTML := make([]string, len(all))
	for i, f := range all {
		findingsHTML[i] = buildFindingHTML(f)
	}

	endpointsSection := ""
	if len(endpoints) > 0 {
		endpointsSection = fmt.Sprintf(
			`<div class="section-title">Обнаруженные эндпоинты (%d)</div><div class="endpoints-section"><div class="endpoint-list">%s</div></div>`,
			len(endpoints), endpointItemsHTML(endpoints, 200))
	}

	discarded := store.Discarded()
	discardedSection := ""
	if len(discarded) > 0 {
		items := make([]string, len(discarded))
		for i, d := range discarded {
			items[i] = fmt.Sprintf(
				`<div class="discarded-item"><div class="d-title">[%s] %s</div><div class="d-reason">%s</div></div>`,
				esc(d.Kind), esc(d.Title), esc(d.Reason))
		}
		discardedSection = fmt.Sprintf(
			`<div class="discarded-section"><div class="discarded-header" onclick="toggleDiscarded()">▾ Отброшено автоматической проверкой (%d) — кандидаты, не подтвердившиеся при углублённой проверке</div><div class="discarded-body" id="discarded-body">%s</div></div>`,
			len(discarded), strings.Join(items, "\n"))
	}

	target, _ := meta["target"].(string)
	date, _ := meta["date"].(string)

	html := renderTemplate(htmlTemplate, map[string]string{
		"title":                 esc(hostOf(target)),
		"header_target":         esc(target),
		"date":                  date,
		"total":                 fmt.Sprintf("%d", store.Len()),
		"c_critical":            fmt.Sprintf("%d", counts[findings.Critical]),
		"c_high":                fmt.Sprintf("%d", counts[findings.High]),
		"c_medium":              fmt.Sprintf("%d", counts[findings.Medium]),
		"c_low":                 fmt.Sprintf("%d", counts[findings.Low]),
		"c_info":                fmt.Sprintf("%d", counts[findings.Info]),
		"owasp_section":         owaspSummaryHTML(owaspCounts),
		"targets_section":       "",
		"endpoints_section":     endpointsSection,
		"discarded_section":     discardedSection,
		"target_filter_buttons": "",
		"findings_html":         strings.Join(findingsHTML, "\n"),
	})

	if err := os.WriteFile(path, []byte(html), 0o644); err != nil {
		return err
	}
	logging.Printf("[+] HTML-отчёт сохранён: %s", path)
	return nil
}

// SaveCombinedHTML writes a single HTML report covering multiple targets.
// Mirrors save_combined_html().
func SaveCombinedHTML(allResults []AllResultsEntry, path string, globalMeta map[string]any) error {
	combinedCounts := map[findings.Severity]int{
		findings.Critical: 0, findings.High: 0, findings.Medium: 0, findings.Low: 0, findings.Info: 0,
	}
	combinedOWASP := make(map[string]int)
	var allFindingsHTML []string
	var allEndpoints []crawler.Endpoint
	var allTargets []string

	for _, r := range allResults {
		allTargets = append(allTargets, r.TargetURL)
		eps := r.Endpoints
		if len(eps) > 50 {
			eps = eps[:50]
		}
		allEndpoints = append(allEndpoints, eps...)
		for k, v := range r.Store.Counts() {
			combinedCounts[k] += v
		}
		for oid, cnt := range r.Store.OWASPCounts() {
			combinedOWASP[oid] += cnt
		}
		for _, f := range r.Store.All() {
			allFindingsHTML = append(allFindingsHTML, buildFindingHTML(f))
		}
	}

	endpointsSection := ""
	if len(allEndpoints) > 0 {
		endpointsSection = fmt.Sprintf(
			`<div class="section-title">Обнаруженные эндпоинты (всего ≈%d)</div><div class="endpoints-section"><div class="endpoint-list">%s</div></div>`,
			len(allEndpoints), endpointItemsHTML(allEndpoints, 300))
	}

	titleStr := fmt.Sprintf("%d целей", len(allResults))

	headerHosts := make([]string, 0, 5)
	for i, t := range allTargets {
		if i >= 5 {
			break
		}
		headerHosts = append(headerHosts, hostOf(t))
	}
	headerTarget := fmt.Sprintf("%d доменов: %s", len(allResults), strings.Join(headerHosts, ", "))
	if len(allTargets) > 5 {
		headerTarget += " ..."
	}

	date, _ := globalMeta["date"].(string)
	total := combinedCounts[findings.Critical] + combinedCounts[findings.High] +
		combinedCounts[findings.Medium] + combinedCounts[findings.Low] + combinedCounts[findings.Info]

	html := renderTemplate(htmlTemplate, map[string]string{
		"title":                 esc(titleStr),
		"header_target":         esc(headerTarget),
		"date":                  date,
		"total":                 fmt.Sprintf("%d", total),
		"c_critical":            fmt.Sprintf("%d", combinedCounts[findings.Critical]),
		"c_high":                fmt.Sprintf("%d", combinedCounts[findings.High]),
		"c_medium":              fmt.Sprintf("%d", combinedCounts[findings.Medium]),
		"c_low":                 fmt.Sprintf("%d", combinedCounts[findings.Low]),
		"c_info":                fmt.Sprintf("%d", combinedCounts[findings.Info]),
		"owasp_section":         owaspSummaryHTML(combinedOWASP),
		"targets_section":       targetsSummaryHTML(allResults),
		"endpoints_section":     endpointsSection,
		"discarded_section":     "",
		"target_filter_buttons": targetFilterButtonsHTML(allTargets),
		"findings_html":         strings.Join(allFindingsHTML, "\n"),
	})

	if err := os.WriteFile(path, []byte(html), 0o644); err != nil {
		return err
	}
	logging.Printf("[+] Объединённый HTML-отчёт сохранён: %s", path)
	return nil
}
