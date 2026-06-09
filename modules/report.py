from __future__ import annotations
import json
import datetime
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from .findings import DiscardedCandidate, Severity, Finding, FindingStore, OWASP_FULL_NAMES, USE_COLOR

STATUS_LABELS = {
    "confirmed": "",
    "confirmed-deep-dive": "✓ Подтверждено доп. проверкой",
    "unverified": "⚠ Не подтверждено автоматически — требуется ручная проверка",
}

RESET = "\033[0m" if USE_COLOR else ""
BOLD  = "\033[1m" if USE_COLOR else ""
GREEN = "\033[32m" if USE_COLOR else ""


# ── Console output ─────────────────────────────────────────────────────────────

def print_findings(store: FindingStore, verbose: bool = False) -> None:
    findings = store.all()
    counts = store.counts()

    print("\n" + "=" * 70)
    print(f"{BOLD}  РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ{RESET}")
    print("=" * 70)
    print(
        f"  {Severity.CRITICAL.color}CRITICAL: {counts['CRITICAL']}{RESET}  "
        f"{Severity.HIGH.color}HIGH: {counts['HIGH']}{RESET}  "
        f"{Severity.MEDIUM.color}MEDIUM: {counts['MEDIUM']}{RESET}  "
        f"{Severity.LOW.color}LOW: {counts['LOW']}{RESET}  "
        f"{Severity.INFO.color}INFO: {counts['INFO']}{RESET}"
    )

    # OWASP summary
    owasp_counts = store.owasp_counts()
    if owasp_counts:
        print("\n  OWASP Top 10:")
        for oid, cnt in sorted(owasp_counts.items()):
            name = OWASP_FULL_NAMES.get(oid, "")
            print(f"    {oid} {name}: {cnt}")

    print("=" * 70 + "\n")

    for f in findings:
        if not verbose and f.severity == Severity.INFO:
            continue
        _print_finding(f)


def _print_finding(f: Finding) -> None:
    color = f.severity.color
    print(f"{color}{'─' * 70}{RESET}")
    owasp_id, owasp_name = f.owasp
    print(f"{color}{BOLD}[{f.severity.value}]{RESET} {BOLD}{f.title}{RESET}")
    print(f"  {color}ID:{RESET} {f.id}  |  {color}OWASP:{RESET} {owasp_id} {owasp_name}  |  {color}CWE:{RESET} {f.cwe or 'N/A'}")
    if f.target:
        print(f"  {color}Target:{RESET} {f.target}")
    print(f"  {color}URL:{RESET} {f.url}")
    if f.parameter:
        print(f"  {color}Parameter:{RESET} {f.parameter}")
    status_label = STATUS_LABELS.get(f.status, "")
    if status_label:
        print(f"  {color}Статус проверки:{RESET} {status_label} (confidence: {f.confidence:.2f})")
    print()
    print(f"  {BOLD}Описание:{RESET}")
    for line in f.description.split("\n"):
        print(f"    {line}")
    if f.evidence:
        print(f"\n  {BOLD}Доказательства:{RESET}")
        for line in f.evidence.split("\n"):
            print(f"    {line}")
    if f.verification_log:
        print(f"\n  {BOLD}Журнал доп. проверки:{RESET}")
        for line in f.verification_log:
            print(f"    - {line}")
    if f.artifacts:
        print(f"\n  {BOLD}Извлечённые артефакты:{RESET}")
        for a in f.artifacts:
            print(f"    - {a}")
    print(f"\n  {BOLD}Как воспроизвести:{RESET}")
    for line in f.reproduction.split("\n"):
        print(f"    {line}")
    print(f"\n  {BOLD}Рекомендации:{RESET}")
    for line in f.remediation.split("\n"):
        print(f"    {line}")
    print()


# ── JSON ───────────────────────────────────────────────────────────────────────

def save_json(store: FindingStore, path: Path, meta: dict) -> None:
    data = {
        "scan_meta": meta,
        "summary": store.counts(),
        "owasp_summary": store.owasp_counts(),
        "total": len(store),
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "owasp_id": f.owasp[0],
                "owasp_name": f.owasp[1],
                "category": f.category,
                "cwe": f.cwe,
                "target": f.target,
                "url": f.url,
                "parameter": f.parameter,
                "method": f.method,
                "description": f.description,
                "evidence": f.evidence,
                "reproduction": f.reproduction,
                "remediation": f.remediation,
                "status": f.status,
                "confidence": f.confidence,
                "verification_log": f.verification_log,
                "artifacts": f.artifacts,
            }
            for f in store.all()
        ],
        "discarded_candidates": [
            {"title": d.title, "kind": d.kind, "reason": d.reason}
            for d in store.discarded()
        ],
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] JSON-отчёт сохранён: {path}")


def save_combined_json(
    all_results: list[tuple[str, FindingStore, list, dict]],
    path: Path,
    global_meta: dict,
) -> None:
    """Save a combined JSON report for multi-target scans."""
    all_findings = []
    combined_counts: dict[str, int] = {s.value: 0 for s in Severity}
    combined_owasp: dict[str, int] = {}
    targets_summary = []

    for target_url, store, endpoints, meta in all_results:
        counts = store.counts()
        for k, v in counts.items():
            combined_counts[k] += v
        for oid, cnt in store.owasp_counts().items():
            combined_owasp[oid] = combined_owasp.get(oid, 0) + cnt
        targets_summary.append({
            "target": target_url,
            "findings": len(store),
            "counts": counts,
            "owasp": store.owasp_counts(),
            "duration_seconds": meta.get("duration_seconds"),
            "endpoints_discovered": len(endpoints),
        })
        for f in store.all():
            all_findings.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "owasp_id": f.owasp[0],
                "owasp_name": f.owasp[1],
                "category": f.category,
                "cwe": f.cwe,
                "target": f.target,
                "url": f.url,
                "parameter": f.parameter,
                "method": f.method,
                "description": f.description,
                "evidence": f.evidence,
                "reproduction": f.reproduction,
                "remediation": f.remediation,
                "status": f.status,
                "confidence": f.confidence,
                "verification_log": f.verification_log,
                "artifacts": f.artifacts,
            })

    data = {
        "scan_meta": global_meta,
        "targets_summary": targets_summary,
        "combined_counts": combined_counts,
        "combined_owasp": combined_owasp,
        "total": len(all_findings),
        "findings": sorted(all_findings, key=lambda x: {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}.get(x["severity"], 0), reverse=True),
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] Объединённый JSON-отчёт сохранён: {path}")


# ── HTML helpers ───────────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    return (s
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _owasp_summary_html(owasp_counts: dict[str, int]) -> str:
    if not owasp_counts:
        return ""
    cards = []
    for oid in sorted(owasp_counts):
        cnt = owasp_counts[oid]
        full = _esc(OWASP_FULL_NAMES.get(oid, ""))
        cards.append(
            f'<div class="owasp-card" data-owasp="{_esc(oid)}" onclick="filterOWASP(\'{_esc(oid)}\')">'
            f'<div class="owasp-id">{_esc(oid)}</div>'
            f'<div class="owasp-name">{full}</div>'
            f'<div class="owasp-count">{cnt}</div>'
            f'</div>'
        )
    return (
        '<div class="section-title">OWASP Top 10 — распределение находок '
        '<span style="font-size:0.75em;color:var(--text2)">(кликните для фильтра)</span></div>'
        f'<div class="owasp-grid">{"".join(cards)}</div>'
    )


def _targets_summary_html(all_results: list[tuple[str, FindingStore, list, dict]]) -> str:
    if len(all_results) <= 1:
        return ""
    rows = []
    for target_url, store, endpoints, meta in all_results:
        counts = store.counts()
        host = _esc(urlparse(target_url).netloc or target_url)
        full = _esc(target_url)
        crit = counts.get("CRITICAL", 0)
        high = counts.get("HIGH", 0)
        med  = counts.get("MEDIUM", 0)
        low  = counts.get("LOW", 0)
        rows.append(
            f'<tr class="target-row" onclick="filterTarget(\'{full}\')" style="cursor:pointer">'
            f'<td class="url-pill">{host}</td>'
            f'<td style="color:var(--c-critical)">{crit}</td>'
            f'<td style="color:var(--c-high)">{high}</td>'
            f'<td style="color:var(--c-medium)">{med}</td>'
            f'<td style="color:var(--c-low)">{low}</td>'
            f'<td>{len(endpoints)}</td>'
            f'</tr>'
        )
    return (
        '<div class="section-title">Цели сканирования</div>'
        '<div class="endpoints-section" style="overflow-x:auto">'
        '<table style="width:100%;border-collapse:collapse;font-size:0.9em">'
        '<thead><tr style="color:var(--text2);text-align:left">'
        '<th style="padding:6px 10px">Домен</th>'
        '<th style="padding:6px 10px;color:var(--c-critical)">CRIT</th>'
        '<th style="padding:6px 10px;color:var(--c-high)">HIGH</th>'
        '<th style="padding:6px 10px;color:var(--c-medium)">MED</th>'
        '<th style="padding:6px 10px;color:var(--c-low)">LOW</th>'
        '<th style="padding:6px 10px">Endpoints</th>'
        '</tr></thead>'
        f'<tbody>{"".join(rows)}</tbody>'
        '</table>'
        '</div>'
    )


def _target_filter_buttons_html(targets: list[str]) -> str:
    if len(targets) <= 1:
        return ""
    buttons = ['<button class="filter-btn all active" onclick="filterTarget(\'all\')">Все цели</button>']
    for t in targets:
        host = urlparse(t).netloc or t
        buttons.append(
            f'<button class="filter-btn" onclick="filterTarget(\'{_esc(t)}\')">{_esc(host)}</button>'
        )
    return (
        '<span style="color:var(--text2);font-size:0.85em;margin-left:16px">Цель:</span> '
        + " ".join(buttons)
    )


# ── HTML template ──────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pentest Report — {title}</title>
<style>
  :root {{
    --c-critical: #dc2626; --c-high: #ea580c; --c-medium: #d97706;
    --c-low: #2563eb; --c-info: #0891b2; --bg: #0f172a; --bg2: #1e293b;
    --bg3: #334155; --text: #e2e8f0; --text2: #94a3b8; --border: #475569;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
  .header {{ background: var(--bg2); border-radius: 12px; padding: 30px; margin-bottom: 24px; border-left: 5px solid #dc2626; }}
  .header h1 {{ font-size: 2em; color: #f8fafc; margin-bottom: 8px; }}
  .header .meta {{ color: var(--text2); font-size: 0.9em; }}
  .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; }}
  .sev-card {{ background: var(--bg2); border-radius: 10px; padding: 20px; text-align: center; border-top: 4px solid; }}
  .sev-card.critical {{ border-color: var(--c-critical); }} .sev-card.high {{ border-color: var(--c-high); }}
  .sev-card.medium {{ border-color: var(--c-medium); }} .sev-card.low {{ border-color: var(--c-low); }}
  .sev-card.info {{ border-color: var(--c-info); }}
  .sev-card .count {{ font-size: 2.5em; font-weight: 700; }}
  .sev-card .label {{ color: var(--text2); font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }}
  .critical .count {{ color: var(--c-critical); }} .high .count {{ color: var(--c-high); }}
  .medium .count {{ color: var(--c-medium); }} .low .count {{ color: var(--c-low); }}
  .info .count {{ color: var(--c-info); }}
  /* OWASP grid */
  .owasp-grid {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 24px; }}
  .owasp-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 10px;
    padding: 12px 16px; cursor: pointer; transition: border-color .2s; min-width: 160px; flex: 1; }}
  .owasp-card:hover, .owasp-card.active {{ border-color: #38bdf8; }}
  .owasp-id {{ font-size: 0.75em; font-weight: 700; color: #38bdf8; letter-spacing: 1px; }}
  .owasp-name {{ font-size: 0.8em; color: var(--text2); margin: 2px 0 6px; }}
  .owasp-count {{ font-size: 1.6em; font-weight: 700; color: var(--text); }}
  /* section */
  .section-title {{ font-size: 1.3em; font-weight: 600; color: var(--text2); text-transform: uppercase;
    letter-spacing: 1px; margin: 24px 0 12px; }}
  .finding {{ background: var(--bg2); border-radius: 10px; margin-bottom: 16px; overflow: hidden; border: 1px solid var(--border); }}
  .finding-header {{ padding: 16px 20px; display: flex; align-items: center; gap: 12px; cursor: pointer; user-select: none; }}
  .finding-header:hover {{ background: var(--bg3); }}
  .badge {{ padding: 3px 10px; border-radius: 20px; font-size: 0.75em; font-weight: 700; text-transform: uppercase; color: #fff; }}
  .badge.critical {{ background: var(--c-critical); }} .badge.high {{ background: var(--c-high); }}
  .badge.medium {{ background: var(--c-medium); }} .badge.low {{ background: var(--c-low); }}
  .badge.info {{ background: var(--c-info); }}
  .badge.owasp {{ background: #1e40af; font-size: 0.7em; }}
  .finding-title {{ font-weight: 600; flex: 1; }}
  .finding-meta {{ color: var(--text2); font-size: 0.8em; }}
  .finding-body {{ padding: 20px; border-top: 1px solid var(--border); display: none; }}
  .finding-body.open {{ display: block; }}
  .field-label {{ font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px; color: var(--text2); margin-top: 16px; margin-bottom: 4px; font-weight: 600; }}
  .field-value {{ color: var(--text); }}
  pre, code {{ background: #0f172a; border-radius: 6px; padding: 12px; overflow-x: auto;
    font-family: 'Fira Code', 'Cascadia Code', monospace; font-size: 0.85em; color: #a3e635;
    white-space: pre-wrap; word-break: break-all; border: 1px solid var(--border); }}
  .url-pill {{ display: inline-block; background: var(--bg3); border-radius: 4px; padding: 2px 8px;
    font-family: monospace; font-size: 0.85em; word-break: break-all; }}
  .filter-bar {{ background: var(--bg2); border-radius: 10px; padding: 16px 20px; margin-bottom: 16px;
    display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }}
  .filter-btn {{ padding: 6px 14px; border-radius: 20px; border: 2px solid var(--border); background: transparent;
    color: var(--text); cursor: pointer; font-size: 0.85em; transition: all 0.2s; }}
  .filter-btn:hover, .filter-btn.active {{ border-color: currentColor; background: rgba(255,255,255,.05); }}
  .filter-btn.critical {{ color: var(--c-critical); }} .filter-btn.high {{ color: var(--c-high); }}
  .filter-btn.medium {{ color: var(--c-medium); }} .filter-btn.low {{ color: var(--c-low); }}
  .filter-btn.info {{ color: var(--c-info); }} .filter-btn.all {{ color: var(--text); }}
  .endpoints-section {{ background: var(--bg2); border-radius: 10px; padding: 20px; margin-bottom: 16px; }}
  .endpoint-list {{ max-height: 300px; overflow-y: auto; }}
  .endpoint-item {{ padding: 6px 0; border-bottom: 1px solid var(--border); font-family: monospace; font-size: 0.85em; color: var(--text2); }}
  .endpoint-item .method {{ display: inline-block; width: 50px; color: #a3e635; font-weight: bold; }}
  .verify-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: 600; margin-top: 12px; }}
  .verify-badge.confirmed {{ background: rgba(34,197,94,0.15); color: #4ade80; border: 1px solid #4ade80; }}
  .verify-badge.unverified {{ background: rgba(217,119,6,0.15); color: #fbbf24; border: 1px solid #fbbf24; }}
  .verify-log {{ margin: 6px 0 0 18px; color: var(--text2); font-size: 0.85em; }}
  .verify-log li {{ margin-bottom: 4px; }}
  .artifact-list {{ list-style: none; margin-top: 4px; }}
  .artifact-list li {{ margin-bottom: 4px; }}
  .artifact-list a {{ color: #38bdf8; font-family: monospace; font-size: 0.85em; word-break: break-all; }}
  .discarded-section {{ background: var(--bg2); border-radius: 10px; margin-bottom: 16px; border: 1px solid var(--border); overflow: hidden; }}
  .discarded-header {{ padding: 14px 20px; cursor: pointer; user-select: none; color: var(--text2); font-weight: 600; }}
  .discarded-header:hover {{ background: var(--bg3); }}
  .discarded-body {{ padding: 0 20px 16px; display: none; }}
  .discarded-body.open {{ display: block; }}
  .discarded-item {{ padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 0.85em; }}
  .discarded-item .d-title {{ color: var(--text); font-weight: 600; }}
  .discarded-item .d-reason {{ color: var(--text2); }}
  .target-row:hover td {{ background: var(--bg3); }}
  .target-row td {{ padding: 8px 10px; border-bottom: 1px solid var(--border); }}
  @media (max-width: 768px) {{ .summary {{ grid-template-columns: repeat(3, 1fr); }} .owasp-grid {{ flex-direction: column; }} }}
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

function applyFilters() {{
  document.querySelectorAll('.finding').forEach(function(el) {{
    var sevOk    = activeSev    === 'all' || el.dataset.sev    === activeSev;
    var owaspOk  = activeOWASP  === 'all' || el.dataset.owasp  === activeOWASP;
    var targetOk = activeTarget === 'all' || el.dataset.target === activeTarget;
    el.style.display = (sevOk && owaspOk && targetOk) ? '' : 'none';
  }});
}}

function filterSev(sev) {{
  activeSev = sev;
  document.querySelectorAll('.filter-btn.critical,.filter-btn.high,.filter-btn.medium,.filter-btn.low,.filter-btn.info,.filter-btn.all').forEach(function(b) {{ b.classList.remove('active'); }});
  var sel = sev === 'all' ? '.filter-btn.all' : '.filter-btn.' + sev;
  var btn = document.querySelector(sel);
  if (btn) btn.classList.add('active');
  applyFilters();
}}

function filterOWASP(oid) {{
  if (activeOWASP === oid) {{ activeOWASP = 'all'; }} else {{ activeOWASP = oid; }}
  document.querySelectorAll('.owasp-card').forEach(function(c) {{ c.classList.remove('active'); }});
  if (activeOWASP !== 'all') {{
    var card = document.querySelector('[data-owasp="' + oid + '"]');
    if (card) card.classList.add('active');
  }}
  applyFilters();
}}

function filterTarget(t) {{
  activeTarget = t;
  document.querySelectorAll('.filter-btn').forEach(function(b) {{
    if (b.textContent === 'Все цели' && t === 'all') b.classList.add('active');
    else b.classList.remove('active');
  }});
  applyFilters();
}}

function toggleFinding(id) {{
  var body = document.getElementById('body-' + id);
  if (body) body.classList.toggle('open');
}}

function toggleDiscarded() {{
  var body = document.getElementById('discarded-body');
  if (body) body.classList.toggle('open');
}}
</script>
</body>
</html>
"""

FINDING_TEMPLATE = """
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
"""


# ── HTML save functions ────────────────────────────────────────────────────────

def _build_finding_html(f: Finding) -> str:
    param_block = (
        f'<div class="field-label">Параметр</div>'
        f'<div class="url-pill">{_esc(f.parameter)}</div>'
        if f.parameter else ""
    )

    verify_block = ""
    badge_label = STATUS_LABELS.get(f.status, "")
    if badge_label:
        badge_class = "confirmed" if f.status == "confirmed-deep-dive" else "unverified"
        verify_block = (
            f'<span class="verify-badge {badge_class}">'
            f'{_esc(badge_label)} (confidence: {f.confidence:.2f})</span>'
        )
        if f.verification_log:
            log_items = "\n".join(f"<li>{_esc(line)}</li>" for line in f.verification_log)
            verify_block += f'<ul class="verify-log">{log_items}</ul>'

    artifacts_block = ""
    if f.artifacts:
        links = "\n".join(
            f'<li><a href="{_esc(a)}" target="_blank">{_esc(a)}</a></li>'
            for a in f.artifacts
        )
        artifacts_block = (
            '<div class="field-label">Извлечённые артефакты</div>'
            f'<ul class="artifact-list">{links}</ul>'
        )

    owasp_id, owasp_name = f.owasp
    target_escaped = _esc(f.target)
    target_label = f" | {_esc(urlparse(f.target).netloc or f.target)}" if f.target else ""

    return FINDING_TEMPLATE.format(
        sev_lower=f.severity.value.lower(),
        sev=f.severity.value,
        fid=f.id,
        title=_esc(f.title),
        category=_esc(f.category),
        owasp_id=_esc(owasp_id),
        owasp_name=_esc(owasp_name),
        cwe=_esc(f.cwe or "N/A"),
        url=_esc(f.url),
        target_escaped=target_escaped,
        target_label=_esc(target_label),
        param_block=param_block,
        description=_esc(f.description).replace("\n", "<br>"),
        evidence=_esc(f.evidence or "—"),
        verify_block=verify_block,
        artifacts_block=artifacts_block,
        reproduction=_esc(f.reproduction or "—"),
        remediation=_esc(f.remediation).replace("\n", "<br>"),
    )


def save_html(store: FindingStore, path: Path, meta: dict, endpoints: list) -> None:
    counts = store.counts()
    owasp_counts = store.owasp_counts()

    findings_html = "\n".join(_build_finding_html(f) for f in store.all())

    endpoints_section = ""
    if endpoints:
        items = "\n".join(
            f'<div class="endpoint-item"><span class="method">{_esc(ep.method)}</span> {_esc(ep.url)}</div>'
            for ep in endpoints[:200]
        )
        endpoints_section = (
            f'<div class="section-title">Обнаруженные эндпоинты ({len(endpoints)})</div>'
            f'<div class="endpoints-section"><div class="endpoint-list">{items}</div></div>'
        )

    discarded = store.discarded()
    discarded_section = ""
    if discarded:
        items = "\n".join(
            f'<div class="discarded-item"><div class="d-title">[{_esc(d.kind)}] {_esc(d.title)}</div>'
            f'<div class="d-reason">{_esc(d.reason)}</div></div>'
            for d in discarded
        )
        discarded_section = (
            f'<div class="discarded-section">'
            f'<div class="discarded-header" onclick="toggleDiscarded()">'
            f'▾ Отброшено автоматической проверкой ({len(discarded)}) — '
            f'кандидаты, не подтвердившиеся при углублённой проверке</div>'
            f'<div class="discarded-body" id="discarded-body">{items}</div>'
            f'</div>'
        )

    target = meta.get("target", "")
    html = HTML_TEMPLATE.format(
        title=_esc(urlparse(target).netloc or target),
        header_target=_esc(target),
        date=meta.get("date", ""),
        total=len(store),
        c_critical=counts["CRITICAL"],
        c_high=counts["HIGH"],
        c_medium=counts["MEDIUM"],
        c_low=counts["LOW"],
        c_info=counts["INFO"],
        owasp_section=_owasp_summary_html(owasp_counts),
        targets_section="",
        endpoints_section=endpoints_section,
        discarded_section=discarded_section,
        target_filter_buttons="",
        findings_html=findings_html,
    )

    path.write_text(html, encoding="utf-8")
    print(f"[+] HTML-отчёт сохранён: {path}")


def save_combined_html(
    all_results: list[tuple[str, FindingStore, list, dict]],
    path: Path,
    global_meta: dict,
) -> None:
    """Save a single combined HTML report for multi-target scans."""
    # Build a merged store view (findings already tagged with .target)
    combined_counts: dict[str, int] = {s.value: 0 for s in Severity}
    combined_owasp: dict[str, int] = {}
    all_findings_html: list[str] = []
    all_endpoints: list = []
    all_targets: list[str] = []

    for target_url, store, endpoints, meta in all_results:
        all_targets.append(target_url)
        all_endpoints.extend(endpoints[:50])  # cap per-target contribution
        for k, v in store.counts().items():
            combined_counts[k] += v
        for oid, cnt in store.owasp_counts().items():
            combined_owasp[oid] = combined_owasp.get(oid, 0) + cnt
        for f in store.all():
            all_findings_html.append(_build_finding_html(f))

    targets_section = _targets_summary_html(all_results)
    owasp_section = _owasp_summary_html(combined_owasp)
    target_buttons = _target_filter_buttons_html(all_targets)

    # Endpoints section (merged, capped)
    endpoints_section = ""
    if all_endpoints:
        items = "\n".join(
            f'<div class="endpoint-item"><span class="method">{_esc(ep.method)}</span> {_esc(ep.url)}</div>'
            for ep in all_endpoints[:300]
        )
        endpoints_section = (
            f'<div class="section-title">Обнаруженные эндпоинты (всего ≈{len(all_endpoints)})</div>'
            f'<div class="endpoints-section"><div class="endpoint-list">{items}</div></div>'
        )

    title_str = f"{len(all_results)} целей"
    html = HTML_TEMPLATE.format(
        title=_esc(title_str),
        header_target=_esc(f"{len(all_results)} доменов: " + ", ".join(
            urlparse(t).netloc or t for t in all_targets[:5]
        ) + (" ..." if len(all_targets) > 5 else "")),
        date=global_meta.get("date", ""),
        total=sum(combined_counts.values()),
        c_critical=combined_counts["CRITICAL"],
        c_high=combined_counts["HIGH"],
        c_medium=combined_counts["MEDIUM"],
        c_low=combined_counts["LOW"],
        c_info=combined_counts["INFO"],
        owasp_section=owasp_section,
        targets_section=targets_section,
        endpoints_section=endpoints_section,
        discarded_section="",
        target_filter_buttons=target_buttons,
        findings_html="\n".join(all_findings_html),
    )

    path.write_text(html, encoding="utf-8")
    print(f"[+] Объединённый HTML-отчёт сохранён: {path}")
