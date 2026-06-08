"""Adaptive confirmation engine.

Check modules can flag a *weak* signal (single regex match, response-size delta,
status-code change, ...) as a `Candidate` instead of publishing it directly.
`run_confirmation_pass` then digs into each candidate with a class-specific
follow-up probe and decides whether to confirm it (with extra evidence and,
where useful, dumped artifacts), discard it as a false positive, or — if the
target stops cooperating — pass it through as "unverified" with a hedged
severity so a human still sees it.
"""
from __future__ import annotations
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import requests

from . import tools
from .findings import DiscardedCandidate, Finding, FindingStore, Severity


# ── Outcomes & data structures ────────────────────────────────────────────────

class Outcome:
    CONFIRMED = "confirmed"
    DISCARDED = "discarded"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Verdict:
    outcome: str
    extra_evidence: str = ""
    artifacts: list[tuple[str, str]] = field(default_factory=list)   # (filename, text content)
    new_severity: Optional[Severity] = None
    reason: str = ""   # shown in console / discarded-appendix / verification_log


@dataclass
class Candidate:
    """A weak-signal detection awaiting confirmation.

    `kind` selects the verifier from VERIFIERS; `context` carries whatever the
    check module captured to make follow-up probes possible (saved responses,
    a `probe(...)` callable to replay requests with different payloads, etc).
    """
    finding: Finding
    kind: str
    context: dict = field(default_factory=dict)


_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _downgrade(sev: Severity) -> Severity:
    idx = _SEVERITY_ORDER.index(sev)
    return _SEVERITY_ORDER[max(0, idx - 1)]


# ── Artifact dumping ──────────────────────────────────────────────────────────

def _dump_artifact(artifact_root: Path, finding_id: str, filename: str, content: str) -> str:
    target_dir = artifact_root / finding_id
    target_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^\w.\-]", "_", filename)[:120] or "artifact.txt"
    path = target_dir / safe_name
    path.write_text(content, encoding="utf-8", errors="replace")
    # Relative to the report directory (artifact_root's parent) so HTML <a href> links resolve.
    return str(path.relative_to(artifact_root.parent)).replace("\\", "/")


# ── Secret-signature scanning (used by the disclosure verifier) ──────────────

SECRET_SIGNATURES: list[tuple[str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Приватный ключ"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT"),
    (r"(?im)^\s*(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|API_KEY|AWS_SECRET_ACCESS_KEY)\s*=\s*\S+", "Секрет в .env-стиле конфига"),
    (r"(?i)mysql://[^\s\"']+|postgres(?:ql)?://[^\s\"']+|mongodb(?:\+srv)?://[^\s\"']+", "Строка подключения к БД"),
    (r"(?m)^ref:\s*refs/", "Git HEAD ref"),
    (r"\[core\]|\[remote \"origin\"\]", "Git config секция"),
]


def _scan_for_secrets(text: str) -> list[tuple[str, str, str]]:
    """Returns [(label, pattern, matched_snippet), ...] for every signature found."""
    hits = []
    for pattern, label in SECRET_SIGNATURES:
        m = re.search(pattern, text)
        if m:
            hits.append((label, pattern, m.group(0)[:200]))
    return hits


# ── Generated nuclei templates (used to map the blast radius of a confirmed
#    disclosure finding in a single follow-up run) ───────────────────────────

SIBLING_PROBES: dict[str, list[dict]] = {
    "/.git/config": [
        {"path": "/.git/HEAD", "matcher_type": "regex",
         "values": [r"^ref:\\s*refs/"], "label": "git-head-ref"},
        {"path": "/.git/index", "matcher_type": "word",
         "values": ["DIRC"], "label": "git-index-signature"},
        {"path": "/.git/logs/HEAD", "matcher_type": "regex",
         "values": [r"^[0-9a-f]{40}\\s"], "label": "git-reflog-entry"},
    ],
    "/.env": [
        {"path": "/.env.local", "matcher_type": "regex",
         "values": [r"(?i)(DB_PASSWORD|SECRET_KEY|API_KEY)\\s*="], "label": "env-local-secret"},
        {"path": "/.env.production", "matcher_type": "regex",
         "values": [r"(?i)(DB_PASSWORD|SECRET_KEY|API_KEY)\\s*="], "label": "env-production-secret"},
        {"path": "/config/.env", "matcher_type": "regex",
         "values": [r"(?i)(DB_PASSWORD|SECRET_KEY|API_KEY)\\s*="], "label": "config-env-secret"},
    ],
}


def _build_nuclei_template(template_id: str, name: str, probes: list[dict]) -> str:
    blocks = []
    for p in probes:
        matcher_key = "regex" if p["matcher_type"] == "regex" else "words"
        values_yaml = "\n".join(f'          - "{v}"' for v in p["values"])
        blocks.append(
            "  - method: GET\n"
            f"    path:\n"
            f"      - \"{{{{BaseURL}}}}{p['path']}\"\n"
            f"    matchers:\n"
            f"      - type: {p['matcher_type']}\n"
            f"        part: body\n"
            f"        {matcher_key}:\n"
            f"{values_yaml}\n"
            f"        name: \"{p['label']}\"\n"
        )
    return (
        f"id: {template_id}\n"
        "info:\n"
        f"  name: \"{name}\"\n"
        "  author: vectrixsecwave-adaptive\n"
        "  severity: info\n"
        "http:\n" + "\n".join(blocks)
    )


# ── Per-class verifiers ───────────────────────────────────────────────────────
# Every verifier has the signature (session, base_url, candidate, artifact_root, deep_dive) -> Verdict
# even when it doesn't need every argument, so the dispatch table stays uniform.

_IDENTITY_RE = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    r'|"(?:username|user_?name|login|full_?name|email|name)"\s*:\s*"([^"]{2,60})"',
    re.IGNORECASE,
)


def _identity_tokens(text: str) -> set[str]:
    tokens = set()
    for m in _IDENTITY_RE.finditer(text):
        tokens.add(m.group(1) if m.group(1) else m.group(0))
    return tokens


def _verify_idor(session, base_url, candidate, artifact_root, deep_dive):
    ctx = candidate.context
    original_resp = ctx.get("original_resp")
    probe_resp = ctx.get("probe_resp")
    if original_resp is None or probe_resp is None:
        return Verdict(Outcome.INCONCLUSIVE, reason="нет сохранённых ответов для повторного анализа")

    original_tokens = _identity_tokens(original_resp.text)
    probe_tokens = _identity_tokens(probe_resp.text)

    if not original_tokens or not probe_tokens:
        return Verdict(
            Outcome.INCONCLUSIVE,
            reason=("в ответах не найдено идентифицирующих полей (email/username/...) "
                    "для автоматического сравнения — нужна ручная проверка"),
        )

    if original_tokens != probe_tokens:
        return Verdict(
            Outcome.CONFIRMED,
            extra_evidence=(
                "Повторный анализ содержимого подтвердил, что это разные объекты:\n"
                f"  Идентификаторы в оригинале: {', '.join(sorted(original_tokens))[:200]}\n"
                f"  Идентификаторы в зонде:     {', '.join(sorted(probe_tokens))[:200]}\n"
                "Содержимое отличается не только по объёму, но и по фактическим данным "
                "— похоже на доступ к чужому объекту."
            ),
        )

    return Verdict(
        Outcome.DISCARDED,
        reason=("идентифицирующие поля в обоих ответах совпадают — вероятно, тот же объект "
                "или одна и та же шаблонная страница"),
    )


def _verify_injection(session, base_url, candidate, artifact_root, deep_dive):
    ctx = candidate.context
    probe: Optional[Callable[[str], Optional[requests.Response]]] = ctx.get("probe")
    if probe is None:
        return Verdict(Outcome.INCONCLUSIVE, reason="нет функции для повторной отправки payload'ов")

    marker = uuid.uuid4().hex[:6]
    true_payload = f"' OR '{marker}'='{marker}' -- -"
    false_payload = f"' AND '{marker}'='{marker}_no_match' -- -"

    try:
        true_resp = probe(true_payload)
        false_resp = probe(false_payload)
    except Exception as e:
        return Verdict(Outcome.INCONCLUSIVE, reason=f"ошибка при повторной отправке payload'ов: {e}")
    if true_resp is None or false_resp is None:
        return Verdict(Outcome.INCONCLUSIVE, reason="сервер не ответил на повторные запросы")

    true_len, false_len = len(true_resp.text), len(false_resp.text)
    same_status = true_resp.status_code == false_resp.status_code
    similar_len = false_len == 0 or abs(true_len - false_len) / max(false_len, 1) < 0.03

    if same_status and similar_len:
        return Verdict(
            Outcome.DISCARDED,
            reason=(f"TRUE- и FALSE-условие дали неразличимые ответы "
                    f"(status {true_resp.status_code}=={false_resp.status_code}, "
                    f"длина {true_len}≈{false_len}) — похоже на статичную страницу ошибки, "
                    "а не на реальную инъекцию"),
        )

    return Verdict(
        Outcome.CONFIRMED,
        extra_evidence=(
            "Дифференциальная boolean-проверка подтвердила инъекцию:\n"
            f"  TRUE-условие  ({true_payload}): HTTP {true_resp.status_code}, {true_len} байт\n"
            f"  FALSE-условие ({false_payload}): HTTP {false_resp.status_code}, {false_len} байт\n"
            "Ответы заметно различаются — сервер по-разному обрабатывает true/false условия "
            "внутри SQL-запроса."
        ),
    )


def _verify_ssrf(session, base_url, candidate, artifact_root, deep_dive):
    ctx = candidate.context
    probe: Optional[Callable[[str], Optional[requests.Response]]] = ctx.get("probe")
    payload = ctx.get("payload", "")
    if probe is None:
        return Verdict(Outcome.INCONCLUSIVE, reason="нет функции для повторной отправки SSRF-payload'ов")

    control_payload = "http://127.0.0.1:1/__vsw_unlikely_port__"
    try:
        resp_a = probe(payload)
        resp_b = probe(control_payload)
    except Exception as e:
        return Verdict(Outcome.INCONCLUSIVE, reason=f"ошибка при повторных запросах: {e}")
    if resp_a is None or resp_b is None:
        return Verdict(Outcome.INCONCLUSIVE, reason="сервер не ответил на повторные запросы")

    len_a, len_b = len(resp_a.text), len(resp_b.text)
    same_status = resp_a.status_code == resp_b.status_code
    similar_len = len_b == 0 or abs(len_a - len_b) / max(len_b, 1) < 0.05

    if same_status and similar_len:
        return Verdict(
            Outcome.DISCARDED,
            reason=(f"ответ на исходный payload неотличим от ответа на заведомо нерабочий адрес "
                    f"(status {resp_a.status_code}=={resp_b.status_code}, длина {len_a}≈{len_b}) "
                    "— сервер, видимо, не делает запрос по адресу из параметра"),
        )

    return Verdict(
        Outcome.CONFIRMED,
        extra_evidence=(
            "Дифференциальная проверка: ответ на исходный SSRF-payload заметно отличается "
            f"от ответа на заведомо недостижимый адрес ({control_payload}):\n"
            f"  Payload:  HTTP {resp_a.status_code}, {len_a} байт\n"
            f"  Контроль: HTTP {resp_b.status_code}, {len_b} байт\n"
            "Сервер по-разному обрабатывает разные адреса назначения — похоже на реальный "
            "исходящий запрос с сервера."
        ),
    )


_ADMIN_MARKERS = re.compile(
    r'(панель\s+администратора|admin\s*panel|dashboard|logout|выйти из|welcome,?\s*admin'
    r'|"role"\s*:\s*"admin"|"is_admin"\s*:\s*true)',
    re.IGNORECASE,
)


def _verify_auth_bypass(session, base_url, candidate, artifact_root, deep_dive):
    ctx = candidate.context
    probe: Optional[Callable[[], Optional[requests.Response]]] = ctx.get("probe")
    baseline_resp = ctx.get("baseline_resp")
    header = ctx.get("header", "")
    value = ctx.get("value", "")
    if probe is None or baseline_resp is None:
        return Verdict(Outcome.INCONCLUSIVE, reason="нет сохранённого контекста для повторной проверки")

    try:
        resp = probe()
    except Exception as e:
        return Verdict(Outcome.INCONCLUSIVE, reason=f"повторный запрос с заголовком не удался: {e}")
    if resp is None:
        return Verdict(Outcome.INCONCLUSIVE, reason="сервер не ответил на повторный запрос")

    baseline_markers = set(_ADMIN_MARKERS.findall(baseline_resp.text))
    bypass_markers = set(_ADMIN_MARKERS.findall(resp.text))
    new_markers = bypass_markers - baseline_markers

    if resp.status_code == 200 and new_markers:
        return Verdict(
            Outcome.CONFIRMED,
            extra_evidence=(
                f"Повторная проверка с заголовком '{header}: {value}':\n"
                f"HTTP {resp.status_code}, обнаружены admin-специфичные маркеры, "
                f"отсутствующие в базовом (без заголовка) ответе: {', '.join(sorted(new_markers))[:300]}"
            ),
        )

    return Verdict(
        Outcome.DISCARDED,
        reason=("ответ отличается по размеру, но не содержит admin-специфичных маркеров "
                "(нет признаков попадания на защищённую страницу) — вероятно, просто другая "
                "страница того же роутинга, не реальный обход авторизации"),
    )


def _verify_disclosure(session, base_url, candidate, artifact_root, deep_dive):
    finding = candidate.finding
    ctx = candidate.context
    path = ctx.get("path", "")
    url = ctx.get("url") or (base_url.rstrip("/") + path)

    try:
        resp = session.get(url, params={"_vsw": uuid.uuid4().hex[:8]}, timeout=10, allow_redirects=True)
    except Exception as e:
        return Verdict(Outcome.INCONCLUSIVE, reason=f"повторный запрос не удался: {e}")

    hits = _scan_for_secrets(resp.text)
    if not hits:
        return Verdict(
            Outcome.DISCARDED,
            reason=("содержимое отличается от baseline, но не содержит распознаваемых сигнатур "
                    "секретов/исходного кода — вероятно, не настоящая утечка, а просто иной шаблон "
                    "ответа (страница ошибки, листинг и т.п.)"),
        )

    evidence_lines = [f"Повторный запрос к '{path}' (с anti-cache параметром) подтвердил содержимое:"]
    artifacts = []
    for hit_label, pattern, snippet in hits:
        evidence_lines.append(f"  - {hit_label}: {snippet}")
        artifact_name = re.sub(r"[^A-Za-z0-9]+", "_", hit_label).strip("_") + ".txt"
        artifacts.append((
            artifact_name,
            f"URL: {url}\nСигнатура: {hit_label}\nPattern: {pattern}\n\n--- Фрагмент ответа (4000 байт) ---\n{resp.text[:4000]}",
        ))

    extra_evidence = "\n".join(evidence_lines)

    if deep_dive:
        siblings = SIBLING_PROBES.get(path)
        if siblings:
            template_yaml = _build_nuclei_template(
                f"adaptive-{finding.id}", f"Adaptive follow-up for {path}", siblings,
            )
            matches = tools.run_custom_nuclei_template(session, base_url, template_yaml, label=path)
            if matches:
                lines = [f"Сгенерированный nuclei-шаблон нашёл {len(matches)} связанных совпадений "
                         "(карта соседних утечек по той же сигнатуре):"]
                for m in matches[:8]:
                    matcher_name = m.get("matcher-name") or m.get("info", {}).get("name", "")
                    matched_at = m.get("matched-at", "")
                    lines.append(f"  - {matcher_name}: {matched_at}")
                extra_evidence += "\n\n" + "\n".join(lines)

    return Verdict(Outcome.CONFIRMED, extra_evidence=extra_evidence, artifacts=artifacts,
                   new_severity=Severity.CRITICAL)


VERIFIERS: dict[str, Callable[..., Verdict]] = {
    "idor": _verify_idor,
    "sqli": _verify_injection,
    "ssrf": _verify_ssrf,
    "auth_bypass": _verify_auth_bypass,
    "disclosure": _verify_disclosure,
}


# ── The confirmation pass ─────────────────────────────────────────────────────

def run_confirmation_pass(session: requests.Session, base_url: str, store: FindingStore,
                          artifact_root: Path, deep_dive: bool = True, verbose: bool = False) -> None:
    candidates = store.pop_candidates()
    if not candidates:
        return

    print(f"[*] Адаптивная проверка: {len(candidates)} кандидат(ов) на углублённый анализ...")

    for candidate in candidates:
        finding = candidate.finding
        verifier = VERIFIERS.get(candidate.kind)

        if verifier is None:
            verdict = Verdict(Outcome.INCONCLUSIVE, reason=f"нет верификатора для типа '{candidate.kind}'")
        else:
            try:
                verdict = verifier(session, base_url, candidate, artifact_root, deep_dive)
            except Exception as e:
                verdict = Verdict(Outcome.INCONCLUSIVE, reason=f"верификация завершилась с ошибкой: {e}")

        if verdict.outcome == Outcome.CONFIRMED:
            finding.status = "confirmed-deep-dive"
            finding.confidence = max(finding.confidence, 0.85)
            if verdict.new_severity is not None:
                finding.severity = verdict.new_severity
            if verdict.extra_evidence:
                finding.evidence = (
                    (finding.evidence + "\n\n" if finding.evidence else "")
                    + f"[Подтверждено доп. проверкой]\n{verdict.extra_evidence}"
                )
            finding.verification_log.append(
                f"CONFIRMED ({candidate.kind}): углублённая проверка подтвердила находку"
            )
            for filename, content in verdict.artifacts:
                rel_path = _dump_artifact(artifact_root, finding.id, filename, content)
                finding.artifacts.append(rel_path)
            store.add(finding)
            print(f"  [+] CONFIRMED: {finding.title}")

        elif verdict.outcome == Outcome.DISCARDED:
            store.add_discarded(DiscardedCandidate(title=finding.title, kind=candidate.kind, reason=verdict.reason))
            if verbose:
                print(f"  [-] DISCARDED: {finding.title} — {verdict.reason}")

        else:  # INCONCLUSIVE
            finding.status = "unverified"
            finding.confidence = min(finding.confidence, 0.5)
            finding.severity = _downgrade(finding.severity)
            finding.verification_log.append(f"UNVERIFIED ({candidate.kind}): {verdict.reason}")
            store.add(finding)
            if verbose:
                print(f"  [?] UNVERIFIED: {finding.title} — {verdict.reason}")

    confirmed = sum(1 for f in store.all() if f.status == "confirmed-deep-dive")
    unverified = sum(1 for f in store.all() if f.status == "unverified")
    print(f"[+] Адаптивная проверка завершена: "
          f"подтверждено — {confirmed}, отброшено — {len(store.discarded())}, "
          f"требуют ручной проверки — {unverified}")
