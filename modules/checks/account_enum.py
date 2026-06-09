"""Account enumeration checks.

Compares server responses (status code, body size, error message, timing)
between requests with known/likely usernames and clearly non-existent ones
across login, registration, and password reset endpoints.
"""
from __future__ import annotations
import re
import time
import requests

from ..findings import Finding, Severity
from ..session import session_to_curl_flags

# Clearly non-existent sentinel username
FAKE_USER = "vectrix_nosuchuser_97zq"
FAKE_EMAIL = f"{FAKE_USER}@vectrix-probe-no-reply.invalid"

# Usernames that often exist on real apps
CANDIDATE_USERS = ["admin", "administrator", "user", "test", "support", "info"]

LOGIN_PATHS = [
    "/login", "/signin", "/api/login", "/api/signin",
    "/api/auth/login", "/api/auth/token", "/api/token",
    "/api/v1/login", "/api/v2/login", "/api/v1/auth/login",
    "/auth/local", "/auth/login",
]
REGISTER_PATHS = [
    "/register", "/signup", "/api/register", "/api/signup",
    "/api/v1/register", "/api/v2/register", "/api/users",
    "/api/v1/users",
]
RESET_PATHS = [
    "/forgot-password", "/forgot_password", "/password/reset",
    "/password-reset", "/api/password/reset", "/api/auth/forgot",
    "/api/v1/auth/password/forgot", "/api/auth/password",
    "/reset-password", "/account/forgot",
]

SIZE_DIFF_THRESHOLD = 0.12   # 12% body size difference → suspicious
TIMING_DIFF_SEC     = 0.4    # 400ms difference → suspicious

# Patterns that reveal account existence
ACCOUNT_EXISTS_PATTERNS = re.compile(
    r"already (registered|taken|exists|in use)|"
    r"email.{0,20}already|"
    r"(username|account|user).{0,20}already|"
    r"is taken|address is already",
    re.IGNORECASE,
)
ACCOUNT_NOT_FOUND_PATTERNS = re.compile(
    r"(user(name)?|email|account).{0,30}(not found|doesn.?t? exist|not registered|invalid)|"
    r"no account.{0,20}(with|found|for).{0,20}email|"
    r"we couldn.?t find|"
    r"incorrect (username|email)|"
    r"(invalid|unknown) (user|email|username|account)",
    re.IGNORECASE,
)


# ── Main entry ────────────────────────────────────────────────────────────────

def run(session: requests.Session, base_url: str, endpoints: list, store) -> None:
    print("[*] Checking account enumeration...")
    curl_auth = session_to_curl_flags(session)
    timeout = getattr(session, 'timeout', 15)

    for url in _collect(base_url, endpoints, LOGIN_PATHS)[:4]:
        _check_login(session, url, curl_auth, timeout, store)

    for url in _collect(base_url, endpoints, REGISTER_PATHS)[:3]:
        _check_register(session, url, curl_auth, timeout, store)

    for url in _collect(base_url, endpoints, RESET_PATHS)[:3]:
        _check_reset(session, url, curl_auth, timeout, store)


# ── Per-endpoint checks ───────────────────────────────────────────────────────

def _check_login(session, url, curl_auth, timeout, store):
    """Compare login response for known-candidate vs clearly-fake username."""
    results = []
    for username in [CANDIDATE_USERS[0], FAKE_USER]:
        r = _post_timed(session, url, [
            {"username": username, "password": "VectrixWrong!999"},
            {"email": f"{username}@example.com", "password": "VectrixWrong!999"},
            {"login": username, "password": "VectrixWrong!999"},
        ], timeout)
        if r:
            results.append((username, *r))

    if len(results) < 2:
        return

    known_status, known_size, known_body, known_time = results[0][1:]
    fake_status,  fake_size,  fake_body,  fake_time  = results[1][1:]

    if _report_if_different(
        url, curl_auth, store,
        "login",
        known_status, known_size, known_body, known_time,
        fake_status,  fake_size,  fake_body,  fake_time,
    ):
        return

    # Explicit "invalid username" message absent for fake user but different for known
    if (ACCOUNT_NOT_FOUND_PATTERNS.search(fake_body) and
            not ACCOUNT_NOT_FOUND_PATTERNS.search(known_body)):
        m = ACCOUNT_NOT_FOUND_PATTERNS.search(fake_body)
        _add_finding(store, url, curl_auth, "Login — error message",
                     f"Для несуществующего пользователя: «{m.group()[:100]}»")


def _check_register(session, url, curl_auth, timeout, store):
    """Compare registration response for taken vs fresh email."""
    taken_email   = f"admin@example.com"
    fresh_email   = FAKE_EMAIL

    results = []
    for email in [taken_email, fresh_email]:
        r = _post_timed(session, url, [
            {"email": email, "username": email.split("@")[0], "password": "Test@Vectrix99"},
            {"email": email, "password": "Test@Vectrix99"},
        ], timeout)
        if r:
            results.append((email, *r))

    if len(results) < 2:
        return

    taken_status, taken_size, taken_body, _ = results[0][1:]
    fresh_status, fresh_size, fresh_body, _ = results[1][1:]

    # Status differs → direct leak
    if taken_status != fresh_status and taken_status not in (404, 500):
        _add_finding(store, url, curl_auth, "Registration — HTTP status",
                     f"Существующий email: HTTP {taken_status}, "
                     f"Новый email: HTTP {fresh_status}")
        return

    # "Already taken" message only for existing email
    if (ACCOUNT_EXISTS_PATTERNS.search(taken_body) and
            not ACCOUNT_EXISTS_PATTERNS.search(fresh_body)):
        m = ACCOUNT_EXISTS_PATTERNS.search(taken_body)
        _add_finding(store, url, curl_auth, "Registration — error message",
                     f"«{m.group()[:100]}» только для существующего аккаунта")


def _check_reset(session, url, curl_auth, timeout, store):
    """Check if password reset reveals whether email is registered."""
    results = []
    for email in ["admin@example.com", FAKE_EMAIL]:
        r = _post_timed(session, url, [
            {"email": email},
            {"username": email},
            {"email": email, "g-recaptcha-response": ""},  # common field
        ], timeout)
        if r:
            results.append((email, *r))

    if len(results) < 2:
        return

    real_status, real_size, real_body, real_time = results[0][1:]
    fake_status, fake_size, fake_body, fake_time = results[1][1:]

    _report_if_different(
        url, curl_auth, store,
        "password reset",
        real_status, real_size, real_body, real_time,
        fake_status, fake_size, fake_body, fake_time,
    )

    if (ACCOUNT_NOT_FOUND_PATTERNS.search(fake_body) and
            not ACCOUNT_NOT_FOUND_PATTERNS.search(real_body)):
        m = ACCOUNT_NOT_FOUND_PATTERNS.search(fake_body)
        _add_finding(store, url, curl_auth, "Password reset — error message",
                     f"Сброс пароля раскрывает отсутствие аккаунта: «{m.group()[:100]}»")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _post_timed(session, url, payloads_to_try, timeout):
    """Try each payload dict; return (status, body_size, body[:500], elapsed) on first 200-499."""
    for payload in payloads_to_try:
        try:
            t0 = time.monotonic()
            r = session.post(url, json=payload, timeout=timeout, allow_redirects=False)
            elapsed = time.monotonic() - t0
            if r.status_code not in (404, 405, 501):
                return r.status_code, len(r.text), r.text[:600], elapsed
        except Exception:
            continue
    return None


def _report_if_different(url, curl_auth, store, kind,
                          a_status, a_size, a_body, a_time,
                          b_status, b_size, b_body, b_time) -> bool:
    # Status code
    if a_status != b_status and b_status not in (404, 500):
        _add_finding(store, url, curl_auth, f"{kind.title()} — HTTP status",
                     f"Существующий: HTTP {a_status} | Несуществующий: HTTP {b_status}")
        return True

    # Body size
    max_size = max(a_size, b_size, 1)
    if abs(a_size - b_size) / max_size > SIZE_DIFF_THRESHOLD and max_size > 50:
        _add_finding(store, url, curl_auth, f"{kind.title()} — размер ответа",
                     f"Существующий: {a_size} байт | Несуществующий: {b_size} байт "
                     f"({abs(a_size-b_size)/max_size*100:.0f}% разница)")
        return True

    # Timing
    if abs(a_time - b_time) > TIMING_DIFF_SEC:
        _add_finding(store, url, curl_auth, f"{kind.title()} — время ответа (timing attack)",
                     f"Существующий: {a_time:.2f}с | Несуществующий: {b_time:.2f}с "
                     f"(Δ {abs(a_time-b_time):.2f}с)")
        return True

    return False


def _add_finding(store, url, curl_auth, method, evidence):
    store.add(Finding(
        title=f"Перебор аккаунтов ({method})",
        severity=Severity.MEDIUM,
        category="Authentication",
        cwe="CWE-204",
        description=(
            f"Endpoint {url} возвращает различные ответы для существующих "
            f"и несуществующих аккаунтов.\n"
            f"Метод обнаружения: {method}\n\n"
            "Атакующий может составить список зарегистрированных email/username методом перебора, "
            "что упрощает последующие атаки (credential stuffing, spear phishing, brute force)."
        ),
        url=url,
        method="POST",
        evidence=evidence,
        remediation=(
            "1. Всегда возвращайте одинаковые ответы (тело, статус, время) для "
            "   существующих и несуществующих аккаунтов.\n"
            "2. Для reset: «Если этот email зарегистрирован, вы получите письмо» — "
            "   без указания факта существования.\n"
            "3. Применяйте constant-time операции при поиске пользователя, "
            "   чтобы устранить timing-атаку.\n"
            "4. После N неудачных попыток — CAPTCHA или временная блокировка IP."
        ),
        reproduction=(
            f"# Сравните ответы:\n"
            f"curl -sk {curl_auth} -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"email\":\"admin@example.com\",\"password\":\"wrong\"}}' '{url}'\n"
            f"curl -sk {curl_auth} -X POST -H 'Content-Type: application/json' "
            f"-d '{{\"email\":\"{FAKE_EMAIL}\",\"password\":\"wrong\"}}' '{url}'"
        ),
    ))
