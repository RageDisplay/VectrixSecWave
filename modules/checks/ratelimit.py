from __future__ import annotations
import time
from urllib.parse import urljoin
import requests

from ..findings import Finding, Severity
from ..session import session_to_curl_flags


LOGIN_PATHS = [
    "/login", "/api/login", "/auth/login", "/signin", "/api/signin",
    "/api/v1/login", "/api/v2/login", "/api/auth", "/api/token",
    "/api/auth/token", "/user/login", "/users/login",
    "/authenticate", "/api/authenticate",
]

RATE_LIMIT_INDICATORS = [
    "rate limit", "too many requests", "try again", "throttle",
    "quota exceeded", "limit exceeded", "slow down", "429",
]


def run(session: requests.Session, base_url: str, endpoints: list, store) -> None:
    print("[*] Checking rate limiting...")
    curl_auth = session_to_curl_flags(session)
    timeout = getattr(session, 'timeout', 15)

    _check_login_rate_limit(session, base_url, curl_auth, timeout, store)
    _check_api_rate_limit(session, endpoints, curl_auth, timeout, store)


def _check_login_rate_limit(session, base_url, curl_auth, timeout, store):
    for path in LOGIN_PATHS:
        url = base_url.rstrip("/") + path

        # Quick probe to see if endpoint exists
        try:
            probe = session.get(url, timeout=5, allow_redirects=False)
            if probe.status_code in (404, 410):
                continue
        except Exception:
            continue

        # Send 20 rapid failed login attempts
        codes = []
        headers_seen = []
        for i in range(20):
            try:
                resp = session.post(
                    url,
                    data={
                        "username": "pentest_ratelimit_probe",
                        "password": f"wrongpassword{i}",
                        "email": "pentest@ratelimit.test",
                    },
                    json=None,
                    timeout=timeout,
                    allow_redirects=False,
                )
                codes.append(resp.status_code)
                rl_header = resp.headers.get("X-RateLimit-Remaining", "")
                retry_after = resp.headers.get("Retry-After", "")
                if retry_after:
                    headers_seen.append(f"Retry-After: {retry_after}")

                # If we're getting 429 or rate limit signals, it's protected
                body_lower = resp.text[:200].lower()
                if resp.status_code == 429 or any(kw in body_lower for kw in RATE_LIMIT_INDICATORS):
                    store.add(Finding(
                        title=f"Rate limiting работает на {path} (после {i+1} запросов)",
                        severity=Severity.INFO,
                        category="Rate Limiting",
                        cwe="",
                        description=f"Endpoint {path} возвращает HTTP {resp.status_code} после {i+1} попыток. Rate limiting защищает от брутфорса.",
                        url=url,
                        evidence=f"HTTP {resp.status_code} после {i+1} запросов",
                        remediation="",
                        reproduction="",
                    ))
                    return

                time.sleep(0.1)  # Small delay between requests
            except Exception:
                break

        # If all 20 got consistent non-blocking responses
        non_blocking = [c for c in codes if c not in (429, 503)]
        if len(non_blocking) >= 15:
            unique_codes = set(non_blocking)
            store.add(Finding(
                title=f"Отсутствует Rate Limiting на endpoint входа: {path}",
                severity=Severity.HIGH,
                category="Rate Limiting",
                cwe="CWE-307",
                description=(
                    f"20 последовательных запросов на {path} не вызвали блокировки или замедления. "
                    f"HTTP коды ответов: {unique_codes}. "
                    "Отсутствие rate limiting позволяет атаки брутфорс/credential stuffing."
                ),
                url=url,
                evidence=f"20 запросов без ограничений. Коды: {codes[:10]}...",
                remediation=(
                    "1. Добавьте rate limiting: не более 5-10 попыток входа в минуту.\n"
                    "2. После X неудачных попыток — блокировка аккаунта или CAPTCHA.\n"
                    "3. Используйте IP-based throttling + account-based lockout.\n"
                    "4. Добавьте заголовки: X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After.\n"
                    "5. Логируйте и алертируйте при аномальном числе неудачных попыток входа."
                ),
                reproduction=(
                    f"# 20 быстрых попыток брутфорса:\n"
                    f"for i in $(seq 1 20); do\n"
                    f"  curl -sk {curl_auth} -X POST '{url}' \\\n"
                    f"    -d 'username=admin&password=wrong$i' -o /dev/null -w '%{{http_code}}\\n'\n"
                    f"done"
                ),
            ))
        break  # Test only first found login endpoint


def _check_api_rate_limit(session, endpoints, curl_auth, timeout, store):
    # Check up to 3 API endpoints for rate limiting
    api_endpoints = [ep for ep in endpoints
                     if "/api/" in ep.url and ep.method == "GET"][:3]

    for ep in api_endpoints:
        codes = []
        for i in range(30):
            try:
                resp = session.get(ep.url, timeout=5)
                codes.append(resp.status_code)
                if resp.status_code == 429:
                    break
                time.sleep(0.05)
            except Exception:
                break

        non_throttled = [c for c in codes if c == 200]
        if len(non_throttled) == 30:
            store.add(Finding(
                title=f"Отсутствует Rate Limiting на API endpoint",
                severity=Severity.MEDIUM,
                category="Rate Limiting",
                cwe="CWE-770",
                description=(
                    f"30 запросов к '{ep.url}' без throttling. "
                    "Без rate limiting возможны DoS через массовые запросы, "
                    "enumeration атаки и data harvesting."
                ),
                url=ep.url,
                evidence=f"30 запросов вернули HTTP 200 без ограничений",
                remediation=(
                    "1. Добавьте rate limiting на API-уровне (gateway или приложение).\n"
                    "2. Используйте Token Bucket или Sliding Window алгоритмы.\n"
                    "3. Вернуть 429 Too Many Requests с Retry-After."
                ),
                reproduction=(
                    f"for i in $(seq 1 50); do\n"
                    f"  curl -sk {curl_auth} '{ep.url}' -o /dev/null -w '%{{http_code}} ';\n"
                    f"done"
                ),
            ))
