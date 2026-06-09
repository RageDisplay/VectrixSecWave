"""Host header injection checks.

Tests for:
1. Host header reflection — injected value appears in response body or headers
   (cache poisoning, open redirect, link injection vectors)
2. Password reset poisoning — forged Host causes reset links to point to
   attacker-controlled domain; check verifies server reflects the injected host
   in response body (email content preview / token in response)
3. X-Forwarded-Host / X-Host / proxy header variants
"""
from __future__ import annotations
import re
import requests

from ..findings import Finding, Severity
from ..session import session_to_curl_flags

PROBE_HOST = "vectrix-probe.attacker-host.com"

HOST_OVERRIDE_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "X-Original-Host",
]

RESET_PATHS = [
    "/forgot-password", "/forgot_password", "/password/reset",
    "/password-reset", "/auth/reset", "/api/password/reset",
    "/api/auth/forgot", "/api/auth/password/reset",
    "/users/password", "/account/forgot", "/reset-password",
    "/api/v1/auth/forgot", "/api/v2/auth/forgot",
]


# ── Main entry ────────────────────────────────────────────────────────────────

def run(session: requests.Session, base_url: str, endpoints: list, store) -> None:
    print("[*] Checking Host header injection...")
    curl_auth = session_to_curl_flags(session)
    timeout = getattr(session, 'timeout', 15)

    _check_host_reflection(session, base_url, curl_auth, timeout, store)
    _check_reset_poisoning(session, base_url, endpoints, curl_auth, timeout, store)


# ── Host reflection ───────────────────────────────────────────────────────────

def _check_host_reflection(session, base_url, curl_auth, timeout, store):
    """Try injecting PROBE_HOST via various override headers; look for reflection."""
    for header in HOST_OVERRIDE_HEADERS:
        try:
            resp = session.get(
                base_url,
                headers={header: PROBE_HOST},
                timeout=timeout,
                allow_redirects=False,
            )
        except Exception:
            continue

        probe_lower = PROBE_HOST.lower()
        reflected_in_body = probe_lower in resp.text.lower()
        reflected_in_location = probe_lower in resp.headers.get("Location", "").lower()
        reflected_in_link = probe_lower in resp.headers.get("Link", "").lower()

        if not (reflected_in_body or reflected_in_location or reflected_in_link):
            continue

        where = []
        if reflected_in_body:      where.append("body")
        if reflected_in_location:  where.append("Location header")
        if reflected_in_link:      where.append("Link header")

        store.add(Finding(
            title=f"Host Header Injection — отражение через '{header}'",
            severity=Severity.HIGH,
            category="Injection",
            cwe="CWE-113",
            description=(
                f"Заголовок '{header}: {PROBE_HOST}' отражается в ответе ({', '.join(where)}).\n\n"
                "Векторы эксплуатации:\n"
                "• **Web Cache Poisoning** — CDN/proxy кэшируют ответ с injected-ссылками\n"
                "• **Password Reset Poisoning** — ссылка в письме указывает на сервер атакующего\n"
                "• **Open Redirect** — Location содержит внешний домен\n"
                "• **SSRF через Host** — внутренние сервисы принимают запросы по поддельному хосту"
            ),
            url=base_url,
            evidence=(
                f"Заголовок: {header}: {PROBE_HOST}\n"
                f"Зеркало найдено в: {', '.join(where)}\n"
                f"HTTP {resp.status_code}"
            ),
            remediation=(
                "1. Формируйте абсолютные URL из жёстко заданного домена в конфигурации, "
                "   а не из заголовка HTTP Host.\n"
                "2. Валидируйте Host и X-Forwarded-Host по whitelist разрешённых доменов.\n"
                "3. В nginx/Apache/CDN задайте canonical hostname и отклоняйте нераспознанные.\n"
                "4. Для cache poisoning: установьте Vary: Host на кэшируемые ответы."
            ),
            reproduction=(
                f"curl -sk {curl_auth} -H '{header}: {PROBE_HOST}' -I '{base_url}'"
            ),
        ))
        return  # One finding per base_url is enough


# ── Password reset poisoning ──────────────────────────────────────────────────

def _check_reset_poisoning(session, base_url, endpoints, curl_auth, timeout, store):
    """Try to trigger a reset and check if the injected Host appears in response."""
    # Collect reset endpoints from crawl + static list
    reset_urls: set[str] = set()
    for ep in endpoints:
        if any(p in ep.url.lower() for p in RESET_PATHS):
            reset_urls.add(ep.url)
    for path in RESET_PATHS:
        reset_urls.add(base_url.rstrip("/") + path)

    for url in list(reset_urls)[:12]:
        # Quick GET probe — skip if 404/410
        try:
            probe = session.get(url, timeout=timeout, allow_redirects=False)
            if probe.status_code in (404, 410):
                continue
        except Exception:
            continue

        for header in ["Host", "X-Forwarded-Host"]:
            try:
                extra = {header: PROBE_HOST}
                if header == "Host":
                    extra["X-Forwarded-Host"] = PROBE_HOST

                resp = session.post(
                    url,
                    data={"email": "pentest-probe@example.com"},
                    headers=extra,
                    timeout=timeout,
                    allow_redirects=False,
                )
            except Exception:
                continue

            if resp.status_code not in (200, 201, 202, 204, 302, 301):
                continue

            if PROBE_HOST.lower() not in resp.text.lower():
                continue

            store.add(Finding(
                title="Password Reset Poisoning — Host header в теле ответа сброса пароля",
                severity=Severity.HIGH,
                category="Authentication",
                cwe="CWE-640",
                description=(
                    f"Endpoint {url} принял POST с поддельным {header} "
                    f"и отразил '{PROBE_HOST}' в теле ответа.\n\n"
                    "Если сервер использует Host для формирования ссылки в reset-письме, "
                    "атакующий может перехватить токен сброса пароля:\n"
                    "1. Злоумышленник инициирует сброс для жертвы с Host: evil.com\n"
                    "2. Жертва получает письмо со ссылкой https://evil.com/reset?token=...\n"
                    "3. При клике — токен улетает на сервер атакующего\n"
                    "4. Атакующий меняет пароль жертвы"
                ),
                url=url,
                method="POST",
                evidence=(
                    f"{header}: {PROBE_HOST} → '{PROBE_HOST}' найдено в ответе\n"
                    f"HTTP {resp.status_code}"
                ),
                remediation=(
                    "1. Генерируйте reset-ссылки с доменом из конфигурации приложения, "
                    "   НЕ из заголовка Host.\n"
                    "2. Добавьте whitelist разрешённых доменов для Host/X-Forwarded-Host.\n"
                    "3. Проверьте: config('app.url') в Laravel, settings.ALLOWED_HOSTS в Django, "
                    "   ServerName в Apache, server_name в nginx."
                ),
                reproduction=(
                    f"curl -sk {curl_auth} -X POST "
                    f"-H 'Host: {PROBE_HOST}' "
                    f"-H 'X-Forwarded-Host: {PROBE_HOST}' "
                    f"-d 'email=victim@target.com' '{url}'"
                ),
            ))
            return  # One finding is enough
