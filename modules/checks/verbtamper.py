"""HTTP Verb Tampering, Mass Assignment, and Method Override checks.

Verb Tampering:
  - Restricted endpoints accessible via alternate HTTP methods (GET→POST, PATCH, DELETE…)
  - X-HTTP-Method-Override / _method bypass
  - HTTP TRACE (XST vector)

Mass Assignment:
  - Inject admin/privilege fields into JSON POST/PUT endpoints; detect reflection
  - Covers is_admin, role, price=0, discount=100, etc.
"""
from __future__ import annotations
import json
import re
import requests

from ..findings import Finding, Severity
from ..session import session_to_curl_flags

TRACE_PROBE_HEADER = "X-Vectrix-Trace-Probe"

ADMIN_PATHS = [
    "/admin", "/admin/users", "/admin/settings",
    "/api/admin", "/api/v1/admin", "/api/v2/admin",
    "/management", "/manage", "/dashboard/admin",
    "/api/users", "/api/v1/users", "/api/v2/users",
    "/api/config", "/api/settings",
]

METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-HTTP-Method",
    "_method",
]

MASS_ASSIGN_PROBE: dict = {
    "is_admin": True,
    "isAdmin": True,
    "role": "admin",
    "admin": True,
    "is_superuser": True,
    "privilege": "admin",
    "account_type": "admin",
    "user_type": "admin",
    "permissions": ["admin"],
    "price": 0,
    "amount": -1,
    "discount": 100,
    "balance": 99999,
    "credit": 99999,
}

# Keys that signal successful mass assignment if reflected back
MASS_ASSIGN_CONFIRM_KEYS = {"is_admin", "isAdmin", "role", "admin",
                             "is_superuser", "privilege", "account_type",
                             "user_type", "permissions", "price", "discount"}


# ── Main entry ────────────────────────────────────────────────────────────────

def run(session: requests.Session, base_url: str, endpoints: list, store) -> None:
    print("[*] Checking HTTP verb tampering & mass assignment...")
    curl_auth = session_to_curl_flags(session)
    timeout = getattr(session, 'timeout', 15)

    _check_trace(session, base_url, curl_auth, timeout, store)
    _check_verb_tampering(session, base_url, endpoints, curl_auth, timeout, store)
    _check_method_override(session, base_url, endpoints, curl_auth, timeout, store)
    _check_mass_assignment(session, endpoints, curl_auth, timeout, store)


# ── TRACE / XST ───────────────────────────────────────────────────────────────

def _check_trace(session, base_url, curl_auth, timeout, store):
    try:
        resp = session.request(
            "TRACE", base_url,
            headers={TRACE_PROBE_HEADER: "vectrix-xst-probe"},
            timeout=timeout,
        )
    except Exception:
        return

    if resp.status_code == 200 and "vectrix-xst-probe" in resp.text:
        store.add(Finding(
            title="HTTP TRACE включён — Cross-Site Tracing (XST) возможен",
            severity=Severity.LOW,
            category="Security Headers",
            cwe="CWE-16",
            description=(
                "Сервер принимает HTTP TRACE и возвращает заголовки запроса в теле ответа.\n"
                "В сочетании с XSS это позволяет атакующему читать HttpOnly-куки через XST:\n"
                "1. Встраивает JavaScript с XHR TRACE-запросом на целевой сайт\n"
                "2. В теле ответа появляются все заголовки, включая HttpOnly Cookie\n"
                "3. Cookie отправляется на сервер атакующего"
            ),
            url=base_url,
            method="TRACE",
            evidence=f"TRACE ответ содержит инъектированный заголовок {TRACE_PROBE_HEADER}",
            remediation=(
                "Отключите TRACE во всех компонентах стека:\n"
                "  nginx:  limit_except GET POST { deny all; }\n"
                "  Apache: TraceEnable off\n"
                "  IIS:    <verbs allowUnlisted='false'> в web.config\n"
                "  Node/Express: app.disable('x-powered-by'); + явная блокировка TRACE"
            ),
            reproduction=(
                f"curl -sk {curl_auth} -X TRACE "
                f"-H '{TRACE_PROBE_HEADER}: vectrix-xst-probe' '{base_url}'"
            ),
        ))


# ── Verb tampering ────────────────────────────────────────────────────────────

def _check_verb_tampering(session, base_url, endpoints, curl_auth, timeout, store):
    # Collect restricted-ish paths: admin paths + any endpoint that returned 4xx on crawl
    candidate_urls: set[str] = set()
    for path in ADMIN_PATHS:
        candidate_urls.add(base_url.rstrip("/") + path)
    for ep in endpoints:
        if "/admin" in ep.url.lower() or "/manage" in ep.url.lower():
            candidate_urls.add(ep.url)

    for url in list(candidate_urls)[:20]:
        # Baseline: GET
        try:
            baseline = session.get(url, timeout=timeout, allow_redirects=False)
        except Exception:
            continue

        if baseline.status_code == 200:
            continue  # Already accessible — not a tampering bypass

        baseline_code = baseline.status_code
        alt_methods = ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

        for method in alt_methods:
            try:
                resp = session.request(method, url, timeout=timeout, allow_redirects=False)
            except Exception:
                continue

            if resp.status_code == 200 and len(resp.text) > 100:
                store.add(Finding(
                    title=f"HTTP Verb Tampering — {method} даёт доступ к {url}",
                    severity=Severity.HIGH,
                    category="Access Control",
                    cwe="CWE-650",
                    description=(
                        f"Endpoint {url} недоступен через GET "
                        f"(HTTP {baseline_code}), но возвращает HTTP 200 "
                        f"при {method}-запросе ({len(resp.text)} байт).\n\n"
                        "Контроль доступа реализован только для определённых методов, "
                        "что позволяет атакующему обойти ограничения, изменив HTTP-метод."
                    ),
                    url=url,
                    method=method,
                    evidence=(
                        f"GET → HTTP {baseline_code}\n"
                        f"{method} → HTTP 200 ({len(resp.text)} байт)"
                    ),
                    remediation=(
                        "1. Применяйте авторизацию ко всем HTTP-методам, а не только GET/POST.\n"
                        "2. Явно запрещайте ненужные методы (405 Method Not Allowed).\n"
                        "3. Spring Security: .requestMatchers('/**').hasRole('ADMIN') "
                        "применяется ко всем методам.\n"
                        "4. Express/Koa: middleware авторизации на router.use(), "
                        "не только на router.get()."
                    ),
                    reproduction=f"curl -sk {curl_auth} -X {method} '{url}'",
                ))
                break  # one finding per endpoint


# ── Method override ───────────────────────────────────────────────────────────

def _check_method_override(session, base_url, endpoints, curl_auth, timeout, store):
    for path in ADMIN_PATHS[:8]:
        url = base_url.rstrip("/") + path
        try:
            baseline = session.get(url, timeout=timeout, allow_redirects=False)
        except Exception:
            continue

        if baseline.status_code in (200, 404, 410):
            continue

        for hdr in METHOD_OVERRIDE_HEADERS:
            for override_method in ("GET", "DELETE"):
                try:
                    resp = session.post(
                        url,
                        headers={hdr: override_method},
                        timeout=timeout,
                        allow_redirects=False,
                    )
                except Exception:
                    continue

                if resp.status_code == 200 and len(resp.text) > 100:
                    store.add(Finding(
                        title=f"HTTP Method Override bypass — '{hdr}: {override_method}'",
                        severity=Severity.HIGH,
                        category="Access Control",
                        cwe="CWE-650",
                        description=(
                            f"Заголовок '{hdr}: {override_method}' позволяет обойти "
                            f"ограничение доступа к {url}.\n"
                            f"Baseline GET → HTTP {baseline.status_code}, "
                            f"POST + {hdr} → HTTP 200.\n\n"
                            "Фреймворки (Rails, Laravel, некоторые SPA) поддерживают _method/override "
                            "для обратной совместимости с HTML-формами. Если middleware применяет "
                            "авторизацию по реальному методу, а роутер — по override, возникает gap."
                        ),
                        url=url,
                        method="POST",
                        evidence=(
                            f"Baseline GET: HTTP {baseline.status_code}\n"
                            f"POST + {hdr}: {override_method} → HTTP 200"
                        ),
                        remediation=(
                            "1. Проверяйте авторизацию по реальному HTTP-методу, "
                            "   а не только по переопределённому.\n"
                            "2. Ограничьте список методов, допустимых через override.\n"
                            "3. Rails: config.action_dispatch.perform_deep_munge — "
                            "   отключите _method для privileged endpoints."
                        ),
                        reproduction=(
                            f"curl -sk {curl_auth} -X POST "
                            f"-H '{hdr}: {override_method}' '{url}'"
                        ),
                    ))
                    return


# ── Mass assignment ───────────────────────────────────────────────────────────

def _check_mass_assignment(session, endpoints, curl_auth, timeout, store):
    # Target JSON endpoints that mutate state
    mutable = [
        ep for ep in endpoints
        if ep.method in ("POST", "PUT", "PATCH")
        and ep.body_params  # has known fields from crawl
    ]

    checked: set[str] = set()
    for ep in mutable[:25]:
        key = f"{ep.method}:{ep.url}"
        if key in checked:
            continue
        checked.add(key)

        # Send normal request first to get baseline status
        try:
            baseline = session.request(
                ep.method, ep.url, json=ep.body_params,
                timeout=timeout, allow_redirects=False,
            )
        except Exception:
            continue

        if baseline.status_code >= 500:
            continue

        # Inject mass-assignment bait fields
        try:
            bait_payload = {**ep.body_params, **MASS_ASSIGN_PROBE}
            resp = session.request(
                ep.method, ep.url, json=bait_payload,
                timeout=timeout, allow_redirects=False,
            )
        except Exception:
            continue

        if resp.status_code >= 400:
            continue

        # Parse JSON response and look for injected admin fields
        reflected: list[str] = []
        try:
            resp_data = resp.json()
            resp_str = json.dumps(resp_data).lower()
            for key in MASS_ASSIGN_CONFIRM_KEYS:
                if key.lower() in resp_str:
                    injected_val = MASS_ASSIGN_PROBE.get(key)
                    if injected_val is not None and str(injected_val).lower() in resp_str:
                        reflected.append(key)
        except (ValueError, TypeError):
            # Non-JSON response: look for string matches
            resp_str = resp.text.lower()
            for key in ("is_admin", "admin", "role"):
                if key in resp_str and "true" in resp_str:
                    reflected.append(key)

        if not reflected:
            continue

        sample_payload = json.dumps({**ep.body_params, "is_admin": True, "role": "admin"})
        store.add(Finding(
            title=f"Mass Assignment — поля {reflected[:3]} приняты и отражены",
            severity=Severity.HIGH,
            category="Access Control",
            cwe="CWE-915",
            description=(
                f"Endpoint {ep.url} ({ep.method}) принял и вернул в ответе "
                f"инъектированные привилегированные поля: {reflected}.\n\n"
                "Mass Assignment позволяет атакующему установить произвольные "
                "атрибуты объекта (например, is_admin=true), которые сервер "
                "не должен принимать от пользователя."
            ),
            url=ep.url,
            method=ep.method,
            evidence=(
                f"Инъектированные поля: {reflected}\n"
                f"HTTP {resp.status_code} (baseline: {baseline.status_code})"
            ),
            remediation=(
                "1. Используйте строгий whitelist принимаемых полей (DTO, Serializer):\n"
                "   Django: явно указывайте fields= в Serializer\n"
                "   Laravel: $fillable вместо $guarded\n"
                "   Rails:   Strong Parameters (permit только нужные поля)\n"
                "   Spring:  @JsonIgnore / @JsonProperty(access = READ_ONLY)\n"
                "2. Никогда не передавайте request body напрямую в ORM/ActiveRecord.\n"
                "3. Разделяйте входные DTO и доменные модели."
            ),
            reproduction=(
                f"curl -sk {curl_auth} -X {ep.method} "
                f"-H 'Content-Type: application/json' "
                f"-d '{sample_payload}' '{ep.url}'"
            ),
        ))
