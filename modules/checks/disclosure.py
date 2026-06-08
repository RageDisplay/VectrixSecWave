from __future__ import annotations
import re
from urllib.parse import urljoin
import requests

from ..findings import Finding, Severity
from ..session import session_to_curl_flags


SENSITIVE_PATHS = {
    # API docs
    "/swagger.json": "Swagger JSON (API schema)",
    "/swagger.yaml": "Swagger YAML",
    "/swagger-ui.html": "Swagger UI",
    "/swagger-ui/": "Swagger UI",
    "/api-docs": "API docs",
    "/openapi.json": "OpenAPI schema",
    "/openapi.yaml": "OpenAPI schema",
    "/graphql": "GraphQL endpoint",
    "/graphiql": "GraphiQL IDE",
    "/v1/api-docs": "Spring API docs",
    "/v2/api-docs": "Spring API docs v2",
    # Actuator / management
    "/actuator": "Spring Boot Actuator",
    "/actuator/env": "Spring Boot env (env vars!)",
    "/actuator/health": "Spring Boot health",
    "/actuator/metrics": "Spring Boot metrics",
    "/actuator/beans": "Spring Boot beans",
    "/actuator/mappings": "Spring Boot mappings",
    "/actuator/trace": "Spring Boot request trace",
    "/actuator/httptrace": "Spring Boot HTTP trace",
    "/actuator/logfile": "Spring Boot logfile",
    "/actuator/threaddump": "Spring Boot thread dump",
    "/actuator/heapdump": "Spring Boot heap dump!",
    "/actuator/sessions": "Spring Boot sessions",
    "/actuator/scheduledtasks": "Spring Boot scheduled tasks",
    # Debug
    "/debug": "debug endpoint",
    "/console": "debug console",
    "/phpinfo.php": "PHP info",
    "/info.php": "PHP info",
    "/test.php": "PHP test file",
    "/.env": ".env file",
    "/.env.local": ".env.local",
    "/.env.development": ".env.development",
    "/.env.production": ".env.production",
    # Config / Git
    "/.git/config": "Git config",
    "/.git/HEAD": "Git HEAD",
    "/.svn/entries": "SVN entries",
    "/web.config": "IIS web.config",
    "/.htaccess": "Apache .htaccess",
    "/config.json": "config.json",
    "/config.yaml": "config.yaml",
    "/settings.json": "settings.json",
    "/app.config": "app.config",
    # Backup
    "/backup.zip": "backup archive",
    "/backup.sql": "SQL dump",
    "/db.sql": "SQL dump",
    "/dump.sql": "SQL dump",
    # Secrets
    "/credentials.json": "credentials",
    "/secrets.json": "secrets",
    "/private.key": "private key",
    "/server.key": "SSL private key",
    # Metrics / monitoring
    "/metrics": "metrics endpoint",
    "/prometheus": "Prometheus metrics",
    "/health": "health check",
    "/status": "status endpoint",
    "/ping": "ping",
    # Admin
    "/admin": "admin panel",
    "/admin/login": "admin login",
    "/administrator": "administrator panel",
    "/manage": "management panel",
    "/wp-admin": "WordPress admin",
    "/phpmyadmin": "phpMyAdmin",
}

ERROR_TRIGGERS = [
    "/'\"<>{}[]()", # various injection chars
    "../../../../../etc/passwd",
    "undefined",
    "\x00",
    "' OR 1=1--",
]

# Patterns indicating verbose errors
VERBOSE_ERROR_SIGNATURES = [
    r"Traceback \(most recent call last\)",      # Python
    r"at .+\([\w.]+:\d+\)",                      # Java stack trace
    r"NullPointerException",
    r"ClassNotFoundException",
    r"Exception in thread",
    r"PHP Fatal error",
    r"PHP Warning",
    r"PHP Notice",
    r"Parse error:.*PHP",
    r"Warning:.*on line \d+",
    r"include\(.*\): failed to open stream",
    r"Microsoft.*ODBC.*Driver",
    r"ORA-\d{5}:",
    r"SQLSTATE\[",
    r"You have an error in your SQL syntax",
    r"Uncaught Error:",
    r"Unhandled Promise Rejection",
    r"undefined is not a function",             # JS errors
    r"Cannot read property .* of undefined",
    r"Error: ENOENT: no such file",             # Node.js
    r"ActiveRecord::.*Error",                   # Rails
    r"PG::.*Error",
    r"django\.core\.exceptions",
    r"WSGI Application Error",
]

VERSION_PATTERNS = {
    "Apache": re.compile(r"Apache/([\d.]+)", re.I),
    "nginx": re.compile(r"nginx/([\d.]+)", re.I),
    "PHP": re.compile(r"PHP/([\d.]+)", re.I),
    "ASP.NET": re.compile(r"ASP\.NET Version:([\d.]+)", re.I),
    "Spring": re.compile(r"Spring Framework ([\d.]+)", re.I),
    "Tomcat": re.compile(r"Apache Tomcat/([\d.]+)", re.I),
    "Express": re.compile(r"Express/([\d.]+)", re.I),
    "Django": re.compile(r"Django/([\d.]+)", re.I),
    "Rails": re.compile(r"Rails ([\d.]+)", re.I),
}

SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key": re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*([A-Za-z0-9/+]{40})"),
    "Private Key": re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Stripe Key": re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}"),
    "GitHub Token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
    "JWT Secret": re.compile(r"(?i)(jwt[_-]?secret|secret[_-]?key)\s*[=:]\s*['\"]([^'\"]{8,})"),
    "Database URL": re.compile(r"(?i)(postgres|mysql|mongodb|redis)://[^@\s]{4,}@[^\s\"']+"),
}


def run(session: requests.Session, base_url: str, endpoints: list, store) -> None:
    print("[*] Checking information disclosure...")
    curl_auth = session_to_curl_flags(session)
    timeout = getattr(session, 'timeout', 15)

    _check_sensitive_paths(session, base_url, curl_auth, timeout, store)
    _check_verbose_errors(session, base_url, endpoints, curl_auth, timeout, store)
    _check_secrets_in_responses(session, endpoints, curl_auth, timeout, store)
    _check_graphql(session, base_url, curl_auth, timeout, store)


def _check_sensitive_paths(session, base_url, curl_auth, timeout, store):
    for path, label in SENSITIVE_PATHS.items():
        url = base_url.rstrip("/") + path
        try:
            resp = session.get(url, timeout=8, allow_redirects=True)
        except Exception:
            continue

        if resp.status_code in (404, 410, 501):
            continue

        severity = Severity.HIGH
        if resp.status_code in (401, 403):
            severity = Severity.INFO
        elif path in ("/.env", "/.git/config", "/actuator/env", "/actuator/heapdump",
                      "/backup.sql", "/credentials.json", "/secrets.json", "/private.key"):
            severity = Severity.CRITICAL

        ct = resp.headers.get("content-type", "").lower()
        body_snippet = resp.text[:300].replace("\n", " ")

        store.add(Finding(
            title=f"Доступен чувствительный путь: {path} ({label})",
            severity=severity,
            category="Information Disclosure",
            cwe="CWE-200",
            description=(
                f"URL '{url}' возвращает HTTP {resp.status_code}.\n"
                f"Ресурс: {label}\n"
                f"Content-Type: {ct or 'не указан'}"
            ),
            url=url,
            evidence=f"HTTP {resp.status_code}\n{body_snippet}",
            remediation=(
                f"1. Закройте доступ к {path} на уровне веб-сервера / файрвола.\n"
                "2. Удалите чувствительные файлы из webroot.\n"
                "3. Ограничьте Actuator-эндпоинты (management.endpoints.web.exposure.include)."
            ),
            reproduction=f"curl -sk {curl_auth} '{url}'",
        ))


def _check_verbose_errors(session, base_url, endpoints, curl_auth, timeout, store):
    tested = set()
    targets = [base_url] + [ep.url for ep in endpoints if ep.method == "GET"][:20]

    for url in targets:
        if url in tested:
            continue
        tested.add(url)

        for trigger in ERROR_TRIGGERS[:3]:
            test_url = url + trigger if "?" not in url else url + "&err=" + trigger
            try:
                resp = session.get(test_url, timeout=8)
            except Exception:
                continue

            for sig in VERBOSE_ERROR_SIGNATURES:
                m = re.search(sig, resp.text, re.IGNORECASE)
                if m:
                    snippet = resp.text[max(0, m.start()-100):m.end()+200]
                    store.add(Finding(
                        title="Verbose error messages — утечка стектрейса",
                        severity=Severity.MEDIUM,
                        category="Information Disclosure",
                        cwe="CWE-209",
                        description=(
                            f"Приложение возвращает подробные сообщения об ошибках.\n"
                            f"Паттерн: {sig}\n"
                            "Это раскрывает технологический стек, пути файлов и детали реализации."
                        ),
                        url=test_url,
                        evidence=f"...{snippet}...",
                        remediation=(
                            "1. Настройте production error handler: возвращайте только generic сообщение.\n"
                            "2. Логируйте детали ошибки только на сервере.\n"
                            "3. DEBUG=False (Django), displayErrors: false, error_reporting(0) (PHP)."
                        ),
                        reproduction=f"curl -sk {curl_auth} '{test_url}'",
                    ))
                    tested.add(url)  # Don't re-test this URL
                    break
            break  # One trigger per URL is enough for detection


def _check_secrets_in_responses(session, endpoints, curl_auth, timeout, store):
    for ep in endpoints[:30]:  # Limit to first 30 endpoints
        if ep.method not in ("GET", "HEAD"):
            continue
        try:
            resp = session.get(ep.url, timeout=timeout)
            if resp.status_code != 200:
                continue
            text = resp.text
        except Exception:
            continue

        for secret_type, pattern in SECRET_PATTERNS.items():
            m = pattern.search(text)
            if m:
                store.add(Finding(
                    title=f"Секрет в HTTP-ответе: {secret_type}",
                    severity=Severity.CRITICAL,
                    category="Information Disclosure",
                    cwe="CWE-312",
                    description=(
                        f"В ответе '{ep.url}' обнаружен {secret_type}.\n"
                        "Утечка credentials в HTTP-ответах критична для безопасности."
                    ),
                    url=ep.url,
                    evidence=f"Найдено: {m.group()[:80]}...",
                    remediation=(
                        "1. Немедленно ротируйте скомпрометированные credentials.\n"
                        "2. Не возвращайте секреты в API-ответах.\n"
                        "3. Используйте secret management (Vault, AWS Secrets Manager).\n"
                        "4. Проверьте git-историю на предмет закоммиченных секретов."
                    ),
                    reproduction=f"curl -sk {curl_auth} '{ep.url}' | grep -oE '<pattern>'",
                ))


def _check_graphql(session, base_url, curl_auth, timeout, store):
    graphql_endpoints = ["/graphql", "/api/graphql", "/graphiql", "/gql", "/query"]

    for path in graphql_endpoints:
        url = base_url.rstrip("/") + path
        # Check if endpoint exists
        try:
            probe = session.get(url, timeout=8)
            if probe.status_code in (404, 410):
                continue
        except Exception:
            continue

        # Try introspection
        introspection_query = {
            "query": "{ __schema { types { name fields { name } } } }"
        }
        try:
            resp = session.post(
                url,
                json=introspection_query,
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            if resp.status_code == 200 and "__schema" in resp.text:
                store.add(Finding(
                    title="GraphQL: introspection включена (schema disclosure)",
                    severity=Severity.MEDIUM,
                    category="Information Disclosure",
                    cwe="CWE-200",
                    description=(
                        f"GraphQL endpoint '{url}' возвращает полную схему через introspection.\n"
                        "Атакующий может восстановить всю структуру API, включая мутации и аргументы."
                    ),
                    url=url,
                    evidence=f"__schema присутствует в ответе на introspection-запрос",
                    remediation=(
                        "1. Отключите introspection в production:\n"
                        "   GraphQL Shield, depth-limit или параметр disableIntrospection.\n"
                        "2. Если introspection нужна — ограничьте по IP или роли."
                    ),
                    reproduction=(
                        f"curl -sk {curl_auth} -X POST '{url}' \\\n"
                        f"  -H 'Content-Type: application/json' \\\n"
                        f"  -d '{{\"query\":\"{{ __schema {{ types {{ name }} }} }}\"}}"
                    ),
                ))

            # Check for batch query attack
            batch_query = [introspection_query, introspection_query, introspection_query]
            resp_batch = session.post(
                url,
                json=batch_query,
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            if resp_batch.status_code == 200 and isinstance(resp_batch.json(), list):
                store.add(Finding(
                    title="GraphQL: batch queries включены",
                    severity=Severity.LOW,
                    category="API Security",
                    cwe="CWE-770",
                    description=(
                        "GraphQL endpoint принимает batch-запросы (массив операций в одном HTTP-запросе). "
                        "Это может использоваться для обхода rate limiting или брутфорса."
                    ),
                    url=url,
                    evidence=f"Batch ответ: {resp_batch.text[:200]}",
                    remediation="Ограничьте глубину и количество операций в одном запросе. Отключите batch если не используется.",
                    reproduction=(
                        f"curl -sk {curl_auth} -X POST '{url}' \\\n"
                        f"  -H 'Content-Type: application/json' \\\n"
                        f"  -d '[{{\"query\":\"{{me{{id}}}}\"}},{{\"query\":\"{{me{{id}}}}\"}},{{\"query\":\"{{me{{id}}}}\"}}]'"
                    ),
                ))
        except Exception:
            pass
