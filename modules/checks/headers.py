from __future__ import annotations
from typing import TYPE_CHECKING
import requests

if TYPE_CHECKING:
    from ..findings import FindingStore
    from ..crawler import Endpoint

from ..findings import Finding, Severity
from ..session import session_to_curl_flags


def run(session: requests.Session, base_url: str, endpoints: list, store) -> None:
    print("[*] Checking security headers...")
    try:
        resp = session.get(base_url, timeout=getattr(session, 'timeout', 15))
    except Exception as e:
        print(f"  [!] Headers check failed: {e}")
        return

    headers = {k.lower(): v for k, v in resp.headers.items()}
    curl_auth = session_to_curl_flags(session)

    _check_csp(headers, base_url, curl_auth, store)
    _check_hsts(headers, base_url, curl_auth, store)
    _check_xframe(headers, base_url, curl_auth, store)
    _check_xcontent(headers, base_url, curl_auth, store)
    _check_referrer(headers, base_url, curl_auth, store)
    _check_permissions(headers, base_url, curl_auth, store)
    _check_server_banner(headers, base_url, curl_auth, resp, store)
    _check_cors_wildcard(headers, base_url, curl_auth, session, store)
    _check_cache_control(headers, base_url, curl_auth, store)


def _check_csp(headers, url, curl_auth, store):
    csp = headers.get("content-security-policy", "")
    if not csp:
        store.add(Finding(
            title="Отсутствует заголовок Content-Security-Policy",
            severity=Severity.MEDIUM,
            category="Security Headers",
            cwe="CWE-693",
            description=(
                "Заголовок Content-Security-Policy не установлен. "
                "Это позволяет XSS-атакам загружать произвольные скрипты из внешних источников."
            ),
            url=url,
            remediation=(
                "Добавьте строгий CSP. Минимум: "
                "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';"
            ),
            reproduction=f"curl -sk {curl_auth} -I '{url}' | grep -i content-security",
            evidence="Заголовок Content-Security-Policy отсутствует в ответе",
        ))
    else:
        issues = []
        if "unsafe-inline" in csp and "script-src" in csp.lower():
            issues.append("'unsafe-inline' в script-src нейтрализует защиту от XSS")
        if "unsafe-eval" in csp:
            issues.append("'unsafe-eval' разрешает выполнение eval(), что опасно")
        if "* " in csp or csp.strip().endswith("*"):
            issues.append("wildcard (*) в CSP разрешает любые источники")
        if "http://" in csp:
            issues.append("CSP разрешает небезопасные http:// источники")
        if issues:
            store.add(Finding(
                title="Небезопасная конфигурация Content-Security-Policy",
                severity=Severity.MEDIUM,
                category="Security Headers",
                cwe="CWE-693",
                description="CSP установлен, но содержит небезопасные директивы:\n• " + "\n• ".join(issues),
                url=url,
                evidence=f"CSP: {csp[:300]}",
                remediation="Уберите 'unsafe-inline', 'unsafe-eval' и wildcard из CSP. Используйте nonces или hashes.",
                reproduction=f"curl -sk {curl_auth} -I '{url}' | grep -i content-security",
            ))


def _check_hsts(headers, url, curl_auth, store):
    if not url.startswith("https://"):
        return
    hsts = headers.get("strict-transport-security", "")
    if not hsts:
        store.add(Finding(
            title="Отсутствует HTTP Strict Transport Security (HSTS)",
            severity=Severity.MEDIUM,
            category="Security Headers",
            cwe="CWE-319",
            description=(
                "Заголовок HSTS не установлен. Браузеры могут быть принудительно переключены "
                "на HTTP, что делает возможными атаки типа SSL stripping / MITM."
            ),
            url=url,
            remediation=(
                "Добавьте: Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains; preload"
            ),
            reproduction=f"curl -sk {curl_auth} -I '{url}' | grep -i strict",
            evidence="Заголовок Strict-Transport-Security отсутствует",
        ))
    else:
        if "max-age=0" in hsts:
            store.add(Finding(
                title="HSTS установлен с max-age=0 (отключён)",
                severity=Severity.MEDIUM,
                category="Security Headers",
                cwe="CWE-319",
                description="HSTS установлен с max-age=0, что фактически отключает его.",
                url=url,
                evidence=f"Strict-Transport-Security: {hsts}",
                remediation="Установите max-age минимум 31536000 (1 год).",
                reproduction=f"curl -sk {curl_auth} -I '{url}' | grep -i strict",
            ))
        elif "max-age=" in hsts:
            try:
                age = int(hsts.split("max-age=")[1].split(";")[0].split(",")[0])
                if age < 15768000:
                    store.add(Finding(
                        title=f"HSTS max-age слишком мал ({age} сек)",
                        severity=Severity.LOW,
                        category="Security Headers",
                        cwe="CWE-319",
                        description=f"max-age={age} меньше рекомендуемых 6 месяцев (15768000).",
                        url=url,
                        evidence=f"Strict-Transport-Security: {hsts}",
                        remediation="Установите max-age минимум 15768000.",
                        reproduction=f"curl -sk {curl_auth} -I '{url}' | grep -i strict",
                    ))
            except (ValueError, IndexError):
                pass


def _check_xframe(headers, url, curl_auth, store):
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    has_frame_in_csp = "frame-ancestors" in csp.lower()
    if not xfo and not has_frame_in_csp:
        store.add(Finding(
            title="Отсутствует защита от Clickjacking (X-Frame-Options / CSP frame-ancestors)",
            severity=Severity.MEDIUM,
            category="Security Headers",
            cwe="CWE-1021",
            description=(
                "Ни X-Frame-Options, ни CSP frame-ancestors не установлены. "
                "Приложение может быть встроено в iframe на стороннем сайте (clickjacking)."
            ),
            url=url,
            remediation=(
                "Добавьте: X-Frame-Options: DENY\n"
                "Или в CSP: Content-Security-Policy: frame-ancestors 'none';"
            ),
            reproduction=(
                f"# Создайте HTML-файл и откройте в браузере:\n"
                f"echo '<iframe src=\"{url}\"></iframe>' > /tmp/clickjack.html && "
                f"xdg-open /tmp/clickjack.html"
            ),
            evidence="X-Frame-Options отсутствует, frame-ancestors в CSP не задан",
        ))


def _check_xcontent(headers, url, curl_auth, store):
    if not headers.get("x-content-type-options", ""):
        store.add(Finding(
            title="Отсутствует X-Content-Type-Options",
            severity=Severity.LOW,
            category="Security Headers",
            cwe="CWE-693",
            description=(
                "Заголовок X-Content-Type-Options: nosniff не установлен. "
                "Браузер может интерпретировать ответы не по объявленному Content-Type "
                "(MIME sniffing), что открывает вектор для некоторых XSS-атак."
            ),
            url=url,
            remediation="Добавьте: X-Content-Type-Options: nosniff",
            reproduction=f"curl -sk {curl_auth} -I '{url}' | grep -i x-content-type",
            evidence="X-Content-Type-Options отсутствует",
        ))


def _check_referrer(headers, url, curl_auth, store):
    rp = headers.get("referrer-policy", "")
    if not rp:
        store.add(Finding(
            title="Отсутствует Referrer-Policy",
            severity=Severity.LOW,
            category="Security Headers",
            cwe="CWE-116",
            description=(
                "Referrer-Policy не установлен. URL с токенами и параметрами сессии "
                "могут утекать в Referer-заголовке к третьим сторонам."
            ),
            url=url,
            remediation="Добавьте: Referrer-Policy: strict-origin-when-cross-origin",
            reproduction=f"curl -sk {curl_auth} -I '{url}' | grep -i referrer",
            evidence="Referrer-Policy отсутствует",
        ))
    elif rp.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        store.add(Finding(
            title=f"Небезопасный Referrer-Policy: {rp}",
            severity=Severity.LOW,
            category="Security Headers",
            cwe="CWE-116",
            description=f"Значение '{rp}' передаёт полный URL (включая query string) как Referer.",
            url=url,
            evidence=f"Referrer-Policy: {rp}",
            remediation="Установите: Referrer-Policy: strict-origin-when-cross-origin",
            reproduction=f"curl -sk {curl_auth} -I '{url}' | grep -i referrer",
        ))


def _check_permissions(headers, url, curl_auth, store):
    if not headers.get("permissions-policy", "") and not headers.get("feature-policy", ""):
        store.add(Finding(
            title="Отсутствует Permissions-Policy",
            severity=Severity.INFO,
            category="Security Headers",
            cwe="CWE-693",
            description=(
                "Permissions-Policy не установлен. Рекомендуется явно ограничивать "
                "доступ страниц к браузерным API (камера, микрофон, геолокация и пр.)."
            ),
            url=url,
            remediation=(
                "Добавьте: Permissions-Policy: geolocation=(), camera=(), "
                "microphone=(), payment=()"
            ),
            reproduction=f"curl -sk {curl_auth} -I '{url}' | grep -i permissions-policy",
            evidence="Permissions-Policy отсутствует",
        ))


def _check_server_banner(headers, url, curl_auth, resp, store):
    leaks = []
    for h in ("server", "x-powered-by", "x-aspnet-version",
              "x-aspnetmvc-version", "x-generator", "x-runtime"):
        val = headers.get(h, "")
        if val:
            leaks.append(f"{h}: {val}")
    if leaks:
        store.add(Finding(
            title="Раскрытие информации о серверном ПО через заголовки",
            severity=Severity.LOW,
            category="Information Disclosure",
            cwe="CWE-200",
            description=(
                "HTTP-ответ содержит заголовки, раскрывающие тип и версию серверного ПО. "
                "Это помогает злоумышленнику подобрать известные CVE."
            ),
            url=url,
            evidence="\n".join(leaks),
            remediation=(
                "Скройте или удалите информационные заголовки: "
                "ServerTokens Prod (Apache), server_tokens off (nginx), "
                "removeHeaders в web.config (IIS)."
            ),
            reproduction=f"curl -sk {curl_auth} -I '{url}' | grep -iE 'server|x-powered-by|x-asp'",
        ))


def _check_cors_wildcard(headers, url, curl_auth, session, store):
    try:
        resp = session.get(
            url,
            headers={"Origin": "https://evil.example.com"},
            timeout=8,
        )
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == "*":
            store.add(Finding(
                title="CORS: wildcard Access-Control-Allow-Origin",
                severity=Severity.LOW,
                category="CORS",
                cwe="CWE-942",
                description="Сервер возвращает Access-Control-Allow-Origin: * — любой сайт может читать ответы через XHR.",
                url=url,
                evidence=f"Access-Control-Allow-Origin: {acao}",
                remediation="Ограничьте CORS конкретными доменами. Никогда не используйте '*' с credentials.",
                reproduction=f"curl -sk {curl_auth} -H 'Origin: https://evil.example.com' -I '{url}' | grep -i access-control",
            ))
        elif acao and acac == "true":
            store.add(Finding(
                title="CORS: отражение Origin с Allow-Credentials: true",
                severity=Severity.HIGH,
                category="CORS",
                cwe="CWE-942",
                description=(
                    f"Сервер отражает Origin '{acao}' и устанавливает Allow-Credentials: true. "
                    "Атакующий может совершать аутентифицированные cross-origin запросы."
                ),
                url=url,
                evidence=f"ACAO: {acao}\nACAC: {acac}",
                remediation="Проверяйте Origin по белому списку, не используйте отражение произвольного Origin.",
                reproduction=(
                    f"curl -sk {curl_auth} -H 'Origin: https://evil.example.com' "
                    f"-I '{url}' | grep -i access-control"
                ),
            ))
    except Exception:
        pass


def _check_cache_control(headers, url, curl_auth, store):
    cc = headers.get("cache-control", "").lower()
    pragma = headers.get("pragma", "").lower()
    ct = headers.get("content-type", "").lower()
    if "html" not in ct and "json" not in ct:
        return
    if "no-store" not in cc and "no-cache" not in cc and "private" not in cc:
        store.add(Finding(
            title="Отсутствует Cache-Control: no-store на динамической странице",
            severity=Severity.LOW,
            category="Security Headers",
            cwe="CWE-524",
            description=(
                "Динамическая страница кэшируется браузером или промежуточными прокси. "
                "Чувствительные данные (токены, ПДн) могут быть сохранены в кэше."
            ),
            url=url,
            evidence=f"Cache-Control: {cc or '(не задан)'}",
            remediation="Добавьте для аутентифицированных страниц: Cache-Control: no-store, no-cache, must-revalidate",
            reproduction=f"curl -sk {curl_auth} -I '{url}' | grep -i cache-control",
        ))
