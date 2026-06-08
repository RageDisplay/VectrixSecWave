from __future__ import annotations
import re
import subprocess
import ssl
import socket
from urllib.parse import urlparse
import requests

from ..findings import Finding, Severity
from ..session import session_to_curl_flags


WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5",
    "ADH", "AECDH", "aNULL", "eNULL",
]

WEAK_TLS_VERSIONS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]


def run(session: requests.Session, base_url: str, endpoints: list, store) -> None:
    if not base_url.startswith("https://"):
        store.add(Finding(
            title="Приложение не использует HTTPS",
            severity=Severity.CRITICAL,
            category="TLS/SSL",
            cwe="CWE-319",
            description=(
                "Приложение доступно по HTTP без TLS. "
                "Весь трафик, включая credentials и сессионные cookies, "
                "передаётся в открытом виде."
            ),
            url=base_url,
            evidence=f"URL: {base_url}",
            remediation=(
                "1. Настройте TLS-сертификат и включите HTTPS.\n"
                "2. Настройте редирект HTTP → HTTPS (301).\n"
                "3. Включите HSTS для предотвращения SSL stripping."
            ),
            reproduction=f"curl -v '{base_url}' 2>&1 | head -30",
        ))
        return

    print("[*] Checking TLS/SSL configuration...")
    curl_auth = session_to_curl_flags(session)

    parsed = urlparse(base_url)
    host = parsed.hostname
    port = parsed.port or 443

    _check_http_redirect(session, base_url, host, curl_auth, store)
    _check_sslscan(host, port, base_url, curl_auth, store)
    _check_cert_python(host, port, base_url, curl_auth, store)
    _check_mixed_content(session, base_url, curl_auth, store)


def _check_http_redirect(session, base_url, host, curl_auth, store):
    http_url = base_url.replace("https://", "http://", 1)
    try:
        resp = requests.get(http_url, timeout=8, verify=False, allow_redirects=False)
        if resp.status_code not in (301, 302, 307, 308):
            store.add(Finding(
                title="HTTP не перенаправляет на HTTPS",
                severity=Severity.HIGH,
                category="TLS/SSL",
                cwe="CWE-319",
                description=(
                    f"Запрос к {http_url} вернул HTTP {resp.status_code} без редиректа на HTTPS. "
                    "Пользователи, открывающие сайт по HTTP, не перенаправляются на защищённое соединение."
                ),
                url=http_url,
                evidence=f"HTTP {resp.status_code}, Location: {resp.headers.get('location', 'нет')}",
                remediation=(
                    "Настройте 301-редирект с HTTP на HTTPS:\n"
                    "  Apache: RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n"
                    "  nginx:  return 301 https://$host$request_uri;"
                ),
                reproduction=f"curl -sk -I '{http_url}'",
            ))
        elif resp.headers.get("location", "").startswith("http://"):
            store.add(Finding(
                title="HTTP редиректит на другой HTTP URL (не HTTPS)",
                severity=Severity.HIGH,
                category="TLS/SSL",
                cwe="CWE-319",
                description=f"Location: {resp.headers['location']} — редирект ведёт на HTTP.",
                url=http_url,
                evidence=f"Location: {resp.headers.get('location')}",
                remediation="Убедитесь что редирект ведёт на https://.",
                reproduction=f"curl -sk -I '{http_url}'",
            ))
    except Exception:
        pass


def _check_sslscan(host, port, base_url, curl_auth, store):
    try:
        result = subprocess.run(
            ["sslscan", "--no-colour", f"{host}:{port}"],
            capture_output=True, text=True, timeout=60,
        )
        output = result.stdout + result.stderr
    except FileNotFoundError:
        # sslscan not available, skip
        return
    except subprocess.TimeoutExpired:
        return

    # Check weak TLS versions
    for version in WEAK_TLS_VERSIONS:
        # sslscan marks enabled protocols with "enabled"
        pattern = re.compile(
            rf"{re.escape(version)}\s+enabled",
            re.IGNORECASE,
        )
        if pattern.search(output):
            severity = Severity.CRITICAL if "SSLv" in version else Severity.HIGH
            store.add(Finding(
                title=f"Устаревший TLS/SSL протокол включён: {version}",
                severity=severity,
                category="TLS/SSL",
                cwe="CWE-326",
                description=(
                    f"Сервер поддерживает {version}, который считается небезопасным.\n"
                    f"SSLv2/SSLv3: DROWN, POODLE атаки.\n"
                    f"TLS 1.0/1.1: BEAST, POODLE-TLS, множество известных атак."
                ),
                url=base_url,
                evidence=f"sslscan output: {version} enabled",
                remediation=(
                    f"Отключите {version}. Минимальная версия: TLS 1.2, рекомендуется TLS 1.3.\n"
                    "nginx: ssl_protocols TLSv1.2 TLSv1.3;\n"
                    "Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1"
                ),
                reproduction=f"sslscan {host}:{port}",
            ))

    # Check weak ciphers
    weak_found = []
    for cipher in WEAK_CIPHERS:
        if re.search(rf"\b{re.escape(cipher)}\b", output, re.IGNORECASE):
            weak_found.append(cipher)

    if weak_found:
        store.add(Finding(
            title=f"Слабые шифры TLS: {', '.join(weak_found)}",
            severity=Severity.HIGH,
            category="TLS/SSL",
            cwe="CWE-326",
            description=(
                f"Сервер поддерживает небезопасные cipher suites: {', '.join(weak_found)}.\n"
                "Слабые шифры могут быть использованы для расшифровки трафика."
            ),
            url=base_url,
            evidence=f"Найдены в sslscan: {weak_found}",
            remediation=(
                "Используйте только современные cipher suites:\n"
                "nginx: ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...'\n"
                "Проверьте: https://ssl-config.mozilla.org/"
            ),
            reproduction=f"sslscan {host}:{port} | grep -i 'accepted\\|cipher'",
        ))

    # Check for self-signed cert
    if "self-signed" in output.lower() or "self signed" in output.lower():
        store.add(Finding(
            title="Самоподписанный TLS-сертификат",
            severity=Severity.MEDIUM,
            category="TLS/SSL",
            cwe="CWE-295",
            description=(
                "Сервер использует самоподписанный сертификат. "
                "Браузеры показывают предупреждение, пользователи уязвимы к MITM."
            ),
            url=base_url,
            evidence="sslscan обнаружил self-signed certificate",
            remediation="Используйте сертификат от доверенного CA (Let's Encrypt, корпоративный CA).",
            reproduction=f"sslscan {host}:{port} | grep -i 'self'",
        ))


def _check_cert_python(host, port, base_url, curl_auth, store):
    try:
        import datetime
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=10),
                              server_hostname=host) as s:
            cert = s.getpeercert()

        # Expiry check
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_dt = ssl.cert_time_to_seconds(expire_str)
            import time
            days_left = (expire_dt - time.time()) / 86400
            if days_left < 0:
                store.add(Finding(
                    title="TLS-сертификат просрочен",
                    severity=Severity.CRITICAL,
                    category="TLS/SSL",
                    cwe="CWE-298",
                    description=f"Сертификат истёк {abs(int(days_left))} дней назад ({expire_str}).",
                    url=base_url,
                    evidence=f"notAfter: {expire_str}",
                    remediation="Немедленно обновите TLS-сертификат.",
                    reproduction=f"echo | openssl s_client -connect {host}:{port} 2>/dev/null | openssl x509 -noout -dates",
                ))
            elif days_left < 14:
                store.add(Finding(
                    title=f"TLS-сертификат истекает через {int(days_left)} дней",
                    severity=Severity.HIGH,
                    category="TLS/SSL",
                    cwe="CWE-298",
                    description=f"Срок действия сертификата заканчивается: {expire_str}.",
                    url=base_url,
                    evidence=f"notAfter: {expire_str}",
                    remediation="Обновите сертификат в ближайшее время.",
                    reproduction=f"echo | openssl s_client -connect {host}:{port} 2>/dev/null | openssl x509 -noout -dates",
                ))
    except ssl.SSLCertVerificationError:
        store.add(Finding(
            title="Ошибка верификации TLS-сертификата",
            severity=Severity.HIGH,
            category="TLS/SSL",
            cwe="CWE-295",
            description=(
                "Python не смог верифицировать TLS-сертификат сервера. "
                "Возможные причины: самоподписанный, истёкший, несоответствие hostname или недоверенный CA."
            ),
            url=base_url,
            evidence="ssl.SSLCertVerificationError",
            remediation="Установите валидный сертификат от доверенного CA.",
            reproduction=f"curl -v 'https://{host}:{port}/' 2>&1 | grep -i 'ssl\\|cert\\|verify'",
        ))
    except Exception:
        pass


def _check_mixed_content(session, base_url, curl_auth, store):
    if not base_url.startswith("https://"):
        return
    try:
        resp = session.get(base_url, timeout=10)
        # Look for http:// resources in HTTPS page
        http_resources = re.findall(
            r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']',
            resp.text, re.IGNORECASE,
        )
        if http_resources:
            store.add(Finding(
                title="Mixed Content — HTTP-ресурсы на HTTPS-странице",
                severity=Severity.MEDIUM,
                category="TLS/SSL",
                cwe="CWE-311",
                description=(
                    "HTTPS-страница загружает ресурсы по HTTP. "
                    "Браузеры блокируют активный mixed content. "
                    "Пассивный mixed content может быть перехвачен MITM-атакой."
                ),
                url=base_url,
                evidence=f"Найдено {len(http_resources)} HTTP-ресурсов:\n" + "\n".join(http_resources[:5]),
                remediation=(
                    "1. Замените все http:// ссылки на https://.\n"
                    "2. Используйте protocol-relative URLs (//example.com/resource).\n"
                    "3. Включите CSP upgrade-insecure-requests."
                ),
                reproduction=f"curl -sk '{base_url}' | grep -oE 'src=\"http://[^\"]+\"' | head -10",
            ))
    except Exception:
        pass
