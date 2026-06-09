from __future__ import annotations
import os
import subprocess
import sys
import shutil
import json
import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse
import requests

from .findings import Finding, Severity
from .session import session_to_curl_flags


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: list[str], timeout: int = 120) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", 1
    except subprocess.TimeoutExpired:
        return "", f"Timeout: {cmd}", 1


def run_all_tools(session: requests.Session, base_url: str, store) -> list[str]:
    print("[*] Running external Kali tools...")
    cookie_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
    auth_header = session.headers.get("Authorization", "")

    tech_names = _run_whatweb(base_url, cookie_str, auth_header, store)
    _run_wafw00f(base_url, store)
    _run_nikto(base_url, cookie_str, auth_header, store)
    _run_nuclei(base_url, cookie_str, auth_header, store)
    return tech_names


_WHATWEB_TECH_RE = re.compile(r"([A-Za-z][\w\-.]*)\[")


def _run_whatweb(base_url, cookie_str, auth_header, store) -> list[str]:
    if not _tool_available("whatweb"):
        return []
    print("  [*] whatweb — технология...")
    cmd = ["whatweb", "--colour=never", "-a", "3", base_url]
    if cookie_str:
        cmd += ["--cookie", cookie_str]
    stdout, stderr, rc = _run(cmd, timeout=60)

    tech_names: list[str] = []
    if stdout.strip():
        tech_names = sorted({m.lower() for m in _WHATWEB_TECH_RE.findall(stdout)})
        store.add(Finding(
            title="Обнаружение технологий (whatweb)",
            severity=Severity.INFO,
            category="Reconnaissance",
            cwe="",
            description="Результаты fingerprinting технологий приложения.",
            url=base_url,
            evidence=stdout.strip()[:1000],
            remediation=(
                "Скройте информацию о серверном ПО и версиях:\n"
                "Server: ; X-Powered-By: (удалить или обобщить)"
            ),
            reproduction=f"whatweb --colour=never -a 3 '{base_url}'",
        ))
    return tech_names


def _run_wafw00f(base_url, store):
    if not _tool_available("wafw00f"):
        return
    print("  [*] wafw00f — WAF detection...")
    stdout, stderr, rc = _run(["wafw00f", base_url, "--format", "json"], timeout=30)

    if not stdout.strip():
        return

    try:
        data = json.loads(stdout)
        for entry in data if isinstance(data, list) else [data]:
            firewall = entry.get("firewall") or entry.get("waf")
            detected = entry.get("detected", False)
            if firewall and detected:
                store.add(Finding(
                    title=f"WAF обнаружен: {firewall}",
                    severity=Severity.INFO,
                    category="Reconnaissance",
                    cwe="",
                    description=(
                        f"Web Application Firewall '{firewall}' обнаружен перед приложением. "
                        "WAF может блокировать некоторые векторы атак, но не заменяет secure coding."
                    ),
                    url=base_url,
                    evidence=f"wafw00f: {firewall}",
                    remediation="",
                    reproduction=f"wafw00f '{base_url}'",
                ))
            elif not detected:
                store.add(Finding(
                    title="WAF не обнаружен",
                    severity=Severity.LOW,
                    category="Reconnaissance",
                    cwe="",
                    description="wafw00f не обнаружил WAF. Приложение может быть напрямую доступно без дополнительного защитного экрана.",
                    url=base_url,
                    evidence="wafw00f: no WAF detected",
                    remediation="Рассмотрите развёртывание WAF (ModSecurity, AWS WAF, CloudFlare) как дополнительный уровень защиты.",
                    reproduction=f"wafw00f '{base_url}'",
                ))
    except json.JSONDecodeError:
        # Plain text output
        if "no waf" in stdout.lower() or "not detected" in stdout.lower():
            store.add(Finding(
                title="WAF не обнаружен",
                severity=Severity.LOW,
                category="Reconnaissance",
                cwe="",
                description="Приложение не защищено WAF.",
                url=base_url,
                evidence=stdout.strip()[:200],
                remediation="Рассмотрите развёртывание WAF.",
                reproduction=f"wafw00f '{base_url}'",
            ))


def _run_nikto(base_url, cookie_str, auth_header, store):
    if not _tool_available("nikto"):
        return
    print("  [*] nikto — веб-сканер...")
    parsed = urlparse(base_url)
    host = parsed.hostname
    port = str(parsed.port or (443 if parsed.scheme == "https" else 80))
    ssl_flag = ["-ssl"] if parsed.scheme == "https" else []

    cmd = [
        "nikto", "-host", host, "-port", port,
        "-nointeractive", "-Format", "csv",
        "-Tuning", "x6",  # Skip DoS tests, focus on interesting findings
    ] + ssl_flag

    if cookie_str:
        cmd += ["-cookies", cookie_str]
    if auth_header:
        cmd += ["-useragent", f"Mozilla/5.0 -auth-token {auth_header[:50]}"]

    print(f"  [*] nikto запущен (может занять 2-5 минут)...")
    stdout, stderr, rc = _run(cmd, timeout=300)

    # Parse CSV output from nikto
    finding_count = 0
    for line in stdout.split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("host,"):
            continue
        # CSV: hostname,ip,port,vuln_id,vuln_description,...
        parts = line.split(",", 6)
        if len(parts) >= 6:
            vuln_desc = parts[6] if len(parts) > 6 else parts[-1]
            vuln_desc = vuln_desc.strip().strip('"')

            if not vuln_desc or "OSVDB" == vuln_desc:
                continue

            sev = Severity.MEDIUM
            desc_lower = vuln_desc.lower()
            if any(k in desc_lower for k in ("sql", "injection", "rce", "execute")):
                sev = Severity.HIGH
            elif any(k in desc_lower for k in ("xss", "cross-site")):
                sev = Severity.MEDIUM
            elif any(k in desc_lower for k in ("info", "version", "server", "banner")):
                sev = Severity.LOW

            store.add(Finding(
                title=f"Nikto: {vuln_desc[:100]}",
                severity=sev,
                category="Nikto Scan",
                cwe="",
                description=f"Результат сканирования nikto:\n{vuln_desc}",
                url=base_url,
                evidence=f"Nikto CSV: {line[:200]}",
                remediation="Изучите подробности находки и примените соответствующие меры.",
                reproduction=f"nikto -host '{host}' -port {port} {''.join(ssl_flag)}",
            ))
            finding_count += 1

    if finding_count == 0 and stdout:
        # Fallback: extract from plain text output
        for line in stdout.split("\n"):
            if "+ " in line and len(line) > 20:
                line = line.strip()
                if line.startswith("+"):
                    store.add(Finding(
                        title=f"Nikto: {line[2:80]}",
                        severity=Severity.LOW,
                        category="Nikto Scan",
                        cwe="",
                        description=line,
                        url=base_url,
                        evidence=line[:300],
                        remediation="",
                        reproduction=f"nikto -host '{host}' -port {port}",
                    ))


# Maps technology/plugin names (as parsed from whatweb output) to relevant nuclei
# tags — lets the scan focus on templates that actually match the detected stack
# instead of running the same generic CVE pass against every target.
TECH_TO_NUCLEI_TAGS: dict[str, list[str]] = {
    "wordpress": ["wordpress", "wp-plugin"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "grafana": ["grafana"],
    "jira": ["jira", "atlassian"],
    "confluence": ["confluence", "atlassian"],
    "tomcat": ["tomcat", "apache"],
    "spring": ["springboot", "spring"],
    "laravel": ["laravel", "php"],
    "django": ["django", "python"],
    "magento": ["magento"],
    "nginx": ["nginx"],
    "apache": ["apache"],
    "iis": ["iis", "microsoft"],
    "php": ["php"],
}


def _tech_tags(tech_names: list[str]) -> list[str]:
    """Maps detected technology names to nuclei tags, deduplicated, order-preserving."""
    seen: set[str] = set()
    tags: list[str] = []
    for name in tech_names:
        for tag in TECH_TO_NUCLEI_TAGS.get(name, []):
            if tag not in seen:
                seen.add(tag)
                tags.append(tag)
    return tags


def _run_nuclei(base_url, cookie_str, auth_header, store,
                endpoints=None, extra_tags=None, max_targets: int = 30,
                full_tags: bool = True):
    if not _tool_available("nuclei"):
        return
    print("  [*] nuclei — template-based scanner...")

    base_tags = ["cve", "oast", "exposure", "misconfig", "token"] if full_tags \
        else ["cve", "exposure", "misconfig"]
    tags: list[str] = []
    for tag in base_tags + list(extra_tags or []):
        if tag not in tags:
            tags.append(tag)

    targets_file = None
    cmd = [
        "nuclei",
        "-severity", "critical,high,medium",
        "-silent",
        "-json",
        "-timeout", "10",
        "-c", "20",             # 20 concurrent
        "-rl", "50",            # rate limit
        "-tags", ",".join(tags),
        "-no-color",
    ]

    target_urls = [base_url]
    if endpoints:
        seen = {base_url}
        for ep in endpoints:
            ep_url = getattr(ep, "base_url", ep.url)
            if ep_url not in seen:
                seen.add(ep_url)
                target_urls.append(ep_url)
            if len(target_urls) >= max_targets:
                break

    if len(target_urls) > 1:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
            tmp.write("\n".join(target_urls))
            targets_file = tmp.name
        cmd += ["-l", targets_file]
    else:
        cmd += ["-u", base_url]

    if cookie_str:
        cmd += ["-H", f"Cookie: {cookie_str}"]
    if auth_header:
        cmd += ["-H", f"Authorization: {auth_header}"]

    print(f"  [*] nuclei запущен на {len(target_urls)} цел(ях), теги: {','.join(tags)} "
          f"(может занять 5-10 минут)...")
    try:
        stdout, stderr, rc = _run(cmd, timeout=600)
    finally:
        if targets_file:
            try:
                Path(targets_file).unlink()
            except OSError:
                pass

    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        template_id = data.get("template-id", "unknown")
        name = data.get("info", {}).get("name", template_id)
        sev_str = data.get("info", {}).get("severity", "info").upper()
        matched_at = data.get("matched-at", base_url)
        description = data.get("info", {}).get("description", "")
        tags = data.get("info", {}).get("tags", [])
        cve = next((t for t in tags if t.upper().startswith("CVE-")), "")
        remediation = data.get("info", {}).get("remediation", "Изучите шаблон nuclei для деталей.")
        curl_line = data.get("curl-command", "")

        try:
            severity = Severity[sev_str]
        except KeyError:
            severity = Severity.INFO

        store.add(Finding(
            title=f"Nuclei [{template_id}]: {name}",
            severity=severity,
            category="Nuclei",
            cwe=cve or "",
            description=(
                f"{description}\n\n"
                f"Template: {template_id}\n"
                f"Tags: {', '.join(tags)}"
            ),
            url=matched_at,
            evidence=f"nuclei matched: {matched_at}",
            remediation=remediation,
            reproduction=curl_line or f"nuclei -u '{matched_at}' -t {template_id}",
        ))


def run_custom_nuclei_template(session: requests.Session, base_url: str, template_yaml: str,
                               label: str = "") -> list[dict]:
    """Запускает nuclei с динамически сгенерированным шаблоном (адаптивное углубление —
    например, follow-up проверка соседних путей вокруг подтверждённой находки).

    Возвращает разобранные совпадения как сырые dict'ы — решение, как использовать их
    в Finding/Candidate, остаётся за вызывающим кодом (modules/adaptive.py)."""
    if not _tool_available("nuclei"):
        return []

    cookie_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
    auth_header = session.headers.get("Authorization", "")

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tmp:
        tmp.write(template_yaml)
        template_path = tmp.name

    try:
        cmd = [
            "nuclei", "-u", base_url, "-t", template_path,
            "-json", "-silent", "-no-color", "-timeout", "10",
        ]
        if cookie_str:
            cmd += ["-H", f"Cookie: {cookie_str}"]
        if auth_header:
            cmd += ["-H", f"Authorization: {auth_header}"]

        print(f"  [*] nuclei (сгенерированный шаблон{f' для ' + label if label else ''})...")
        stdout, stderr, rc = _run(cmd, timeout=120)
    finally:
        try:
            Path(template_path).unlink()
        except OSError:
            pass

    matches = []
    for line in stdout.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            matches.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return matches


def run_gobuster(session: requests.Session, base_url: str, store) -> list[str]:
    """Run gobuster for directory/endpoint discovery. Returns found URLs."""
    if not _tool_available("gobuster"):
        print("  [!] gobuster not found, skipping directory brute-force")
        return []

    # Pick wordlist available in Kali
    wordlists = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ]
    wordlist = next((w for w in wordlists if os.path.exists(w)), None)
    if not wordlist:
        print("  [!] No wordlist found for gobuster")
        return []

    print(f"  [*] gobuster dir ({wordlist})...")
    cookie_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
    auth_header = session.headers.get("Authorization", "")

    out_fd, out_path = tempfile.mkstemp(prefix="gobuster_", suffix=".txt")
    os.close(out_fd)
    cmd = [
        "gobuster", "dir",
        "-u", base_url,
        "-w", wordlist,
        "-q",                   # quiet
        "-t", "30",             # threads
        "--no-error",
        "-o", out_path,
        "-x", "php,asp,aspx,jsp,json,yaml,xml,bak,old,txt",
        "--timeout", "10s",
    ]

    if cookie_str:
        cmd += ["-c", cookie_str]
    if auth_header:
        cmd += ["-H", f"Authorization: {auth_header}"]

    parsed = urlparse(base_url)
    if parsed.scheme == "https":
        cmd += ["-k"]  # Skip TLS verification

    try:
        _run(cmd, timeout=300)

        # Read results
        found = []
        with open(out_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("["):
                    # Extract URL path from gobuster output
                    m = re.match(r"(/\S+)\s+\(Status: (\d+)\)", line)
                    if m:
                        path = m.group(1)
                        status = int(m.group(2))
                        url = base_url.rstrip("/") + path
                        found.append(url)
                        if status not in (404, 403):
                            store.add(Finding(
                                title=f"Gobuster: обнаружен путь [{status}] {path}",
                                severity=Severity.INFO,
                                category="Directory Enumeration",
                                cwe="",
                                description=f"Gobuster нашёл доступный путь: {path} (HTTP {status})",
                                url=url,
                                evidence=f"HTTP {status}",
                                remediation="Убедитесь что обнаруженные пути не содержат чувствительной информации.",
                                reproduction=f"curl -sk '{url}'",
                            ))
    except FileNotFoundError:
        found = []
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass

    return found


def run_sqlmap(session: requests.Session, url: str, param: str, store) -> None:
    """Deep SQL injection test via sqlmap on a specific parameter."""
    if not _tool_available("sqlmap"):
        return

    cookie_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
    print(f"  [*] sqlmap → {url} (param: {param})")

    out_dir = tempfile.mkdtemp(prefix="sqlmap_")
    cmd = [
        "sqlmap", "-u", url,
        "-p", param,
        "--batch",              # Non-interactive
        "--level", "3",
        "--risk", "2",
        "--timeout", "10",
        "--retries", "2",
        "--output-dir", out_dir,
        "--forms",
        "--crawl=2",
    ]
    if cookie_str:
        cmd += ["--cookie", cookie_str]
    auth = session.headers.get("Authorization", "")
    if auth:
        cmd += ["--headers", f"Authorization: {auth}"]

    stdout, stderr, rc = _run(cmd, timeout=300)

    if "injectable" in stdout.lower() or "sqlmap identified" in stdout.lower():
        store.add(Finding(
            title=f"SQLMap подтвердил SQL Injection: {url} (param: {param})",
            severity=Severity.CRITICAL,
            category="Injection",
            cwe="CWE-89",
            description=(
                f"sqlmap подтвердил SQL-инъекцию в параметре '{param}'.\n"
                f"Полный вывод sqlmap в {out_dir}/"
            ),
            url=url,
            parameter=param,
            evidence=stdout[:500],
            remediation=(
                "1. Параметризованные запросы / Prepared Statements.\n"
                "2. ORM с экранированием.\n"
                "3. Валидация входных данных."
            ),
            reproduction=(
                f"sqlmap -u '{url}' -p '{param}' "
                f"--cookie '{cookie_str}' --batch --dbs"
            ),
        ))
