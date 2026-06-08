from __future__ import annotations
import json
import sys
import http.cookiejar
from pathlib import Path
from typing import Optional
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 15
DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def build_session(
    cookie_string: Optional[str] = None,
    cookie_file: Optional[str] = None,
    token: Optional[str] = None,
    basic_auth: Optional[str] = None,
    extra_headers: Optional[list[str]] = None,
    proxy: Optional[str] = None,
    verify_ssl: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
) -> requests.Session:
    session = requests.Session()
    session.verify = verify_ssl
    session.timeout = timeout  # type: ignore[attr-defined]  # stored for modules to read

    session.headers.update({"User-Agent": DEFAULT_UA})

    if extra_headers:
        for h in extra_headers:
            if ":" in h:
                k, v = h.split(":", 1)
                session.headers[k.strip()] = v.strip()

    if token:
        t = token.strip()
        if not t.lower().startswith("bearer "):
            t = f"Bearer {t}"
        session.headers["Authorization"] = t

    if basic_auth and ":" in basic_auth:
        user, pwd = basic_auth.split(":", 1)
        session.auth = (user, pwd)

    if cookie_string:
        for pair in cookie_string.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                session.cookies.set(k.strip(), v.strip())

    if cookie_file:
        _load_cookie_file(session, cookie_file)

    if proxy:
        proxies = {"http": proxy, "https": proxy}
        session.proxies.update(proxies)

    return session


def _load_cookie_file(session: requests.Session, path: str) -> None:
    p = Path(path)
    if not p.exists():
        print(f"[!] Cookie file not found: {path}", file=sys.stderr)
        return

    content = p.read_text(encoding="utf-8").strip()

    # Try JSON format first (e.g., from EditThisCookie extension)
    if content.startswith("["):
        try:
            cookies = json.loads(content)
            for c in cookies:
                name = c.get("name") or c.get("Name")
                value = c.get("value") or c.get("Value", "")
                domain = c.get("domain") or c.get("Domain", "")
                session.cookies.set(name, value, domain=domain)
            return
        except json.JSONDecodeError:
            pass

    # Try JSON object (single cookie or dict of name->value)
    if content.startswith("{"):
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                for k, v in data.items():
                    session.cookies.set(k, str(v))
            return
        except json.JSONDecodeError:
            pass

    # Try Netscape cookie jar format
    try:
        jar = http.cookiejar.MozillaCookieJar(path)
        jar.load(ignore_discard=True, ignore_expires=True)
        for cookie in jar:
            session.cookies.set(cookie.name, cookie.value, domain=cookie.domain)
        return
    except Exception:
        pass

    # Fallback: treat as raw "name=value; name2=value2" string
    for pair in content.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            session.cookies.set(k.strip(), v.strip())


def session_to_curl_flags(session: requests.Session) -> str:
    """Return curl flags representing the session auth for reproduction steps."""
    flags = []
    cookie_parts = [f"{k}={v}" for k, v in session.cookies.items()]
    if cookie_parts:
        flags.append(f'-b "{"; ".join(cookie_parts)}"')
    for k, v in session.headers.items():
        if k.lower() in ("authorization", "x-api-key", "x-auth-token"):
            flags.append(f'-H "{k}: {v}"')
    if session.auth:
        flags.append(f"-u '{session.auth[0]}:{session.auth[1]}'")
    if session.proxies:
        proxy = next(iter(session.proxies.values()))
        flags.append(f"-x '{proxy}'")
    return " ".join(flags)
