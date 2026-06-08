from __future__ import annotations
import re
import sys
from collections import deque
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import requests
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: dict = field(default_factory=dict)
    body_params: dict = field(default_factory=dict)
    content_type: str = ""
    source: str = "crawl"     # crawl | wordlist | js | form

    @property
    def parsed(self):
        return urlparse(self.url)

    @property
    def base_url(self) -> str:
        p = self.parsed
        return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))

    def __hash__(self):
        return hash((self.url, self.method))

    def __eq__(self, other):
        return self.url == other.url and self.method == other.method


INTERESTING_PATHS = [
    # APIs & Docs
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/health", "/api/status",
    "/swagger", "/swagger-ui.html", "/swagger-ui/", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/api/docs", "/graphql",
    "/graphiql", "/.well-known/openapi", "/redoc",
    # Admin
    "/admin", "/admin/", "/administrator", "/manage", "/management",
    "/dashboard", "/console", "/panel",
    # Auth
    "/login", "/logout", "/auth", "/oauth", "/token", "/refresh",
    "/api/login", "/api/auth", "/api/token", "/api/refresh",
    "/forgot-password", "/reset-password", "/register", "/signup",
    # Debug / internal
    "/debug", "/health", "/ping", "/status", "/metrics", "/info",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/metrics",
    "/actuator/beans", "/actuator/mappings", "/actuator/trace",
    "/env", "/trace", "/beans", "/mappings",
    # Config / secrets
    "/.env", "/.git/config", "/.git/HEAD", "/.svn/entries",
    "/config.json", "/config.yaml", "/config.yml",
    "/web.config", "/.htaccess", "/robots.txt", "/sitemap.xml",
    "/server-status", "/server-info",
    # Upload / files
    "/upload", "/uploads", "/files", "/file", "/download", "/media",
    # Backups
    "/backup", "/backups", "/db", "/database",
    "/app.zip", "/app.tar.gz", "/backup.zip", "/www.zip",
    # Errors (to check verbose output)
    "/nonexistent-page-pentest-check",
]

JS_URL_PATTERN = re.compile(
    r'(?:url|href|src|action|endpoint|api)["\s]*[:=]["\s]*'
    r'["\']([/][^"\'<>\s]{2,})["\']',
    re.IGNORECASE,
)


class Crawler:
    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 200,
        same_domain: bool = True,
        verbose: bool = False,
    ):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.same_domain = same_domain
        self.verbose = verbose
        self._parsed_base = urlparse(self.base_url)
        self._visited: set[str] = set()
        self.endpoints: list[Endpoint] = []

    @property
    def _base_host(self) -> str:
        return self._parsed_base.netloc

    def _is_same_domain(self, url: str) -> bool:
        return urlparse(url).netloc == self._base_host

    def _normalise_url(self, url: str, source_url: str = "") -> Optional[str]:
        url = url.strip()
        if not url or url.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return None
        full = urljoin(source_url or self.base_url, url)
        parsed = urlparse(full)
        if parsed.scheme not in ("http", "https"):
            return None
        if self.same_domain and not self._is_same_domain(full):
            return None
        # Drop fragment
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, parsed.query, ""))

    def crawl(self) -> list[Endpoint]:
        print(f"[*] Crawling {self.base_url} (depth={self.max_depth}, max={self.max_pages})")
        queue: deque[tuple[str, int]] = deque()
        queue.append((self.base_url, 0))
        self._visited.add(self.base_url)

        while queue and len(self._visited) < self.max_pages:
            url, depth = queue.popleft()
            self._process_page(url, depth, queue)

        self._probe_interesting_paths()
        print(f"[*] Crawl complete. Discovered {len(self.endpoints)} endpoints.")
        return self.endpoints

    def _process_page(self, url: str, depth: int, queue: deque) -> None:
        try:
            resp = self.session.get(url, timeout=getattr(self.session, 'timeout', 15),
                                    allow_redirects=True)
        except Exception as e:
            if self.verbose:
                print(f"  [!] GET {url} -> {e}", file=sys.stderr)
            return

        status = resp.status_code
        ct = resp.headers.get("content-type", "").lower()

        if self.verbose:
            print(f"  [{status}] {url}")

        # Add as endpoint (with query params parsed)
        parsed = urlparse(url)
        qparams = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        ep = Endpoint(url=url, method="GET", params=qparams, source="crawl")
        if ep not in self.endpoints:
            self.endpoints.append(ep)

        if depth >= self.max_depth:
            return
        if "text/" not in ct and "javascript" not in ct:
            return

        text = resp.text

        # Extract URLs from HTML
        if BS4_AVAILABLE and "html" in ct:
            soup = BeautifulSoup(text, "html.parser")
            self._extract_links(soup, url, depth, queue)
            self._extract_forms(soup, url)
        elif "html" in ct:
            self._extract_links_regex(text, url, depth, queue)

        # Extract URLs from JS
        if "javascript" in ct or url.endswith(".js"):
            self._extract_from_js(text, url)

    def _extract_links(self, soup, source_url: str, depth: int, queue: deque) -> None:
        tags = soup.find_all(["a", "link", "script", "img", "form"],
                             href=True) + soup.find_all(src=True)
        for tag in soup.find_all(["a"]):
            href = tag.get("href", "")
            norm = self._normalise_url(href, source_url)
            if norm and norm not in self._visited:
                self._visited.add(norm)
                queue.append((norm, depth + 1))

        for tag in soup.find_all("script", src=True):
            src = tag.get("src", "")
            norm = self._normalise_url(src, source_url)
            if norm and norm not in self._visited:
                self._visited.add(norm)
                queue.append((norm, depth + 1))

    def _extract_links_regex(self, text: str, source_url: str, depth: int, queue: deque) -> None:
        for href in re.findall(r'href=["\']([^"\']+)["\']', text):
            norm = self._normalise_url(href, source_url)
            if norm and norm not in self._visited:
                self._visited.add(norm)
                queue.append((norm, depth + 1))

    def _extract_forms(self, soup, source_url: str) -> None:
        for form in soup.find_all("form"):
            action = form.get("action", source_url)
            method = (form.get("method", "GET")).upper()
            url = self._normalise_url(action, source_url) or source_url

            body_params: dict[str, str] = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    body_params[name] = inp.get("value", "test")

            ep = Endpoint(
                url=url, method=method,
                body_params=body_params, source="form",
            )
            if ep not in self.endpoints:
                self.endpoints.append(ep)

    def _extract_from_js(self, text: str, source_url: str) -> None:
        for match in JS_URL_PATTERN.finditer(text):
            path = match.group(1)
            norm = self._normalise_url(path, source_url)
            if norm and not any(e.url == norm for e in self.endpoints):
                self.endpoints.append(Endpoint(url=norm, source="js"))

    def _probe_interesting_paths(self) -> None:
        base = self.base_url
        for path in INTERESTING_PATHS:
            url = base + path
            if any(e.url == url for e in self.endpoints):
                continue
            try:
                resp = self.session.get(url, timeout=8, allow_redirects=False)
                if resp.status_code not in (404, 410):
                    self.endpoints.append(Endpoint(
                        url=url, method="GET",
                        source="wordlist",
                    ))
                    if self.verbose:
                        print(f"  [+] Found: [{resp.status_code}] {url}")
            except Exception:
                pass
