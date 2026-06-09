"""Resilient, self-throttling HTTP session.

Built for long unattended scans against targets behind antifraud / WAF where:
  * hammering triggers IP/session bans,
  * the authenticated session expires mid-scan.

`ResilientSession` is a drop-in `requests.Session` subclass: every check in the
toolkit already routes through `session.request()`, so wrapping that one method
gives the whole scanner global rate-limiting and ban/expiry detection for free.

Control flow:
  * Transient blocks (429/503) are retried with `Retry-After`-aware backoff.
  * A run of consecutive blocks triggers an automatic cool-down pause.
  * If blocks persist past the hard limit, or the auth session expires, a
    `ScanAborted` is raised. It subclasses `BaseException` on purpose so the
    checks' broad `except Exception` does NOT swallow it — the orchestrator
    catches it, checkpoints progress, and stops cleanly.
"""
from __future__ import annotations

import random
import re
import threading
import time
from typing import Optional
from urllib.parse import urlparse

import requests


class ScanAborted(BaseException):
    """Raised when the session can no longer make useful requests.

    `reason` is one of "ban" | "session-expired". Subclasses BaseException so
    it propagates past `except Exception` blocks inside check modules."""

    def __init__(self, reason: str, message: str):
        self.reason = reason
        super().__init__(message)


# Body markers that typically mean "you've been blocked", not a real 403/429.
_BLOCK_BODY_RE = re.compile(
    r"(access denied|request blocked|you have been blocked|are you a robot|"
    r"verify you are human|captcha|cf-error|cloudflare|incident id|"
    r"unusual traffic|rate ?limit|too many requests|akamai|imperva|"
    r"web application firewall|forbidden by administrative rules)",
    re.IGNORECASE,
)

# Path/redirect markers that mean "you got bounced to a login screen".
_LOGIN_PATH_RE = re.compile(
    r"(/login|/signin|/sign-in|/sso|/oauth|/auth/|/account/login|"
    r"/session/new|/authenticate|returnurl=|redirect_uri=|/adfs/)",
    re.IGNORECASE,
)


class ResilientSession(requests.Session):
    def __init__(
        self,
        delay: float = 0.5,
        jitter: float = 0.5,
        max_retries: int = 3,
        ban_pause: float = 30.0,
        ban_pause_max: float = 300.0,
        ban_block_threshold: int = 5,
        ban_hard_limit: int = 3,
        detect_session_expiry: bool = True,
        verbose: bool = False,
    ):
        super().__init__()
        # Pacing
        self.delay = max(0.0, delay)
        self.jitter = max(0.0, jitter)
        self.max_retries = max(0, max_retries)
        # Ban handling
        self.ban_pause = ban_pause
        self.ban_pause_max = ban_pause_max
        self.ban_block_threshold = ban_block_threshold  # consecutive blocks → cool-down
        self.ban_hard_limit = ban_hard_limit            # cool-downs that didn't help → abort
        self.detect_session_expiry = detect_session_expiry
        self.verbose = verbose

        # Set once auth is configured, so we only flag expiry when we *had* a session.
        self.auth_configured = False

        # Shared pacing/ban state (thread-safe — checks may run concurrently).
        self._lock = threading.Lock()
        self._next_start = 0.0
        self._consecutive_blocks = 0
        self._cooldowns_used = 0

        # Counters surfaced in the report meta.
        self.stats = {"requests": 0, "retries": 0, "blocks": 0, "cooldowns": 0}

    # ── Public state ─────────────────────────────────────────────────────────

    def mark_auth_configured(self) -> None:
        self.auth_configured = True

    # ── Pacing ───────────────────────────────────────────────────────────────

    def _throttle(self) -> None:
        """Globally space out request *starts*. Sleeping under the lock spaces
        starts even when many worker threads call concurrently; the actual HTTP
        I/O happens after the lock is released, so requests still overlap."""
        if self.delay == 0 and self.jitter == 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._next_start - now
            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()
            interval = self.delay + random.uniform(0, self.jitter)
            self._next_start = max(now, self._next_start) + interval

    # ── Detection helpers ──────────────────────────────────────────────────

    @staticmethod
    def _looks_blocked(resp: requests.Response) -> bool:
        if resp.status_code in (429, 503):
            return True
        if resp.status_code == 403:
            try:
                body = resp.text[:4000]
            except Exception:
                body = ""
            # A plain 403 on a protected path is normal; a 403 that reads like a
            # WAF/anti-bot interstitial is a block.
            return bool(_BLOCK_BODY_RE.search(body))
        return False

    def _is_session_expired(self, resp: requests.Response, requested_url: str) -> bool:
        if not (self.detect_session_expiry and self.auth_configured):
            return False
        # We never flag the login flow itself as "expired".
        if _LOGIN_PATH_RE.search(urlparse(requested_url).path):
            return False
        if resp.status_code == 401:
            return True
        # Redirected to a login screen (works whether or not redirects followed).
        chain = list(resp.history) + [resp]
        for r in chain:
            loc = r.headers.get("Location", "")
            if r.is_redirect and loc and _LOGIN_PATH_RE.search(loc):
                return True
        if resp.history and _LOGIN_PATH_RE.search(urlparse(resp.url).path):
            return True
        return False

    # ── Core override ──────────────────────────────────────────────────────

    def request(self, method, url, **kwargs):  # type: ignore[override]
        attempt = 0
        while True:
            self._throttle()
            resp = super().request(method, url, **kwargs)
            with self._lock:
                self.stats["requests"] += 1

            # Transient block → backoff and retry the same request.
            if resp.status_code in (429, 503) and attempt < self.max_retries:
                attempt += 1
                with self._lock:
                    self.stats["retries"] += 1
                self._backoff_sleep(resp, attempt)
                continue

            self._evaluate(resp, url)
            return resp

    def _backoff_sleep(self, resp: requests.Response, attempt: int) -> None:
        retry_after = resp.headers.get("Retry-After", "")
        wait: float
        if retry_after.isdigit():
            wait = float(retry_after)
        else:
            wait = min(self.ban_pause_max, (2 ** attempt) + random.uniform(0, 1))
        if self.verbose:
            print(f"  [~] {resp.status_code} on {resp.url} — backoff {wait:.1f}s "
                  f"(retry {attempt}/{self.max_retries})")
        time.sleep(wait)

    def _evaluate(self, resp: requests.Response, url: str) -> None:
        """Update ban state and check for session expiry. May raise ScanAborted."""
        if self._is_session_expired(resp, url):
            raise ScanAborted(
                "session-expired",
                f"Сессия истекла (HTTP {resp.status_code} / redirect на логин) при запросе {url}. "
                "Обновите cookie/токен и продолжите с --resume.",
            )

        if self._looks_blocked(resp):
            with self._lock:
                self._consecutive_blocks += 1
                self.stats["blocks"] += 1
                blocks = self._consecutive_blocks
            if blocks >= self.ban_block_threshold:
                self._enter_cooldown(resp)
        else:
            with self._lock:
                self._consecutive_blocks = 0

    def _enter_cooldown(self, resp: requests.Response) -> None:
        with self._lock:
            self._cooldowns_used += 1
            self.stats["cooldowns"] += 1
            cooldowns = self._cooldowns_used
            self._consecutive_blocks = 0  # reset; give it a fresh chance after the pause

        if cooldowns > self.ban_hard_limit:
            raise ScanAborted(
                "ban",
                f"Антифрод/WAF продолжает блокировать после {self.ban_hard_limit} пауз "
                f"(последний статус {resp.status_code}). Остановка. "
                "Смените IP/подождите и продолжите с --resume.",
            )

        pause = min(self.ban_pause_max, self.ban_pause * (2 ** (cooldowns - 1)))
        print(f"  [!] Похоже на блокировку (антифрод/WAF). Пауза {pause:.0f}с "
              f"для остывания [{cooldowns}/{self.ban_hard_limit}]...")
        time.sleep(pause)
