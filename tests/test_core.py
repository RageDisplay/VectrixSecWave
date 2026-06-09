"""Unit tests for the resilience / dedup / scope logic added for unattended
bank-domain scanning. Pure-logic only — no network. Run with:

    python -m unittest discover -s tests
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import requests

from modules.findings import Finding, FindingStore, Severity, _fingerprint
from modules.crawler import Crawler
from modules.checkpoint import Checkpoint
from modules.resilient import ResilientSession


def _finding(title="T", url="https://h/a", sev=Severity.LOW, **kw):
    return Finding(
        title=title, severity=sev, description="d", url=url,
        remediation="r", reproduction="c", **kw,
    )


def _resp(status, url="https://h/a", body="", headers=None, history=None):
    r = requests.Response()
    r.status_code = status
    r.url = url
    r._content = body.encode()
    r.headers.update(headers or {})
    r.history = history or []
    return r


class DedupTests(unittest.TestCase):
    def test_exact_duplicate_collapses(self):
        s = FindingStore()
        s.add(_finding(evidence="e1"))
        s.add(_finding(evidence="e2"))
        self.assertEqual(len(s), 1)
        self.assertIn("e1", s.all()[0].evidence)
        self.assertIn("e2", s.all()[0].evidence)

    def test_higher_severity_wins_on_merge(self):
        s = FindingStore()
        s.add(_finding(sev=Severity.LOW, confidence=0.4))
        s.add(_finding(sev=Severity.HIGH, confidence=0.9))
        self.assertEqual(len(s), 1)
        self.assertEqual(s.all()[0].severity, Severity.HIGH)
        self.assertEqual(s.all()[0].confidence, 0.9)

    def test_different_target_not_merged(self):
        s = FindingStore()
        s.add(_finding(url="https://a/x"))
        s.add(_finding(url="https://b/x"))
        self.assertEqual(len(s), 2)

    def test_fingerprint_ignores_trailing_slash(self):
        self.assertEqual(
            _fingerprint(_finding(url="https://h/a/")),
            _fingerprint(_finding(url="https://h/a")),
        )


class CrawlerScopeTests(unittest.TestCase):
    def setUp(self):
        self.c = Crawler(session=None, base_url="https://h", exclude_patterns=[r"/secret"])

    def test_logout_excluded_by_default(self):
        self.assertTrue(self.c._is_excluded("https://h/account/logout"))
        self.assertTrue(self.c._is_excluded("https://h/users/1/delete"))

    def test_user_pattern_excluded(self):
        self.assertTrue(self.c._is_excluded("https://h/secret/area"))

    def test_password_reset_not_excluded(self):
        # hostinjection check relies on these staying in scope
        self.assertFalse(self.c._is_excluded("https://h/reset-password"))
        self.assertFalse(self.c._is_excluded("https://h/forgot-password"))

    def test_normal_path_allowed(self):
        self.assertFalse(self.c._is_excluded("https://h/api/users"))


class ResilientDetectionTests(unittest.TestCase):
    def setUp(self):
        self.s = ResilientSession(delay=0, jitter=0)
        self.s.mark_auth_configured()

    def test_block_body_on_403(self):
        self.assertTrue(self.s._looks_blocked(_resp(403, body="Access Denied by Cloudflare")))
        self.assertFalse(self.s._looks_blocked(_resp(403, body="You are not authorized")))

    def test_429_always_block(self):
        self.assertTrue(self.s._looks_blocked(_resp(429)))

    def test_session_expiry_on_401(self):
        self.assertTrue(self.s._is_session_expired(_resp(401), "https://h/api/data"))

    def test_session_expiry_on_login_redirect(self):
        hist = [_resp(302, url="https://h/api/data", headers={"Location": "https://h/login"})]
        hist[0].status_code = 302
        final = _resp(200, url="https://h/login", history=hist)
        self.assertTrue(self.s._is_session_expired(final, "https://h/api/data"))

    def test_login_page_itself_not_flagged(self):
        # requesting the login page is normal, not an expiry
        self.assertFalse(self.s._is_session_expired(_resp(401), "https://h/login"))

    def test_no_expiry_without_auth(self):
        s = ResilientSession(delay=0, jitter=0)  # auth NOT configured
        self.assertFalse(s._is_session_expired(_resp(401), "https://h/api/data"))


class CheckpointTests(unittest.TestCase):
    def test_resume_skips_completed(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            targets = ["https://a", "https://b", "https://c"]
            ck = Checkpoint(out, "medium")
            ck.reset(targets)
            ck.mark_done("https://a", targets)

            ck2 = Checkpoint(out, "medium")
            ck2.load()
            self.assertEqual(ck2.pending(targets), ["https://b", "https://c"])

    def test_clear_removes_state(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            ck = Checkpoint(out, "safe")
            ck.reset(["https://a"])
            self.assertTrue(ck.path.exists())
            ck.clear()
            self.assertFalse(ck.path.exists())


if __name__ == "__main__":
    unittest.main()
