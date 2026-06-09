from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
import uuid


# OWASP Top 10 2021 — maps category keyword → (OWASP ID, short label)
OWASP_CATEGORY_MAP: dict[str, tuple[str, str]] = {
    "Injection":               ("A03:2021", "Injection"),
    "XSS":                     ("A03:2021", "Injection"),
    "SSRF":                    ("A10:2021", "SSRF"),
    "CORS":                    ("A05:2021", "Security Misconfiguration"),
    "Security Headers":        ("A05:2021", "Security Misconfiguration"),
    "Authentication":          ("A07:2021", "Auth & Identification Failures"),
    "Session Management":      ("A07:2021", "Auth & Identification Failures"),
    "CSRF":                    ("A01:2021", "Broken Access Control"),
    "IDOR":                    ("A01:2021", "Broken Access Control"),
    "BOLA":                    ("A01:2021", "Broken Access Control"),
    "Open Redirect":           ("A01:2021", "Broken Access Control"),
    "Information Disclosure":  ("A02:2021", "Cryptographic Failures"),
    "SSL/TLS":                 ("A02:2021", "Cryptographic Failures"),
    "Rate Limiting":           ("A05:2021", "Security Misconfiguration"),
    "Access Control":          ("A01:2021", "Broken Access Control"),
    "XXE":                     ("A03:2021", "Injection"),
    "Host Header":             ("A05:2021", "Security Misconfiguration"),
    "Host Injection":          ("A05:2021", "Security Misconfiguration"),
}

OWASP_FULL_NAMES: dict[str, str] = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable & Outdated Components",
    "A07:2021": "Identification & Authentication Failures",
    "A08:2021": "Software & Data Integrity Failures",
    "A09:2021": "Security Logging & Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def weight(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]

    @property
    def color(self) -> str:
        return {
            "CRITICAL": "\033[91m",
            "HIGH":     "\033[31m",
            "MEDIUM":   "\033[33m",
            "LOW":      "\033[34m",
            "INFO":     "\033[36m",
        }[self.value]

    @property
    def html_class(self) -> str:
        return {
            "CRITICAL": "critical",
            "HIGH":     "high",
            "MEDIUM":   "medium",
            "LOW":      "low",
            "INFO":     "info",
        }[self.value]


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    url: str
    remediation: str
    reproduction: str          # curl command or step-by-step
    evidence: str = ""
    parameter: str = ""
    method: str = "GET"
    request_snippet: str = ""
    response_snippet: str = ""
    category: str = ""
    cwe: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    # ── Adaptive confirmation metadata ───────────────────────────────────
    # "confirmed"           — deterministic check, no follow-up needed (default)
    # "unverified"          — weak signal that couldn't be confirmed automatically
    # "confirmed-deep-dive" — weak signal that the adaptive pass actively verified
    status: str = "confirmed"
    confidence: float = 1.0
    verification_log: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    # Candidate kind that produced this finding (e.g. "ssrf", "disclosure"), or ""
    # for deterministic findings — lets later phases (chains.py) dispatch on the
    # underlying technique without fragile title/category string-matching.
    kind: str = ""
    # Target hostname/URL — set automatically in multi-domain scans
    target: str = ""

    @property
    def owasp(self) -> tuple[str, str]:
        """Return (OWASP ID, short name) derived from category."""
        for key, pair in OWASP_CATEGORY_MAP.items():
            if key.lower() in self.category.lower():
                return pair
        return ("A05:2021", "Security Misconfiguration")


@dataclass
class DiscardedCandidate:
    """A weak-signal candidate that the adaptive pass actively refuted.
    Kept only for the report's transparency appendix — never becomes a Finding."""
    title: str
    kind: str
    reason: str


class FindingStore:
    def __init__(self):
        self._findings: list[Finding] = []
        self._candidates: list[Any] = []   # list[adaptive.Candidate], kept as Any to avoid an import cycle
        self._discarded: list[DiscardedCandidate] = []

    def add(self, finding: Finding) -> None:
        self._findings.append(finding)

    def add_candidate(self, candidate: Any) -> None:
        self._candidates.append(candidate)

    def pop_candidates(self) -> list[Any]:
        candidates, self._candidates = self._candidates, []
        return candidates

    def add_discarded(self, discarded: DiscardedCandidate) -> None:
        self._discarded.append(discarded)

    def discarded(self) -> list[DiscardedCandidate]:
        return self._discarded

    def all(self) -> list[Finding]:
        return sorted(self._findings, key=lambda f: f.severity.weight, reverse=True)

    def by_severity(self, sev: Severity) -> list[Finding]:
        return [f for f in self._findings if f.severity == sev]

    def counts(self) -> dict[str, int]:
        return {s.value: len(self.by_severity(s)) for s in Severity}

    def owasp_counts(self) -> dict[str, int]:
        """Return {owasp_id: count} across all findings."""
        result: dict[str, int] = {}
        for f in self._findings:
            oid = f.owasp[0]
            result[oid] = result.get(oid, 0) + 1
        return result

    def targets(self) -> list[str]:
        """Return sorted list of unique target values (non-empty only)."""
        return sorted({f.target for f in self._findings if f.target})

    def __len__(self) -> int:
        return len(self._findings)
