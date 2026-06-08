from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
import uuid


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

    def __len__(self) -> int:
        return len(self._findings)
