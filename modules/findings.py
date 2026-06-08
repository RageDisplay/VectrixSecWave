from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
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


class FindingStore:
    def __init__(self):
        self._findings: list[Finding] = []

    def add(self, finding: Finding) -> None:
        self._findings.append(finding)

    def all(self) -> list[Finding]:
        return sorted(self._findings, key=lambda f: f.severity.weight, reverse=True)

    def by_severity(self, sev: Severity) -> list[Finding]:
        return [f for f in self._findings if f.severity == sev]

    def counts(self) -> dict[str, int]:
        return {s.value: len(self.by_severity(s)) for s in Severity}

    def __len__(self) -> int:
        return len(self._findings)
