from enum import IntEnum
from dataclasses import dataclass, field
from typing import Optional


class Severity(IntEnum):
    OK = 0
    NOTE = 1      # informational note, not an issue (e.g. duplicate header)
    INFO = 2
    LOW = 3
    MEDIUM = 4
    HIGH = 5
    CRITICAL = 6


SEVERITY_COLORS = {
    Severity.OK: "green",
    Severity.NOTE: "blue",
    Severity.INFO: "cyan",
    Severity.LOW: "yellow",
    Severity.MEDIUM: "dark_orange",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}

SEVERITY_LABELS = {
    Severity.OK: "OK",
    Severity.NOTE: "NOTE",
    Severity.INFO: "INFO",
    Severity.LOW: "LOW",
    Severity.MEDIUM: "MEDIUM",
    Severity.HIGH: "HIGH",
    Severity.CRITICAL: "CRITICAL",
}

SEVERITY_SYMBOLS = {
    Severity.OK: "✓",
    Severity.NOTE: "•",
    Severity.INFO: "ℹ",
    Severity.LOW: "⚠",
    Severity.MEDIUM: "⚠",
    Severity.HIGH: "✗",
    Severity.CRITICAL: "✗",
}


@dataclass
class Finding:
    header: str
    severity: Severity
    title: str
    description: str = ""
    recommendation: str = ""


@dataclass
class HeaderResult:
    name: str           # lowercase key
    canonical_name: str # display name
    value: Optional[str]
    findings: list[Finding] = field(default_factory=list)

    @property
    def is_present(self) -> bool:
        return self.value is not None

    @property
    def worst_severity(self) -> Severity:
        if not self.findings:
            return Severity.OK
        return max(f.severity for f in self.findings)
