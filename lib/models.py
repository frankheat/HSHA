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


def is_issue(severity: Severity) -> bool:
    """
    Whether a finding counts as a failure.

    INFO and below are informational: they never mark a header as failed and
    never appear in `--format list`. Every output format goes through this
    function, so they cannot drift apart.
    """
    return severity > Severity.INFO


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
    """
    `severity` is what the finding is worth **if it applies** to this target.

    Whether it applies is a separate question, and for some checks the response
    cannot settle it: a policy that leaves the camera open matters unless the page
    uses the camera, and one saved response cannot say. Those findings carry
    `verify` — the check that settles it, and what each outcome means. An empty
    `verify` is the claim that the response is enough on its own.

    A finding therefore has either `verify` or `recommendation`, not both: until
    the check is done there is nothing to recommend.
    """
    header: str
    severity: Severity
    title: str
    description: str = ""
    recommendation: str = ""
    verify: str = ""

    @property
    def is_contingent(self) -> bool:
        return bool(self.verify)


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

    @property
    def is_contingent(self) -> bool:
        """Nothing settled reaches this header's worst severity on its own."""
        worst = self.worst_severity
        return bool(self.findings) and all(
            f.is_contingent for f in self.findings if f.severity == worst
        )
