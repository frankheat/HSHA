"""Tests for the output layer (lib/reporter.py)."""
from lib import reporter
from lib.models import Finding, HeaderResult, Severity


def result(name: str, *findings: Finding, value: str | None = "x") -> HeaderResult:
    return HeaderResult(name=name.lower(), canonical_name=name, value=value,
                        findings=list(findings))


def finding(severity: Severity, title: str = "t", verify: str = "") -> Finding:
    return Finding(header="H", severity=severity, title=title, verify=verify)


def render(results) -> str:
    with reporter.console.capture() as capture:
        reporter.report(results)
    return capture.get()


def test_absent_and_empty_values_are_rendered_distinctly():
    out = render([
        result("X-Frame-Options", finding(Severity.HIGH), value=None),
        result("Referrer-Policy", finding(Severity.HIGH), value=""),
    ])
    assert "not present" in out and "empty" in out


# ---------------------------------------------------------------------------
# Contingent findings — what the response cannot settle on its own
# ---------------------------------------------------------------------------

CHECK = "Does this page do X? If it does, this stands. If it does not, there is nothing here."


def test_contingent_and_settled_findings_are_reported_apart():
    out = render([
        result("Content-Security-Policy", finding(Severity.HIGH, "settled problem")),
        result("Permissions-Policy", finding(Severity.LOW, "depends", verify=CHECK)),
    ])
    assert "Findings" in out and "To confirm" in out
    assert out.index("settled problem") < out.index("To confirm") < out.index("depends")


def flat(out: str) -> str:
    """Rich wraps to the terminal width; assertions are about the text, not the wrap."""
    return " ".join(out.split())


def test_a_contingent_finding_prints_its_check():
    out = render([result("Permissions-Policy", finding(Severity.LOW, "t", verify=CHECK))])
    assert CHECK in flat(out)


def test_a_contingent_header_is_marked_in_the_table():
    """The level is what it is worth if it applies, so the severity symbol would
    overstate it — '?' says nothing settled has reached it."""
    out = render([result("Permissions-Policy", finding(Severity.MEDIUM, verify=CHECK))])
    assert "? MEDIUM" in out


def test_a_header_with_one_settled_finding_is_not_marked():
    out = render([result("Permissions-Policy",
                         finding(Severity.MEDIUM, "settled"),
                         finding(Severity.MEDIUM, "contingent", verify=CHECK))])
    assert "? MEDIUM" not in out


def test_the_summary_counts_the_two_kinds_separately():
    out = render([
        result("Content-Security-Policy", finding(Severity.HIGH)),
        result("Permissions-Policy", finding(Severity.MEDIUM, verify=CHECK)),
    ])
    lines = {line.split(':')[0].strip('│ '): line for line in out.splitlines()
             if 'Settled:' in line or 'To confirm:' in line}
    assert "1 HIGH" in lines['Settled'] and "MEDIUM" not in lines['Settled']
    assert "1 MEDIUM" in lines['To confirm'] and "HIGH" not in lines['To confirm']
