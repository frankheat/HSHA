"""Tests for the output layer (lib/reporter.py)."""
import pytest

from lib import reporter
from lib.models import Finding, HeaderResult, Severity


def result(name: str, *findings: Finding, value: str | None = "x") -> HeaderResult:
    return HeaderResult(name=name.lower(), canonical_name=name, value=value,
                        findings=list(findings))


def finding(severity: Severity, title: str = "t", verify: str = "") -> Finding:
    return Finding(header="H", severity=severity, title=title, verify=verify)


def render(results, mode: str) -> str:
    with reporter.console.capture() as capture:
        reporter.report(results, mode=mode)
    return capture.get()


# ---------------------------------------------------------------------------
# Issue classification
# ---------------------------------------------------------------------------

def test_no_findings_is_not_an_issue():
    assert not reporter._is_issue(result("X-Frame-Options"))


def test_ok_finding_is_not_an_issue():
    assert not reporter._is_issue(result("X-Frame-Options", finding(Severity.OK)))


def test_note_only_is_not_an_issue():
    """Duplicate-header notes must never turn a header into a failure."""
    assert not reporter._is_issue(result("X-Frame-Options", finding(Severity.NOTE)))


def test_info_only_is_not_an_issue():
    """`--format list` treats INFO as clean, so PASS/FAIL must agree."""
    assert not reporter._is_issue(result("Cache-Control", finding(Severity.INFO)))


@pytest.mark.parametrize("severity", [Severity.LOW, Severity.MEDIUM,
                                      Severity.HIGH, Severity.CRITICAL])
def test_low_and_above_is_an_issue(severity):
    assert reporter._is_issue(result("X-Frame-Options", finding(severity)))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def test_simple_mode_marks_pass_and_fail():
    out = render([
        result("X-Frame-Options", finding(Severity.OK)),
        result("Content-Security-Policy", finding(Severity.HIGH, "Missing CSP")),
    ], mode='simple')
    assert "PASS" in out and "FAIL" in out and "Missing CSP" in out


@pytest.mark.parametrize("severity", [Severity.NOTE, Severity.INFO])
def test_simple_mode_separates_informational_from_issues(severity):
    out = render([result("X-Frame-Options", finding(severity, "worth knowing"))],
                 mode='simple')
    assert "Informational" in out and "not counted as failures" in out
    assert "worth knowing" in out
    assert "Issues" not in out


def test_severity_mode_shows_labels_and_counts():
    out = render([
        result("Content-Security-Policy", finding(Severity.HIGH, "Missing CSP")),
        result("Cache-Control", finding(Severity.INFO, "absent")),
    ], mode='severity')
    assert "HIGH" in out and "INFO" in out
    assert "Overall" in out


def test_severity_mode_hides_ok_findings_from_the_findings_section():
    out = render([result("X-Frame-Options", finding(Severity.OK, "all good"))],
                 mode='severity')
    assert "No issues found" in out
    assert "all good" not in out


def test_list_mode_prints_only_failing_header_names():
    out = render([
        result("Content-Security-Policy", finding(Severity.HIGH)),
        result("X-Frame-Options", finding(Severity.OK)),
        result("Cache-Control", finding(Severity.NOTE)),
    ], mode='list')
    assert "Content-Security-Policy" in out
    assert "X-Frame-Options" not in out
    assert "Cache-Control" not in out


def test_list_mode_reports_a_clean_result():
    out = render([result("X-Frame-Options", finding(Severity.OK))], mode='list')
    assert "No issues found" in out


def test_absent_and_empty_values_are_rendered_distinctly():
    out = render([
        result("X-Frame-Options", finding(Severity.HIGH), value=None),
        result("Referrer-Policy", finding(Severity.HIGH), value=""),
    ], mode='simple')
    assert "not present" in out and "empty" in out


# ---------------------------------------------------------------------------
# Contingent findings — what the response cannot settle on its own
# ---------------------------------------------------------------------------

CHECK = "Does this page do X? If it does, this stands. If it does not, there is nothing here."


def test_contingent_and_settled_findings_are_reported_apart():
    out = render([
        result("Content-Security-Policy", finding(Severity.HIGH, "settled problem")),
        result("Permissions-Policy", finding(Severity.LOW, "depends", verify=CHECK)),
    ], mode='severity')
    assert "Findings" in out and "To confirm" in out
    assert out.index("settled problem") < out.index("To confirm") < out.index("depends")


def flat(out: str) -> str:
    """Rich wraps to the terminal width; assertions are about the text, not the wrap."""
    return " ".join(out.split())


def test_a_contingent_finding_prints_its_check():
    out = render([result("Permissions-Policy", finding(Severity.LOW, "t", verify=CHECK))],
                 mode='severity')
    assert CHECK in flat(out)


def test_a_contingent_header_is_marked_in_the_table():
    """The level is what it is worth if it applies, so the severity symbol would
    overstate it — '?' says nothing settled has reached it."""
    out = render([result("Permissions-Policy", finding(Severity.MEDIUM, verify=CHECK))],
                 mode='severity')
    assert "? MEDIUM" in out


def test_a_header_with_one_settled_finding_is_not_marked():
    out = render([result("Permissions-Policy",
                         finding(Severity.MEDIUM, "settled"),
                         finding(Severity.MEDIUM, "contingent", verify=CHECK))],
                 mode='severity')
    assert "? MEDIUM" not in out


def test_the_summary_counts_the_two_kinds_separately():
    out = render([
        result("Content-Security-Policy", finding(Severity.HIGH)),
        result("Permissions-Policy", finding(Severity.MEDIUM, verify=CHECK)),
    ], mode='severity')
    lines = {line.split(':')[0].strip('│ '): line for line in out.splitlines()
             if 'Settled:' in line or 'To confirm:' in line}
    assert "1 HIGH" in lines['Settled'] and "MEDIUM" not in lines['Settled']
    assert "1 MEDIUM" in lines['To confirm'] and "HIGH" not in lines['To confirm']
