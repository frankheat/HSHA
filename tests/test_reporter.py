"""Tests for the output layer (lib/reporter.py)."""
import pytest

from lib import reporter
from lib.models import Finding, HeaderResult, Severity


def result(name: str, *findings: Finding, value: str | None = "x") -> HeaderResult:
    return HeaderResult(name=name.lower(), canonical_name=name, value=value,
                        findings=list(findings))


def finding(severity: Severity, title: str = "t") -> Finding:
    return Finding(header="H", severity=severity, title=title)


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


def test_simple_mode_separates_notes_from_issues():
    out = render([result("X-Frame-Options", finding(Severity.NOTE, "sent 2 times"))],
                 mode='simple')
    assert "Notes" in out and "not counted as failures" in out
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
