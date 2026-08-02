"""Checks that need more than one header (lib/correlations.py)."""
import pytest

from lib.config import AppConfig, HeaderOverride
from lib.models import Severity

from conftest import analyze, has

ACAO = "Access-Control-Allow-Origin"
ACAC = "Access-Control-Allow-Credentials"


def cors(origin: str | None, credentials: str | None = "true", config=None):
    """Analyse a response with the given CORS pair and return the ACAC result."""
    lines = []
    if origin is not None:
        lines.append(f"{ACAO}: {origin}")
    if credentials is not None:
        lines.append(f"{ACAC}: {credentials}")
    return analyze(*lines or ["X-Nothing: x"], config=config)['access-control-allow-credentials']


# ---------------------------------------------------------------------------
# The verdict depends on the origin, not on the credentials header alone
# ---------------------------------------------------------------------------

def test_null_origin_with_credentials_is_critical():
    result = cors("null")
    assert result.worst_severity == Severity.CRITICAL
    assert has(result.findings, "null with credentials enabled")


def test_wildcard_with_credentials_is_functional_not_a_weakness():
    """Browsers reject the credentialed request, so the combination exposes
    nothing. The wildcard's own effect is graded on ACAO."""
    result = cors("*")
    assert result.worst_severity == Severity.INFO
    assert has(result.findings, "the request fails")


def test_the_wildcard_is_still_graded_on_its_own_header():
    """The credentials verdict is neutral here — browsers refuse the pair — so the
    wildcard's own cost has to keep coming from Access-Control-Allow-Origin."""
    results = analyze(f"{ACAO}: *", f"{ACAC}: true")
    assert results['access-control-allow-origin'].worst_severity == Severity.HIGH


def test_wildcard_recommendation_warns_against_fixing_it_with_reflection():
    finding = next(f for f in cors("*").findings if f.severity == Severity.INFO)
    assert "Do not echo back" in finding.recommendation


def test_specific_origin_with_credentials_is_graded_as_the_reflected_case():
    """An echoed Origin and an allowlisted one are the same bytes, and the echoed
    one hands authenticated responses to any site. The response cannot rule that
    out, so it carries the weight of the case it cannot rule out."""
    result = cors("https://app.example.com")
    assert result.worst_severity == Severity.CRITICAL
    assert has(result.findings, "https://app.example.com")
    assert all(f.is_contingent for f in result.findings
               if f.severity == Severity.CRITICAL)


def test_specific_origin_finding_warns_about_origin_reflection():
    """A reflected origin is indistinguishable from an allowlisted one in a
    single response, so the finding has to tell the reader how to check — and
    what a positive result means, since it is far worse than what is printed."""
    finding = next(f for f in cors("https://app.example.com").findings
                   if f.severity == Severity.CRITICAL)
    assert finding.is_contingent
    assert "echoes back" in finding.description
    assert "Origin: https://an-origin-you-made-up.example" in finding.verify
    assert "does not come back" in finding.verify
    assert "nothing here" in finding.verify


def test_credentials_without_an_origin_have_no_effect():
    result = cors(None)
    assert result.worst_severity == Severity.INFO
    assert has(result.findings, "has no effect")


# ---------------------------------------------------------------------------
# When the rule stays out of the way
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("credentials", ["false", "FALSE", "yes", "1"])
def test_nothing_is_reported_unless_credentials_are_enabled(credentials):
    result = cors("null", credentials)
    assert result.worst_severity == Severity.OK


def test_nothing_is_reported_when_the_credentials_header_is_absent():
    """Even next to the worst possible origin: with no credentials header there is
    nothing to send, so the rule has no verdict to reach."""
    results = analyze(f"{ACAO}: null")
    assert results['access-control-allow-credentials'].findings == []


def test_case_and_padding_are_tolerated():
    assert cors("  NULL  ", "  TRUE  ").worst_severity == Severity.CRITICAL


def test_a_skipped_origin_header_is_reported_as_not_assessed():
    """Silence would read as approval, so say the check could not run."""
    config = AppConfig(overrides={'access-control-allow-origin': HeaderOverride(skip=True)})
    result = cors("https://app.example.com", config=config)
    assert result.worst_severity == Severity.INFO
    assert has(result.findings, "was not evaluated")


def test_a_skipped_credentials_header_disables_the_rule():
    config = AppConfig(overrides={'access-control-allow-credentials': HeaderOverride(skip=True)})
    results = analyze(f"{ACAO}: null", f"{ACAC}: true", config=config)
    assert 'access-control-allow-credentials' not in results


# ---------------------------------------------------------------------------
# Exactly one verdict per situation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("origin", ["null", "*", "https://app.example.com", None])
def test_the_header_carries_a_single_verdict(origin):
    """The per-header checker stays neutral so the report has one row, not two."""
    findings = cors(origin).findings
    graded = [f for f in findings if f.severity > Severity.OK]
    assert len(graded) == 1, [f.title for f in graded]


def test_the_per_header_checker_no_longer_grades_on_its_own():
    from lib.rules import _check_acac
    assert all(f.severity == Severity.OK for f in _check_acac("true", {}))


def test_credentials_are_moot_when_the_origin_list_is_invalid():
    result = cors("https://a.example.com, https://b.example.com")
    assert result.worst_severity == Severity.INFO
    assert has(result.findings, "not usable")


# ---------------------------------------------------------------------------
# frame-ancestors takes the framing decision away from X-Frame-Options
# ---------------------------------------------------------------------------

CSP = "Content-Security-Policy"
XFO = "X-Frame-Options"


def framing(xfo: str | None, frame_ancestors: str | None):
    lines = []
    if xfo is not None:
        lines.append(f"{XFO}: {xfo}")
    if frame_ancestors is not None:
        lines.append(f"{CSP}: default-src 'self'; frame-ancestors {frame_ancestors}")
    return analyze(*lines or ["X-Nothing: x"])['x-frame-options']


def test_a_permissive_frame_ancestors_stops_x_frame_options_reading_as_clean():
    """HTML returns early, the header unread, as soon as an enforced policy carries
    a frame-ancestors directive — so DENY beside `frame-ancestors *` protects only
    browsers too old to implement CSP, and the row must not show a clean result."""
    result = framing("DENY", "*")
    assert result.worst_severity == Severity.INFO
    assert has(result.findings, "replaced by the CSP, which allows framing")


def test_a_restrictive_frame_ancestors_says_nothing_extra():
    """CSP covering modern browsers and X-Frame-Options covering the rest is the
    pairing to aim for; there is nothing to report about it."""
    for sources in ("'none'", "'self'"):
        result = framing("DENY", sources)
        assert result.worst_severity == Severity.OK
        assert not has(result.findings, "replaced by the CSP")


def test_the_exposure_is_not_graded_twice():
    """The CSP row carries it. This one only removes the reassurance, so it must
    stay below the level that would read as a second problem."""
    results = analyze(f"{XFO}: DENY", f"{CSP}: default-src 'self'; frame-ancestors *")
    assert results['content-security-policy'].worst_severity == Severity.HIGH
    assert results['x-frame-options'].worst_severity == Severity.INFO


def test_nothing_is_said_when_x_frame_options_is_absent():
    """Then there is no clean verdict to correct, and the missing header is already
    reported on its own row."""
    result = framing(None, "*")
    assert not has(result.findings, "replaced by the CSP")
