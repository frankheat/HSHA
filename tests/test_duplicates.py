"""Duplicate-header resolution — the strategies in lib/rules.py:_DUPLICATE_STRATEGIES.

A value is only lost when the resolution has to pick one occurrence over the
others, which is what makes it a misconfiguration (LOW): one component's intent
is discarded, and which one wins comes from a resolution rule rather than from
anything the site chose. Repeating the same value, or sending a header whose
occurrences combine, discards nothing and stays a NOTE — whether the combined
value is still valid is then up to that header's own check.
"""
import pytest

from lib.models import Severity

from conftest import analyze, has


def duplicate_finding(result):
    """The single finding emitted for a header that was sent more than once."""
    found = [f for f in result.findings if "times" in f.title]
    assert len(found) == 1, f"expected one duplicate finding, got {[f.title for f in found]}"
    return found[0]


def test_single_occurrence_produces_no_duplicate_finding():
    result = analyze("X-Frame-Options: DENY")['x-frame-options']
    assert not [f for f in result.findings if "times" in f.title]


# ---------------------------------------------------------------------------
# Identical duplicates — harmless
# ---------------------------------------------------------------------------

def test_identical_duplicates_collapse_to_one_value():
    result = analyze("Strict-Transport-Security: max-age=63072000; includeSubDomains",
                     "Strict-Transport-Security: max-age=63072000; includeSubDomains"
                     )['strict-transport-security']
    assert result.value == "max-age=63072000; includeSubDomains"
    finding = duplicate_finding(result)
    assert finding.severity == Severity.NOTE
    assert "identical" in finding.description


def test_identical_duplicates_ignore_case_and_padding():
    result = analyze("X-Content-Type-Options: nosniff",
                     "X-Content-Type-Options:   NOSNIFF  ")['x-content-type-options']
    assert duplicate_finding(result).severity == Severity.NOTE


def test_identical_duplicates_do_not_make_a_header_fail():
    result = analyze("X-Content-Type-Options: nosniff",
                     "X-Content-Type-Options: nosniff")['x-content-type-options']
    assert result.worst_severity == Severity.NOTE
    assert Severity.NOTE < Severity.INFO      # below the issue threshold


# ---------------------------------------------------------------------------
# Conflicting duplicates — a misconfiguration
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("header,key,first,second", [
    ("Strict-Transport-Security", 'strict-transport-security', "max-age=63072000", "max-age=600"),
])
def test_conflicting_duplicates_are_low(header, key, first, second):
    """Only where the resolution discards one of the values."""
    result = analyze(f"{header}: {first}", f"{header}: {second}")[key]
    assert duplicate_finding(result).severity == Severity.LOW
    assert result.worst_severity >= Severity.LOW


@pytest.mark.parametrize("header,key,first,second", [
    ("Cache-Control", 'cache-control', "max-age=600", "must-revalidate"),
    ("Content-Security-Policy", 'content-security-policy', "default-src 'none'", "frame-ancestors 'none'"),
    ("Clear-Site-Data", 'clear-site-data', '"cache"', '"cookies"'),
    ("Permissions-Policy", 'permissions-policy', "camera=()", "microphone=()"),
    ("Pragma", 'pragma', "no-cache", "no-transform"),
])
def test_joined_duplicates_are_not_a_conflict(header, key, first, second):
    """Under 'join' every value survives, so the duplicate itself is not the
    misconfiguration — for these headers sending it twice is how a combined
    list is expressed."""
    result = analyze(f"{header}: {first}", f"{header}: {second}")[key]
    finding = duplicate_finding(result)
    assert finding.severity == Severity.NOTE
    assert "conflicting" not in finding.title


def test_joined_duplicates_carry_no_recommendation():
    """Nothing to change — unlike a repeated identical value, which is noise."""
    joined = analyze("Cache-Control: max-age=600", "Cache-Control: must-revalidate")['cache-control']
    repeated = analyze("Cache-Control: no-store", "Cache-Control: no-store")['cache-control']
    assert duplicate_finding(joined).recommendation == ""
    assert duplicate_finding(repeated).recommendation != ""


def test_conflict_finding_names_the_problem():
    result = analyze("Strict-Transport-Security: max-age=1",
                     "Strict-Transport-Security: max-age=2")['strict-transport-security']
    assert "conflicting values" in duplicate_finding(result).title


def test_conflicting_duplicates_list_every_original_value():
    result = analyze(
        "Strict-Transport-Security: max-age=1",
        "Strict-Transport-Security: max-age=2",
        "Strict-Transport-Security: max-age=3",
    )['strict-transport-security']
    finding = duplicate_finding(result)
    assert "sent 3 times" in finding.title
    for value in ("max-age=1", "max-age=2", "max-age=3"):
        assert value in finding.description


# ---------------------------------------------------------------------------
# Resolution strategies — which value the checks then run against
# ---------------------------------------------------------------------------

def test_default_strategy_is_first_wins():
    """RFC 6797 §8.1: the first HSTS header wins."""
    result = analyze(
        "Strict-Transport-Security: max-age=300",
        "Strict-Transport-Security: max-age=63072000; includeSubDomains",
    )['strict-transport-security']
    assert result.value == "max-age=300"
    assert "first value" in duplicate_finding(result).description
    assert any("max-age too short" in f.title for f in result.findings)


def test_referrer_policy_keeps_the_last_valid_token_across_occurrences():
    """A browser concatenates the occurrences and walks the tokens, so the last
    *valid* one wins — not the last occurrence."""
    both_valid = analyze("Referrer-Policy: unsafe-url",
                         "Referrer-Policy: no-referrer")['referrer-policy']
    assert both_valid.value == "unsafe-url, no-referrer"
    assert both_valid.worst_severity == Severity.NOTE      # no-referrer is applied

    last_invalid = analyze("Referrer-Policy: no-referrer",
                           "Referrer-Policy: bogus")['referrer-policy']
    assert last_invalid.worst_severity == Severity.NOTE    # bogus is skipped, not honoured


@pytest.mark.parametrize("header,key", [
    ("Cache-Control", 'cache-control'),
    ("Clear-Site-Data", 'clear-site-data'),
    ("Permissions-Policy", 'permissions-policy'),
    ("Pragma", 'pragma'),
])
def test_join_strategy_concatenates_occurrences(header, key):
    result = analyze(f"{header}: aaa", f"{header}: bbb")[key]
    assert result.value == "aaa, bbb"
    assert "combine" in duplicate_finding(result).description


def test_x_frame_options_conflict_is_resolved_by_its_own_checker():
    """A browser joins the occurrences and works on the set, so the conflict is a
    fact about the value rather than something the duplicate rule has to resolve."""
    result = analyze("X-Frame-Options: SAMEORIGIN", "X-Frame-Options: DENY")['x-frame-options']
    assert result.value == "SAMEORIGIN, DENY"
    assert duplicate_finding(result).severity == Severity.NOTE
    assert has(result.findings, "blocks framing by contradicting itself")


def test_x_frame_options_conflict_is_not_reported_as_optimal():
    """Framing is refused, so nothing is at risk — but the response does not get an
    OK either, because it never said what it meant."""
    result = analyze("X-Frame-Options: deny", "X-Frame-Options: sameorigin")['x-frame-options']
    assert result.worst_severity == Severity.NOTE
    assert not has(result.findings, "DENY (optimal)")


def test_two_unusable_x_frame_options_values_do_not_become_a_deny():
    """The old rule resolved any conflict to DENY, which reported a framable page
    as protected when neither value was one a browser applies."""
    result = analyze("X-Frame-Options: bogus", "X-Frame-Options: garbage")['x-frame-options']
    absent = analyze("X-Nothing: x")['x-frame-options'].worst_severity
    assert result.worst_severity == absent
    assert has(result.findings, "framable by anyone")


# ---------------------------------------------------------------------------
# COOP — a joined value that no longer parses
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("first,second", [
    ("same-origin", "same-origin"),      # identical is no consolation here
    ("same-origin", "unsafe-none"),
])
def test_duplicate_coop_leaves_the_response_without_coop(first, second):
    """COOP is a structured item: RFC 8941 §4.2 fails parsing on anything after
    the first item, and the browser then applies unsafe-none. So two occurrences
    have to be graded like the header never being sent."""
    result = analyze(
        f"Cross-Origin-Opener-Policy: {first}",
        f"Cross-Origin-Opener-Policy: {second}",
    )['cross-origin-opener-policy']
    assert result.value == f"{first}, {second}"
    assert duplicate_finding(result).severity == Severity.NOTE
    invalid = [f for f in result.findings if "not applied" in f.title]
    assert len(invalid) == 1
    assert invalid[0].severity == Severity.MEDIUM     # == severity of an absent COOP


def test_duplicate_coop_is_never_reported_as_configured():
    result = analyze(
        "Cross-Origin-Opener-Policy: same-origin",
        "Cross-Origin-Opener-Policy: same-origin",
    )['cross-origin-opener-policy']
    assert not [f for f in result.findings if f.severity == Severity.OK]


def test_join_evaluates_the_combined_value_even_when_occurrences_match():
    """The browser concatenates regardless of whether the copies agree, so the
    checks have to run on the concatenation — this is what makes duplicate COOP
    detectable at all."""
    result = analyze("Cache-Control: no-store", "Cache-Control: no-store")['cache-control']
    assert result.value == "no-store, no-store"


# ---------------------------------------------------------------------------
# Custom headers
# ---------------------------------------------------------------------------

def test_duplicate_resolution_applies_to_custom_headers_too():
    from lib.config import AppConfig, HeaderOverride
    config = AppConfig(overrides={'x-request-id': HeaderOverride(required=True)})
    result = analyze("X-Request-Id: a", "X-Request-Id: b", config=config)['x-request-id']
    assert result.value == "a"
    assert duplicate_finding(result).severity == Severity.LOW
