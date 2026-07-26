"""Duplicate-header resolution — the strategies in lib/rules.py:_DUPLICATE_STRATEGIES.

Repeating the same value is harmless (NOTE). Contradictory values are a
misconfiguration (LOW): one component's intent is discarded, and which one wins
comes from a resolution rule rather than from anything the site chose.
"""
import pytest

from lib.models import Severity

from conftest import analyze


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
    result = analyze("X-Frame-Options: DENY", "X-Frame-Options: DENY")['x-frame-options']
    assert result.value == "DENY"
    finding = duplicate_finding(result)
    assert finding.severity == Severity.NOTE
    assert "identical" in finding.description


def test_identical_duplicates_ignore_case_and_padding():
    result = analyze("X-Frame-Options: DENY", "X-Frame-Options:   deny  ")['x-frame-options']
    assert duplicate_finding(result).severity == Severity.NOTE


def test_identical_duplicates_do_not_make_a_header_fail():
    result = analyze("X-Frame-Options: DENY", "X-Frame-Options: DENY")['x-frame-options']
    assert result.worst_severity == Severity.NOTE
    assert Severity.NOTE < Severity.INFO      # below the exit-code threshold


# ---------------------------------------------------------------------------
# Conflicting duplicates — a misconfiguration
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("header,key,first,second", [
    ("Strict-Transport-Security", 'strict-transport-security', "max-age=31536000", "max-age=600"),
    ("Referrer-Policy", 'referrer-policy', "unsafe-url", "no-referrer"),
    ("X-Frame-Options", 'x-frame-options', "deny", "sameorigin"),
    ("Cache-Control", 'cache-control', "no-store", "public"),
])
def test_conflicting_duplicates_are_low(header, key, first, second):
    result = analyze(f"{header}: {first}", f"{header}: {second}")[key]
    assert duplicate_finding(result).severity == Severity.LOW
    assert result.worst_severity >= Severity.LOW


def test_conflict_finding_names_the_problem():
    result = analyze("X-Frame-Options: deny", "X-Frame-Options: sameorigin")['x-frame-options']
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
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    )['strict-transport-security']
    assert result.value == "max-age=300"
    assert "first value" in duplicate_finding(result).description
    assert any("max-age too short" in f.title for f in result.findings)


def test_referrer_policy_is_last_wins():
    result = analyze("Referrer-Policy: unsafe-url", "Referrer-Policy: no-referrer")['referrer-policy']
    assert result.value == "no-referrer"
    # the unsafe first value is not applied, so no HIGH finding for it
    assert result.worst_severity == Severity.LOW


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


def test_x_frame_options_conflict_resolves_to_the_strictest():
    result = analyze("X-Frame-Options: SAMEORIGIN", "X-Frame-Options: DENY")['x-frame-options']
    assert result.value == "DENY"
    assert "block framing" in duplicate_finding(result).description


def test_x_frame_options_conflict_is_not_reported_as_optimal():
    """The DENY it resolves to is an accident of the conflict, not a choice."""
    result = analyze("X-Frame-Options: deny", "X-Frame-Options: sameorigin")['x-frame-options']
    assert result.worst_severity > Severity.NOTE


# ---------------------------------------------------------------------------
# Custom headers
# ---------------------------------------------------------------------------

def test_duplicate_resolution_applies_to_custom_headers_too():
    from lib.config import AppConfig, HeaderOverride
    config = AppConfig(overrides={'x-request-id': HeaderOverride(required=True)})
    result = analyze("X-Request-Id: a", "X-Request-Id: b", config=config)['x-request-id']
    assert result.value == "a"
    assert duplicate_finding(result).severity == Severity.LOW
