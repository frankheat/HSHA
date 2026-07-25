"""Duplicate-header resolution — the strategies in lib/rules.py:_DUPLICATE_STRATEGIES."""
import pytest

from lib.models import Severity

from conftest import analyze, has


def note_of(result):
    notes = [f for f in result.findings if f.severity == Severity.NOTE]
    assert len(notes) == 1, f"expected exactly one NOTE, got {len(notes)}"
    return notes[0]


def test_single_occurrence_produces_no_note():
    result = analyze("X-Frame-Options: DENY")['x-frame-options']
    assert not any(f.severity == Severity.NOTE for f in result.findings)


def test_identical_duplicates_collapse_to_one_value():
    result = analyze("X-Frame-Options: DENY", "X-Frame-Options: DENY")['x-frame-options']
    assert result.value == "DENY"
    assert "identical" in note_of(result).description


def test_identical_duplicates_ignore_case_and_padding():
    result = analyze("X-Frame-Options: DENY", "X-Frame-Options:   deny  ")['x-frame-options']
    assert "identical" in note_of(result).description


def test_default_strategy_is_first_wins():
    """RFC 6797 §8.1: the first HSTS header wins."""
    result = analyze(
        "Strict-Transport-Security: max-age=300",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    )['strict-transport-security']
    assert result.value == "max-age=300"
    assert "first value" in note_of(result).description
    assert has(result.findings, "max-age too short")


def test_referrer_policy_is_last_wins():
    result = analyze(
        "Referrer-Policy: unsafe-url",
        "Referrer-Policy: no-referrer",
    )['referrer-policy']
    assert result.value == "no-referrer"
    assert result.worst_severity == Severity.NOTE     # the unsafe first value is not applied


@pytest.mark.parametrize("header,key", [
    ("Cache-Control", 'cache-control'),
    ("Clear-Site-Data", 'clear-site-data'),
    ("Permissions-Policy", 'permissions-policy'),
    ("Pragma", 'pragma'),
])
def test_join_strategy_concatenates_occurrences(header, key):
    result = analyze(f"{header}: aaa", f"{header}: bbb")[key]
    assert result.value == "aaa, bbb"
    assert "combine" in note_of(result).description


def test_x_frame_options_conflict_resolves_to_the_strictest():
    result = analyze("X-Frame-Options: SAMEORIGIN", "X-Frame-Options: DENY")['x-frame-options']
    assert result.value == "DENY"
    assert "block framing" in note_of(result).description


def test_note_lists_every_original_value():
    result = analyze(
        "Strict-Transport-Security: max-age=1",
        "Strict-Transport-Security: max-age=2",
        "Strict-Transport-Security: max-age=3",
    )['strict-transport-security']
    note = note_of(result)
    assert "sent 3 times" in note.title
    for value in ("max-age=1", "max-age=2", "max-age=3"):
        assert value in note.description


def test_note_alone_does_not_make_a_header_fail():
    """NOTE is informational: it must stay below the INFO exit-code threshold."""
    result = analyze("X-Frame-Options: DENY", "X-Frame-Options: DENY")['x-frame-options']
    assert result.worst_severity == Severity.NOTE
    assert Severity.NOTE < Severity.INFO


def test_duplicate_resolution_applies_to_custom_headers_too():
    from lib.config import AppConfig, HeaderOverride
    config = AppConfig(overrides={'x-request-id': HeaderOverride(required=True)})
    result = analyze("X-Request-Id: a", "X-Request-Id: b", config=config)['x-request-id']
    assert result.value == "a"
    assert note_of(result)
