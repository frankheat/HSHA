"""Orchestration tests for analyze_headers: presence, absence, overrides, custom headers."""
import pytest

from lib.config import AppConfig, HeaderOverride
from lib.models import Severity
from lib.rules import SECURITY_HEADERS, analyze_headers

from conftest import analyze, findings_for, has, result_for, severity_for


def test_all_registry_headers_are_reported_when_nothing_is_skipped():
    results = analyze("X-Frame-Options: DENY")
    assert set(results) == {key for key, *_ in SECURITY_HEADERS}


@pytest.mark.parametrize("header,expected", [
    ("Content-Security-Policy", Severity.HIGH),
    ("Strict-Transport-Security", Severity.HIGH),
    ("X-Frame-Options", Severity.HIGH),
    ("X-Content-Type-Options", Severity.MEDIUM),
    ("Cross-Origin-Opener-Policy", Severity.MEDIUM),
    ("Permissions-Policy", Severity.MEDIUM),
    ("Referrer-Policy", Severity.MEDIUM),
])
def test_missing_required_header_uses_its_default_severity(header, expected):
    result = analyze("X-Nothing: x")[header.lower()]
    assert result.worst_severity == expected
    assert has(result.findings, f"Missing {header}")


@pytest.mark.parametrize("header", [
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
    "Cache-Control",
    "Clear-Site-Data",
    "ETag",
])
def test_missing_optional_header_is_info(header):
    assert analyze("X-Nothing: x")[header.lower()].worst_severity == Severity.INFO


def test_missing_required_header_carries_a_recommendation():
    result = analyze("X-Nothing: x")['content-security-policy']
    assert result.findings[0].recommendation


def test_missing_optional_header_carries_no_recommendation():
    result = analyze("X-Nothing: x")['etag']
    assert result.findings[0].recommendation == ""


def test_absent_header_has_value_none_and_is_not_present():
    result = analyze("X-Nothing: x")['x-frame-options']
    assert result.value is None and not result.is_present


# ---------------------------------------------------------------------------
# Empty values
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["", "   "])
def test_empty_value_is_reported_as_present_but_empty(value):
    result = result_for("X-Frame-Options", value)
    assert result.is_present
    assert has(result.findings, "present but empty")


@pytest.mark.parametrize("key,canonical", [(k, c) for k, c, *_ in SECURITY_HEADERS],
                         ids=[c for _, c, *_ in SECURITY_HEADERS])
def test_empty_value_weighs_the_same_as_an_absent_header(key, canonical):
    """Browsers ignore an empty header, so its impact equals that of a missing one."""
    absent = analyze("X-Nothing: x")[key].worst_severity
    assert result_for(canonical, "").worst_severity == absent


def test_empty_value_severity_follows_config_overrides():
    config = AppConfig(overrides={
        'etag': HeaderOverride(required=True, severity_if_missing='high'),
    })
    assert severity_for("ETag", "", config) == Severity.HIGH


def test_empty_optional_header_is_not_escalated():
    """Regression: an empty ETag used to be HIGH while a missing one was INFO."""
    assert severity_for("ETag", "") == Severity.INFO


def test_empty_value_skips_the_normal_checker():
    findings = findings_for("X-Content-Type-Options", "")
    assert has(findings, "present but empty")
    assert not has(findings, "unexpected value")


# ---------------------------------------------------------------------------
# Config overrides
# ---------------------------------------------------------------------------

def test_skip_removes_the_header_from_the_results():
    config = AppConfig(overrides={'x-frame-options': HeaderOverride(skip=True)})
    assert 'x-frame-options' not in analyze("X-Frame-Options: DENY", config=config)


def test_required_override_promotes_an_optional_header():
    config = AppConfig(overrides={
        'clear-site-data': HeaderOverride(required=True, severity_if_missing='medium'),
    })
    assert analyze("X-Nothing: x", config=config)['clear-site-data'].worst_severity == Severity.MEDIUM


def test_required_override_can_demote_a_required_header():
    config = AppConfig(overrides={
        'content-security-policy': HeaderOverride(required=False),
    })
    assert analyze("X-Nothing: x", config=config)['content-security-policy'].worst_severity == Severity.INFO


def test_expected_value_matching_produces_no_findings():
    config = AppConfig(overrides={'cache-control': HeaderOverride(expected_value='no-store, no-cache')})
    assert findings_for("Cache-Control", "no-store, no-cache", config) == []


def test_expected_value_is_case_insensitive():
    config = AppConfig(overrides={'cache-control': HeaderOverride(expected_value='NO-STORE')})
    assert findings_for("Cache-Control", "no-store", config) == []


def test_expected_value_mismatch_is_medium():
    config = AppConfig(overrides={'cache-control': HeaderOverride(expected_value='no-store')})
    assert severity_for("Cache-Control", "public", config) == Severity.MEDIUM


def test_expected_value_bypasses_the_builtin_checker():
    """Documented behaviour: an explicit assertion replaces the built-in rules."""
    config = AppConfig(overrides={'x-frame-options': HeaderOverride(expected_value='ALLOWALL')})
    assert findings_for("X-Frame-Options", "ALLOWALL", config) == []


def test_expected_pattern_match_and_mismatch():
    config = AppConfig(overrides={'etag': HeaderOverride(expected_pattern=r'^W/')})
    assert findings_for("ETag", 'W/"abc"', config) == []
    assert severity_for("ETag", '"abc"', config) == Severity.MEDIUM


def test_severity_if_present_flags_a_header_without_a_builtin_checker():
    config = AppConfig(overrides={'x-powered-by': HeaderOverride(severity_if_present='medium')})
    result = analyze("X-Powered-By: ASP.NET", config=config)['x-powered-by']
    assert result.worst_severity == Severity.MEDIUM


def test_invalid_severity_name_in_config_raises():
    config = AppConfig(overrides={
        'content-security-policy': HeaderOverride(required=True, severity_if_missing='catastrophic'),
    })
    with pytest.raises(ValueError, match="Invalid severity"):
        analyze("X-Nothing: x", config=config)


# ---------------------------------------------------------------------------
# Custom headers declared only in the config
# ---------------------------------------------------------------------------

def test_custom_required_header_missing_is_reported():
    config = AppConfig(overrides={
        'x-request-id': HeaderOverride(required=True, severity_if_missing='low'),
    })
    result = analyze("X-Nothing: x", config=config)['x-request-id']
    assert result.worst_severity == Severity.LOW
    assert has(result.findings, "Missing custom header")


def test_custom_header_pattern_is_enforced():
    config = AppConfig(overrides={
        'x-request-id': HeaderOverride(required=True, expected_pattern=r'^[0-9a-f-]{36}$'),
    })
    ok = analyze("X-Request-Id: 966b74b5-90c7-428e-a0ca-13a416a9b17a", config=config)
    bad = analyze("X-Request-Id: nope", config=config)
    assert ok['x-request-id'].findings == []
    assert bad['x-request-id'].worst_severity == Severity.MEDIUM


def test_custom_header_present_and_unconstrained_produces_no_findings():
    config = AppConfig(overrides={'x-request-id': HeaderOverride(required=True)})
    assert analyze("X-Request-Id: abc", config=config)['x-request-id'].findings == []


def test_skipped_custom_header_is_not_reported():
    config = AppConfig(overrides={'x-request-id': HeaderOverride(skip=True, required=True)})
    assert 'x-request-id' not in analyze("X-Nothing: x", config=config)


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

def test_basic_profile_skips_the_extended_only_headers():
    from conftest import profile
    results = analyze("X-Nothing: x", config=profile('basic'))
    for skipped in ('permissions-policy', 'x-xss-protection', 'expect-ct',
                    'origin-agent-cluster', 'access-control-allow-origin'):
        assert skipped not in results


def test_extended_profile_checks_more_headers_than_basic():
    from conftest import profile
    basic = analyze("X-Nothing: x", config=profile('basic'))
    extended = analyze("X-Nothing: x", config=profile('extended'))
    assert set(basic) < set(extended)


def test_extended_profile_requires_hsts_preload():
    from conftest import profile
    findings = findings_for("Strict-Transport-Security",
                            "max-age=31536000; includeSubDomains", profile('extended'))
    assert has(findings, "missing preload")


# ---------------------------------------------------------------------------
# Config options must not be silently discarded
# ---------------------------------------------------------------------------

def test_severity_if_missing_implies_the_header_is_required():
    """Stating a severity for absence used to be ignored without `required: true`."""
    config = AppConfig(overrides={
        'clear-site-data': HeaderOverride(severity_if_missing='critical'),
    })
    assert analyze("X-Nothing: x", config=config)['clear-site-data'].worst_severity == Severity.CRITICAL


def test_explicit_required_false_still_wins_over_severity_if_missing():
    config = AppConfig(overrides={
        'clear-site-data': HeaderOverride(required=False, severity_if_missing='critical'),
    })
    assert analyze("X-Nothing: x", config=config)['clear-site-data'].worst_severity == Severity.INFO


def test_severity_if_present_applies_to_headers_that_have_a_checker():
    """Checkers report a clean value with an OK finding, which used to count as
    'the checker said something' and suppress the configured severity."""
    config = AppConfig(overrides={'cache-control': HeaderOverride(severity_if_present='critical')})
    assert severity_for("Cache-Control", "no-store", config) == Severity.CRITICAL


def test_severity_if_present_yields_to_a_real_problem_found_by_the_checker():
    config = AppConfig(overrides={'referrer-policy': HeaderOverride(severity_if_present='low')})
    findings = findings_for("Referrer-Policy", "unsafe-url", config)
    assert has(findings, "unsafe")
    assert max(f.severity for f in findings) == Severity.HIGH


def test_custom_header_keeps_the_casing_used_in_the_config():
    """Overrides are keyed lowercase; the report must not inherit that."""
    from lib.config import load_config
    from conftest import ROOT
    import tempfile, os
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'c.yaml')
        with open(path, 'w') as f:
            f.write("headers:\n  X-Request-Id:\n    required: true\n")
        config = load_config(path)
    result = analyze("X-Nothing: x", config=config)['x-request-id']
    assert result.canonical_name == 'X-Request-Id'
    assert 'X-Request-Id' in result.findings[0].title


def test_custom_header_is_still_matched_case_insensitively():
    from lib.config import AppConfig, HeaderOverride
    config = AppConfig(overrides={
        'x-request-id': HeaderOverride(required=True, display_name='X-Request-Id'),
    })
    result = analyze("x-REQUEST-id: abc", config=config)['x-request-id']
    assert result.value == 'abc'
    assert result.canonical_name == 'X-Request-Id'


# ---------------------------------------------------------------------------
# What an absent header actually tells the reader
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("header,key", [
    ("Cache-Control", 'cache-control'),
    ("Cross-Origin-Embedder-Policy", 'cross-origin-embedder-policy'),
    ("Cross-Origin-Resource-Policy", 'cross-origin-resource-policy'),
])
def test_optional_headers_keep_their_written_recommendation(header, key):
    """These are the findings that would otherwise say nothing useful."""
    from lib.rules import _MISSING_RECS
    finding = analyze("X-Nothing: x")[key].findings[0]
    assert finding.severity == Severity.INFO
    assert finding.recommendation == _MISSING_RECS[key]


def test_optional_header_without_a_written_recommendation_stays_quiet():
    """No generic 'add the header' nagging for headers nobody needs to add."""
    assert analyze("X-Nothing: x")['etag'].findings[0].recommendation == ""


def test_missing_cache_control_explains_heuristic_caching():
    finding = analyze("X-Nothing: x")['cache-control'].findings[0]
    assert "heuristic caching" in finding.description
    assert "signed-in user" in finding.description
    assert "no-store" in finding.recommendation


def test_missing_required_header_still_gets_the_generic_fallback():
    from lib.config import AppConfig, HeaderOverride
    config = AppConfig(overrides={'x-dns-prefetch-control': HeaderOverride(required=True)})
    finding = analyze("X-Nothing: x", config=config)['x-dns-prefetch-control'].findings[0]
    assert finding.recommendation == "Add the X-DNS-Prefetch-Control header."
