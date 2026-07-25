"""Tests for the CSP evaluation engine (lib/csp_evaluator.py)."""
import pytest

from lib.csp_evaluator import evaluate_csp
from lib.models import Severity

# A policy that should be clean under every implemented check.
STRICT = (
    "default-src 'none'; "
    "script-src 'nonce-abcdefghijklmnopqrstuvwx' 'strict-dynamic'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "upgrade-insecure-requests"
)


def titles(policy: str) -> list[str]:
    return [f.title for f in evaluate_csp(policy)]


def flagged(policy: str, substring: str) -> bool:
    return any(substring in t for t in titles(policy))


def severity_of(policy: str, substring: str) -> Severity:
    matches = [f for f in evaluate_csp(policy) if substring in f.title]
    assert matches, f"no finding matching {substring!r} in {titles(policy)}"
    return max(f.severity for f in matches)


def test_strict_policy_is_clean():
    assert evaluate_csp(STRICT) == []


def test_directive_names_are_case_insensitive():
    assert evaluate_csp(STRICT.replace("script-src", "Script-Src")) == []


# ---------------------------------------------------------------------------
# Structural checks
# ---------------------------------------------------------------------------

def test_missing_script_src_and_default_src():
    assert flagged("img-src 'self'", "Missing script-src and default-src")


def test_missing_semicolon_is_detected():
    policy = "default-src 'self' script-src 'none'"
    assert flagged(policy, "Possible missing semicolon")
    assert severity_of(policy, "Possible missing semicolon") == Severity.HIGH


@pytest.mark.parametrize("keyword", [
    'unsafe-inline', 'unsafe-eval', 'unsafe-hashes', 'strict-dynamic', 'none', 'self',
])
def test_unquoted_keyword_is_high(keyword):
    policy = f"script-src {keyword}"
    assert flagged(policy, f"Invalid keyword '{keyword}'")
    assert severity_of(policy, "Invalid keyword") == Severity.HIGH


@pytest.mark.parametrize("value", [
    'nonce-abc123', 'sha256-abc123', 'sha384-abc123', 'sha512-abc123',
])
def test_unquoted_nonce_or_hash_is_high(value):
    policy = f"script-src {value}"
    assert flagged(policy, "Unquoted nonce/hash")
    assert severity_of(policy, "Unquoted nonce/hash") == Severity.HIGH


def test_properly_quoted_nonce_is_not_flagged():
    assert not flagged("script-src 'nonce-abcdefghijklmnopqrstuvwx'", "Unquoted")


# ---------------------------------------------------------------------------
# script-src
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("source,expected", [
    ("*", Severity.CRITICAL),
    ("http:", Severity.CRITICAL),
    ("https:", Severity.HIGH),
])
def test_overly_broad_script_sources(source, expected):
    assert severity_of(f"script-src {source}", "overly broad source") == expected


def test_unsafe_inline_is_high():
    assert severity_of("script-src 'unsafe-inline'", "'unsafe-inline'") == Severity.HIGH


def test_unsafe_inline_is_tolerated_as_a_fallback_next_to_nonce_and_strict_dynamic():
    """The documented backwards-compatibility pattern: old browsers use
    'unsafe-inline', modern ones ignore it because a nonce is present."""
    policy = "script-src 'unsafe-inline' 'nonce-abcdefghijklmnopqrstuvwx' 'strict-dynamic'"
    assert not flagged(policy, "script-src: 'unsafe-inline'")


def test_unsafe_eval_is_high():
    assert severity_of("script-src 'unsafe-eval'", "'unsafe-eval'") == Severity.HIGH


def test_unsafe_hashes_is_medium():
    assert severity_of("script-src 'unsafe-hashes'", "'unsafe-hashes'") == Severity.MEDIUM


def test_strict_dynamic_without_nonce_or_hash_is_medium():
    policy = "script-src 'strict-dynamic'"
    assert severity_of(policy, "'strict-dynamic' without nonce or hash") == Severity.MEDIUM


def test_strict_dynamic_with_hash_is_accepted():
    policy = "script-src 'strict-dynamic' 'sha256-abcdefghijklmnopqrstuvwxyz012345678901234567='"
    assert not flagged(policy, "without nonce or hash")


def test_data_scheme_is_high_and_blob_is_medium():
    assert severity_of("script-src data:", "'data:' URI scheme") == Severity.HIGH
    assert severity_of("script-src blob:", "'blob:' URI scheme") == Severity.MEDIUM


@pytest.mark.parametrize("wildcard", ['*.com', '*.net', '*.org', '*.io', '*.co'])
def test_broad_tld_wildcards_are_high(wildcard):
    assert severity_of(f"script-src {wildcard}", "broad wildcard") == Severity.HIGH


@pytest.mark.parametrize("host", [
    'https://ajax.googleapis.com',
    'https://cdnjs.cloudflare.com',
    'code.jquery.com',
    'https://www.google-analytics.com/',
    'accounts.google.com:443',
])
def test_known_bypass_hosts_are_high(host):
    assert severity_of(f"script-src {host}", "known bypass host") == Severity.HIGH


@pytest.mark.parametrize("source", [
    'https://*.googleapis.com',
    '*.jsdelivr.net',
    'https://*.cloudflare.com',
])
def test_bypass_base_domain_wildcards_are_high(source):
    assert severity_of(f"script-src {source}", "known bypass via wildcard") == Severity.HIGH


def test_ordinary_host_is_not_flagged():
    assert evaluate_csp(STRICT.replace("'strict-dynamic'", "https://cdn.example.com")) == []


def test_short_nonce_is_medium():
    assert severity_of("script-src 'nonce-tooshort'", "nonce too short") == Severity.MEDIUM


def test_nonce_of_at_least_20_chars_is_accepted():
    assert not flagged("script-src 'nonce-abcdefghijklmnopqrst'", "nonce too short")


# ---------------------------------------------------------------------------
# Other directives
# ---------------------------------------------------------------------------

def test_style_src_unsafe_inline_is_medium():
    policy = "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'"
    assert severity_of(policy, "style-src: 'unsafe-inline'") == Severity.MEDIUM


def test_object_src_missing_and_permissive():
    assert flagged("script-src 'self'", "Missing object-src")
    assert severity_of("default-src 'none'; object-src 'self'", "Permissive object-src") == Severity.HIGH


def test_object_src_none_is_accepted():
    assert not flagged(STRICT, "object-src")


def test_base_uri_missing_and_permissive():
    assert flagged("script-src 'self'", "Missing base-uri")
    permissive = STRICT.replace("base-uri 'none'", "base-uri *")
    assert severity_of(permissive, "Permissive base-uri") == Severity.HIGH


def test_frame_ancestors_missing_is_info_and_wildcard_is_high():
    assert severity_of("script-src 'self'", "Missing frame-ancestors") == Severity.INFO
    assert severity_of(STRICT.replace("frame-ancestors 'none'", "frame-ancestors *"),
                       "Permissive frame-ancestors") == Severity.HIGH


def test_default_src_missing_is_medium_and_wildcard_is_high():
    assert severity_of("script-src 'self'", "Missing default-src") == Severity.MEDIUM
    assert severity_of(STRICT.replace("default-src 'none'", "default-src *"),
                       "Permissive default-src") == Severity.HIGH


def test_form_action_missing_is_medium():
    assert severity_of("script-src 'self'", "Missing form-action") == Severity.MEDIUM


def test_upgrade_insecure_requests_missing_is_info():
    assert severity_of("script-src 'self'", "Missing upgrade-insecure-requests") == Severity.INFO


@pytest.mark.parametrize("directive", [
    'reflected-xss', 'referrer', 'block-all-mixed-content', 'prefetch-src',
])
def test_deprecated_directives_are_info(directive):
    policy = f"{STRICT}; {directive} x"
    assert severity_of(policy, f"Deprecated CSP directive: {directive}") == Severity.INFO


# ---------------------------------------------------------------------------
# default-src fallback
# ---------------------------------------------------------------------------

def test_script_src_falls_back_to_default_src():
    assert flagged("default-src 'unsafe-inline'", "script-src: 'unsafe-inline'")


def test_style_src_falls_back_to_default_src():
    assert flagged("default-src 'unsafe-inline'", "style-src: 'unsafe-inline'")


def test_explicit_script_src_overrides_default_src():
    policy = "default-src 'unsafe-eval'; script-src 'self'"
    assert not flagged(policy, "script-src: 'unsafe-eval'")
