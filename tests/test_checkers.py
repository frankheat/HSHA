"""Table-driven tests for the per-header value checkers in lib/rules.py."""
import pytest

from lib.models import Severity

from conftest import analyze, findings_for, has, severity_for

_PP_HIGH = ['camera', 'microphone', 'geolocation', 'payment', 'usb', 'display-capture']
_PP_MEDIUM = ['accelerometer', 'gyroscope', 'magnetometer', 'midi', 'screen-wake-lock',
              'xr-spatial-tracking', 'document-domain', 'publickey-credentials-get']
PP_FULL = ", ".join(f"{f}=()" for f in _PP_HIGH + _PP_MEDIUM)


# (header, value, expected worst severity)
CASES = [
    # --- Strict-Transport-Security ---
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains", Severity.OK),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload", Severity.OK),
    ("Strict-Transport-Security", "MAX-AGE=31536000; INCLUDESUBDOMAINS", Severity.OK),
    ("Strict-Transport-Security", "max-age = 31536000; includeSubDomains", Severity.OK),
    ("Strict-Transport-Security", "max-age=31536000", Severity.LOW),
    ("Strict-Transport-Security", "max-age=300; includeSubDomains", Severity.MEDIUM),
    ("Strict-Transport-Security", "max-age=0; includeSubDomains", Severity.HIGH),
    ("Strict-Transport-Security", "includeSubDomains", Severity.HIGH),

    # --- X-Frame-Options ---
    ("X-Frame-Options", "DENY", Severity.OK),
    ("X-Frame-Options", "deny", Severity.OK),
    ("X-Frame-Options", "SAMEORIGIN", Severity.OK),
    ("X-Frame-Options", "ALLOW-FROM https://example.com", Severity.LOW),
    ("X-Frame-Options", "ALLOWALL", Severity.MEDIUM),

    # --- X-Content-Type-Options ---
    ("X-Content-Type-Options", "nosniff", Severity.OK),
    ("X-Content-Type-Options", "NOSNIFF", Severity.OK),
    ("X-Content-Type-Options", "sniff", Severity.MEDIUM),

    # --- Cross-Origin-Opener-Policy ---
    ("Cross-Origin-Opener-Policy", "same-origin", Severity.OK),
    ("Cross-Origin-Opener-Policy", "same-origin-allow-popups", Severity.LOW),
    ("Cross-Origin-Opener-Policy", "unsafe-none", Severity.MEDIUM),
    ("Cross-Origin-Opener-Policy", "bogus", Severity.INFO),

    # --- Cross-Origin-Embedder-Policy ---
    ("Cross-Origin-Embedder-Policy", "require-corp", Severity.OK),
    ("Cross-Origin-Embedder-Policy", "credentialless", Severity.INFO),
    ("Cross-Origin-Embedder-Policy", "unsafe-none", Severity.LOW),
    ("Cross-Origin-Embedder-Policy", "bogus", Severity.INFO),

    # --- Cross-Origin-Resource-Policy ---
    ("Cross-Origin-Resource-Policy", "same-origin", Severity.OK),
    ("Cross-Origin-Resource-Policy", "same-site", Severity.OK),
    ("Cross-Origin-Resource-Policy", "cross-origin", Severity.LOW),
    ("Cross-Origin-Resource-Policy", "bogus", Severity.INFO),

    # --- Referrer-Policy ---
    ("Referrer-Policy", "no-referrer", Severity.OK),
    ("Referrer-Policy", "strict-origin", Severity.OK),
    ("Referrer-Policy", "strict-origin-when-cross-origin", Severity.OK),
    ("Referrer-Policy", "origin", Severity.INFO),
    ("Referrer-Policy", "origin-when-cross-origin", Severity.INFO),
    ("Referrer-Policy", "same-origin", Severity.OK),
    ("Referrer-Policy", "no-referrer-when-downgrade", Severity.HIGH),
    ("Referrer-Policy", "unsafe-url", Severity.HIGH),
    ("Referrer-Policy", "always", Severity.MEDIUM),  # legacy meta value, not a header token
    ("Referrer-Policy", "bogus", Severity.MEDIUM),   # same effect as sending no header

    # --- X-Permitted-Cross-Domain-Policies ---
    ("X-Permitted-Cross-Domain-Policies", "none", Severity.OK),
    ("X-Permitted-Cross-Domain-Policies", "master-only", Severity.OK),
    ("X-Permitted-Cross-Domain-Policies", "all", Severity.MEDIUM),
    ("X-Permitted-Cross-Domain-Policies", "by-content-type", Severity.MEDIUM),
    ("X-Permitted-Cross-Domain-Policies", "bogus", Severity.INFO),

    # --- Cache-Control ---
    ("Cache-Control", "no-store", Severity.OK),
    ("Cache-Control", "no-cache", Severity.OK),
    ("Cache-Control", "private", Severity.OK),
    ("Cache-Control", "max-age=600", Severity.OK),
    ("Cache-Control", "max-age=600, must-revalidate", Severity.OK),
    ("Cache-Control", "public, max-age=600", Severity.INFO),
    ("Cache-Control", "surrogate-control=xyz", Severity.INFO),

    # --- Clear-Site-Data ---
    ("Clear-Site-Data", '"*"', Severity.OK),
    ("Clear-Site-Data", '"cache", "cookies", "storage"', Severity.OK),
    ("Clear-Site-Data", '"cookies"', Severity.LOW),

    # --- Permissions-Policy ---
    ("Permissions-Policy", PP_FULL, Severity.OK),
    ("Permissions-Policy", PP_FULL.replace("camera=()", "camera=*"), Severity.MEDIUM),
    ("Permissions-Policy", "geolocation=()", Severity.MEDIUM),          # high-risk left undeclared

    # --- Origin-Agent-Cluster ---
    ("Origin-Agent-Cluster", "?1", Severity.OK),
    ("Origin-Agent-Cluster", "?0", Severity.LOW),
    ("Origin-Agent-Cluster", "1", Severity.INFO),

    # --- CORS ---
    ("Access-Control-Allow-Origin", "https://trusted.example.com", Severity.OK),
    ("Access-Control-Allow-Origin", "*", Severity.MEDIUM),
    ("Access-Control-Allow-Origin", "null", Severity.HIGH),
    ("Access-Control-Allow-Origin", "NULL", Severity.HIGH),
    ("Access-Control-Allow-Origin", "https://a.example.com, https://b.example.com", Severity.INFO),
    ("Access-Control-Allow-Origin", "http://app.example.com", Severity.LOW),
    ("Access-Control-Allow-Origin", "http://localhost:3000", Severity.LOW),
    ("Access-Control-Allow-Origin", "HTTP://APP.EXAMPLE.COM", Severity.LOW),
    ("Access-Control-Allow-Credentials", "false", Severity.OK),
    # true alone, with no Access-Control-Allow-Origin in the response, has no effect
    ("Access-Control-Allow-Credentials", "true", Severity.INFO),

    # --- Misc ---
    ("X-DNS-Prefetch-Control", "off", Severity.OK),
    ("X-DNS-Prefetch-Control", "on", Severity.INFO),
    ("Service-Worker-Allowed", "/", Severity.LOW),
    ("Service-Worker-Allowed", "/app/", Severity.INFO),
    ("Content-Disposition", "attachment; filename=x.pdf", Severity.OK),
    ("Content-Disposition", "inline", Severity.OK),
    ("Content-Disposition", "bogus", Severity.INFO),
    ("Pragma", "no-cache", Severity.OK),
    ("Expires", "0", Severity.OK),
    ("Expires", "-1", Severity.OK),
    ("Expires", "Wed, 21 Oct 2026 07:28:00 GMT", Severity.OK),
    ("ETag", 'W/"abc"', Severity.OK),
    ("ETag", '"abc"', Severity.OK),
    ("X-Download-Options", "noopen", Severity.OK),
    ("X-Download-Options", "open", Severity.INFO),

    # --- Deprecated ---
    ("X-XSS-Protection", "0", Severity.OK),
    ("X-XSS-Protection", "1; mode=block", Severity.LOW),
    ("X-XSS-Protection", "1", Severity.LOW),
    ("X-XSS-Protection", "1; report=/x", Severity.LOW),
    ("X-XSS-Protection", "0; mode=block", Severity.OK),
    ("X-XSS-Protection", "report=1; mode=block", Severity.INFO),
    ("X-XSS-Protection", "banana", Severity.INFO),
    ("Expect-CT", "max-age=86400, enforce", Severity.INFO),
]


@pytest.mark.parametrize("header,value,expected", CASES,
                         ids=[f"{h}={v[:40]}" for h, v, _ in CASES])
def test_checker_severity(header, value, expected):
    assert severity_for(header, value) == expected


def test_every_checker_returns_at_least_one_finding():
    """A present header must always produce a verdict, never an empty result."""
    for header, value, _ in CASES:
        assert findings_for(header, value), f"{header}: {value} produced no finding"


# ---------------------------------------------------------------------------
# Targeted assertions where the severity alone is not enough
# ---------------------------------------------------------------------------

def test_hsts_reports_each_problem_separately():
    findings = findings_for("Strict-Transport-Security", "max-age=300")
    assert has(findings, "max-age too short")
    assert has(findings, "missing includeSubDomains")


def test_hsts_min_max_age_is_configurable():
    from lib.config import AppConfig, HeaderOverride
    config = AppConfig(overrides={
        'strict-transport-security': HeaderOverride(extra={'min_max_age': 300}),
    })
    assert severity_for("Strict-Transport-Security",
                        "max-age=600; includeSubDomains", config) == Severity.OK


def test_hsts_require_preload_is_off_by_default_and_configurable():
    from lib.config import AppConfig, HeaderOverride
    value = "max-age=31536000; includeSubDomains"
    assert severity_for("Strict-Transport-Security", value) == Severity.OK

    config = AppConfig(overrides={
        'strict-transport-security': HeaderOverride(extra={'require_preload': True}),
    })
    assert has(findings_for("Strict-Transport-Security", value, config), "missing preload")


def test_hsts_rejects_non_integer_min_max_age():
    from lib.config import AppConfig, HeaderOverride
    config = AppConfig(overrides={
        'strict-transport-security': HeaderOverride(extra={'min_max_age': 'one year'}),
    })
    with pytest.raises(ValueError, match="min_max_age"):
        findings_for("Strict-Transport-Security", "max-age=31536000", config)


def test_clear_site_data_lists_the_missing_directives():
    findings = findings_for("Clear-Site-Data", '"cookies"')
    assert has(findings, '"cache"') and has(findings, '"storage"')


def test_permissions_policy_separates_high_and_medium_risk():
    findings = findings_for("Permissions-Policy", "camera=()")
    assert any(f.severity == Severity.MEDIUM and "high-risk" in f.title for f in findings)
    assert any(f.severity == Severity.LOW and "medium-risk" in f.title for f in findings)
    # the declared feature must not be reported as undeclared
    assert not any("camera" in f.title for f in findings)


def test_cache_control_no_store_takes_precedence_over_no_cache():
    findings = findings_for("Cache-Control", "no-store, no-cache")
    assert has(findings, "no-store")
    assert not has(findings, "revalidated before use")


def test_acao_null_is_not_treated_as_a_trusted_origin():
    """Any page can obtain the null origin via a sandboxed iframe, and unlike
    the wildcard it is a concrete origin, so credentials are sent with it."""
    findings = findings_for("Access-Control-Allow-Origin", "null")
    assert has(findings, "null")
    assert not has(findings, "specific origin")


def test_acao_still_accepts_a_real_origin():
    assert severity_for("Access-Control-Allow-Origin", "https://app.example.com") == Severity.OK


def test_acao_multiple_origins_explains_that_nobody_gets_access():
    """The list never matches a requesting origin, so CORS fails closed."""
    findings = findings_for("Access-Control-Allow-Origin", "https://a.example.com, https://b.example.com")
    assert has(findings, "lists more than one origin")
    assert "no site gets access" in findings[0].description


def test_acao_plaintext_origin_is_reported_before_the_ok_branch():
    findings = findings_for("Access-Control-Allow-Origin", "http://app.example.com")
    assert has(findings, "plaintext origin")
    assert not has(findings, "specific origin")


def test_acao_https_origin_stays_ok():
    assert severity_for("Access-Control-Allow-Origin", "https://app.example.com") == Severity.OK


def test_acao_wildcard_names_the_case_that_actually_matters():
    """The old text only mentioned sensitive data, so a reader with an internal
    API concluded it did not apply to them."""
    finding = findings_for("Access-Control-Allow-Origin", "*")[0]
    assert finding.severity == Severity.MEDIUM
    assert "not by an attacker's server" in finding.description
    assert "reachable" in finding.recommendation


# ---------------------------------------------------------------------------
# X-XSS-Protection: the flag is the first token, not any '1' in the value
# ---------------------------------------------------------------------------

def test_xss_filter_enabled_without_mode_block_is_still_a_finding():
    """Enabling the filter lets a crafted URL neutralise a script the page
    legitimately contains, so it does not belong with unrecognised values."""
    findings = findings_for("X-XSS-Protection", "1")
    assert findings[0].severity == Severity.LOW
    assert has(findings, "enables the deprecated XSS filter")


def test_mode_block_finding_explains_the_cross_origin_oracle():
    finding = findings_for("X-XSS-Protection", "1; mode=block")[0]
    assert "observable from another origin" in finding.description


def test_disabled_filter_stays_ok_with_trailing_directives():
    """mode=block is irrelevant once the filter is off."""
    assert severity_for("X-XSS-Protection", "0; mode=block") == Severity.OK
    assert severity_for("X-XSS-Protection", "0;") == Severity.OK


def test_a_digit_inside_a_directive_is_not_the_flag():
    """Regression: 'report=1; mode=block' used to match the substring '1'."""
    assert severity_for("X-XSS-Protection", "report=1; mode=block") == Severity.INFO


# ---------------------------------------------------------------------------
# Directive names read as names, not searched for in the raw value
# ---------------------------------------------------------------------------

def test_qualified_no_cache_is_not_the_same_as_a_bare_one():
    """no-cache="Set-Cookie" only covers that field: the rest of the response
    may be served from cache without revalidation (RFC 9111)."""
    findings = findings_for("Cache-Control", 'no-cache="Set-Cookie"')
    assert findings[0].severity == Severity.INFO
    assert has(findings, "limited to 'Set-Cookie'")


def test_qualified_private_is_not_the_same_as_a_bare_one():
    findings = findings_for("Cache-Control", 'private="X-Custom"')
    assert findings[0].severity == Severity.INFO
    assert has(findings, "limited to 'X-Custom'")


@pytest.mark.parametrize("value", ["no-store", "no-cache", "private"])
def test_bare_cache_directives_are_still_ok(value):
    assert severity_for("Cache-Control", value) == Severity.OK


def test_a_token_merely_containing_a_directive_name_is_unrecognised():
    """'x-no-store-hack' used to be reported as no-store."""
    findings = findings_for("Cache-Control", "x-no-store-hack")
    assert findings[0].severity == Severity.INFO
    assert has(findings, "unrecognized directive")


def test_a_quoted_comma_does_not_split_a_directive():
    assert severity_for("Cache-Control", 'no-cache="X-A,X-B"') == Severity.INFO


@pytest.mark.parametrize("value", [
    "max-age=31536000; includeSubDomainss",     # doubled letter
    "max-age=31536000; xincludeSubDomains",     # spurious prefix
    "max-age=31536000; report-uri=https://x/includeSubDomains",
])
def test_hsts_only_accepts_the_real_directive_name(value):
    """A misspelled directive is an unrecognised one: browsers ignore it, so
    subdomains stay unprotected and that has to be reported."""
    assert has(findings_for("Strict-Transport-Security", value), "missing includeSubDomains")


def test_hsts_accepts_a_quoted_max_age():
    """RFC 6797 §6.1: directive-value = token / quoted-string."""
    value = 'max-age="31536000"; includeSubDomains'
    assert severity_for("Strict-Transport-Security", value) == Severity.OK


def test_hsts_rejects_a_non_numeric_max_age():
    assert has(findings_for("Strict-Transport-Security", "max-age=forever"), "missing max-age")


def test_permissions_policy_wildcard_is_read_from_the_allowlist():
    """A \\b boundary also matches after the hyphen of an unrelated name, so
    'x-payment=*' used to be reported as a wildcard on 'payment'."""
    declared = ", ".join(f"{f}=()" for f in _PP_HIGH + _PP_MEDIUM)
    assert severity_for("Permissions-Policy", declared + ", x-payment=*") == Severity.OK
    assert severity_for("Permissions-Policy", declared.replace("payment=()", "payment=*")) == Severity.MEDIUM


def test_content_disposition_type_is_the_first_token():
    assert severity_for("Content-Disposition", 'attachment; filename="inline.pdf"') == Severity.OK
    assert severity_for("Content-Disposition", "attachmentx") == Severity.INFO


def test_referrer_policy_same_origin_is_strong():
    """It sends nothing at all cross-origin — less than
    strict-origin-when-cross-origin, which sends the origin."""
    assert severity_for("Referrer-Policy", "same-origin") == Severity.OK


def test_referrer_policy_always_is_not_a_header_token():
    """'always' belonged to <meta name="referrer">; the header grammar defines
    eight tokens and skips anything else, so the browser default applies."""
    findings = findings_for("Referrer-Policy", "always")
    assert findings[0].severity == Severity.MEDIUM
    assert has(findings, "unrecognized value")


def test_referrer_policy_unrecognized_value_explains_the_fallback():
    finding = findings_for("Referrer-Policy", "bogus")[0]
    assert "falls back to its own default" in finding.description
    assert "no-referrer-when-downgrade" in finding.recommendation


def test_missing_referrer_policy_explains_the_browser_default():
    finding = analyze("X-Nothing: x")['referrer-policy'].findings[0]
    assert finding.severity == Severity.MEDIUM
    assert "strict-origin-when-cross-origin" in finding.description
    assert "does not control" in finding.description


def test_referrer_policy_invalid_value_weighs_the_same_as_an_absent_header():
    """The browser falls back to its default either way, so the two match."""
    absent = analyze("X-Nothing: x")['referrer-policy'].worst_severity
    assert severity_for("Referrer-Policy", "bogus") == absent


def test_referrer_policy_invalid_value_follows_a_config_override():
    """Not a hardcoded MEDIUM: it tracks whatever absence would score."""
    from lib.config import AppConfig, HeaderOverride
    config = AppConfig(overrides={
        'referrer-policy': HeaderOverride(severity_if_missing='high'),
    })
    assert analyze("X-Nothing: x", config=config)['referrer-policy'].worst_severity == Severity.HIGH
    assert severity_for("Referrer-Policy", "bogus", config) == Severity.HIGH
