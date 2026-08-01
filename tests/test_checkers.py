"""Table-driven tests for the per-header value checkers in lib/rules.py."""
import pytest

from lib.models import Severity, is_issue

from conftest import (
    PP_CLOSED, PP_DEFAULT_ANY_ORIGIN, analyze, findings_for, has, public, severity_for,
)


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
    ("Cross-Origin-Opener-Policy", "noopener-allow-popups", Severity.LOW),
    ("Cross-Origin-Opener-Policy", "unsafe-none", Severity.MEDIUM),
    ("Cross-Origin-Opener-Policy", 'same-origin; report-to="coop"', Severity.OK),
    # Every value a browser cannot apply carries the severity of an absent COOP.
    ("Cross-Origin-Opener-Policy", "bogus", Severity.MEDIUM),
    ("Cross-Origin-Opener-Policy", "same-origin-plus-COEP", Severity.MEDIUM),
    ("Cross-Origin-Opener-Policy", "same-origin;", Severity.MEDIUM),
    ("Cross-Origin-Opener-Policy", "same origin", Severity.MEDIUM),
    ("Cross-Origin-Opener-Policy", "same-origin, same-origin", Severity.MEDIUM),

    # --- Cross-Origin-Embedder-Policy ---
    ("Cross-Origin-Embedder-Policy", "require-corp", Severity.OK),
    ("Cross-Origin-Embedder-Policy", "credentialless", Severity.OK),
    ("Cross-Origin-Embedder-Policy", 'require-corp; report-to="coep"', Severity.OK),
    # Every way of not having COEP is one browser state, graded as the header's absence.
    ("Cross-Origin-Embedder-Policy", "unsafe-none", Severity.INFO),
    ("Cross-Origin-Embedder-Policy", "bogus", Severity.INFO),
    ("Cross-Origin-Embedder-Policy", "require-corp;", Severity.INFO),
    ("Cross-Origin-Embedder-Policy", "require-corp, require-corp", Severity.INFO),

    # --- Cross-Origin-Resource-Policy ---
    ("Cross-Origin-Resource-Policy", "same-origin", Severity.OK),
    ("Cross-Origin-Resource-Policy", "same-site", Severity.OK),
    ("Cross-Origin-Resource-Policy", "cross-origin", Severity.LOW),
    ("Cross-Origin-Resource-Policy", "bogus", Severity.INFO),

    # --- Referrer-Policy ---
    ("Referrer-Policy", "no-referrer", Severity.OK),
    ("Referrer-Policy", "strict-origin", Severity.OK),
    ("Referrer-Policy", "strict-origin-when-cross-origin", Severity.OK),
    ("Referrer-Policy", "origin", Severity.LOW),
    ("Referrer-Policy", "origin-when-cross-origin", Severity.LOW),
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

    # Cache-Control depends on --context; see the dedicated test below.

    # --- Clear-Site-Data ---
    ("Clear-Site-Data", '"*"', Severity.OK),
    ("Clear-Site-Data", '"cache", "cookies", "storage"', Severity.OK),
    ("Clear-Site-Data", '"cookies"', Severity.LOW),

    # --- Permissions-Policy — graded on each feature's default allowlist ---
    ("Permissions-Policy", PP_CLOSED, Severity.INFO),                   # nothing left to an embed
    ("Permissions-Policy", "geolocation=()", Severity.LOW),             # the any-origin nine left open
    ("Permissions-Policy", PP_CLOSED + ", camera=*", Severity.MEDIUM),  # a self default widened

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


def test_permissions_policy_grades_by_the_browser_default_not_by_a_feature_list():
    """camera and payment are allowed to this origin alone whether or not a policy
    names them, so leaving them out opens nothing to an embedded third party. The
    features that do default to every origin are what the issue is about."""
    issues = [f for f in findings_for("Permissions-Policy", "camera=()") if is_issue(f.severity)]
    assert len(issues) == 1
    assert "browsing-topics" in issues[0].title
    assert "payment" not in issues[0].title
    assert "camera" not in issues[0].title      # declared, so not reported as left open


def test_permissions_policy_undeclared_self_default_features_are_not_an_issue():
    findings = findings_for("Permissions-Policy", PP_CLOSED)
    assert not any(is_issue(f.severity) for f in findings)
    assert has(findings, "left at their default of this origin only")


def test_permissions_policy_names_the_check_for_the_any_origin_group():
    """Whether it costs anything depends on what the page embeds, which the
    response cannot say."""
    issues = [f for f in findings_for("Permissions-Policy", "camera=()") if is_issue(f.severity)]
    assert issues[0].recommendation.startswith("Check")
    assert "cross-origin iframes" in issues[0].recommendation


@pytest.mark.parametrize("feature", PP_DEFAULT_ANY_ORIGIN)
def test_permissions_policy_every_any_origin_feature_is_reported_when_left_out(feature):
    left_out = ", ".join(f"{f}=()" for f in PP_DEFAULT_ANY_ORIGIN if f != feature)
    issues = [f for f in findings_for("Permissions-Policy", left_out) if is_issue(f.severity)]
    assert len(issues) == 1
    assert issues[0].title.endswith(feature)


def test_permissions_policy_does_not_ask_for_a_directive_that_was_dropped():
    """document-domain is no longer in the directive set, so recommending it would
    tell the reader to add something a browser ignores."""
    for f in findings_for("Permissions-Policy", "camera=()"):
        assert 'document-domain' not in f.title + f.description + f.recommendation


def test_permissions_policy_everything_declared_is_ok():
    from lib.rules import _PP_DEFAULT_ANY_ORIGIN, _PP_DEFAULT_SELF
    every = ", ".join(f"{f}=()" for f in _PP_DEFAULT_ANY_ORIGIN | _PP_DEFAULT_SELF)
    assert severity_for("Permissions-Policy", every) == Severity.OK


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
    findings = findings_for("Cache-Control", 'no-cache="Set-Cookie"', public())
    assert findings[0].severity == Severity.INFO
    assert has(findings, "limited to 'Set-Cookie'")


def test_qualified_private_is_not_the_same_as_a_bare_one():
    findings = findings_for("Cache-Control", 'private="X-Custom"', public())
    assert findings[0].severity == Severity.INFO
    assert has(findings, "limited to 'X-Custom'")


@pytest.mark.parametrize("value", ["no-store", "no-cache", "private"])
def test_bare_cache_directives_are_still_ok(value):
    assert severity_for("Cache-Control", value, public()) == Severity.OK


def test_a_token_merely_containing_a_directive_name_is_unrecognised():
    """'x-no-store-hack' used to be reported as no-store."""
    findings = findings_for("Cache-Control", "x-no-store-hack", public())
    assert findings[0].severity == Severity.INFO
    assert has(findings, "unrecognized directive")


def test_a_quoted_comma_does_not_split_a_directive():
    assert severity_for("Cache-Control", 'no-cache="X-A,X-B"', public()) == Severity.INFO


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
    assert has(findings_for("Strict-Transport-Security", "max-age=forever"),
               "max-age must be a number of seconds")


def test_permissions_policy_wildcard_is_read_from_the_allowlist():
    """A \\b boundary also matches after the hyphen of an unrelated name, so
    'x-payment=*' used to be reported as a wildcard on 'payment'."""
    assert severity_for("Permissions-Policy", PP_CLOSED + ", x-payment=*") == Severity.INFO
    assert severity_for("Permissions-Policy", PP_CLOSED + ", payment=*") == Severity.MEDIUM


def test_permissions_policy_self_is_not_read_as_an_opening():
    """(self) is the default for these, so stating it changes nothing."""
    assert severity_for("Permissions-Policy", PP_CLOSED + ", camera=(self)") == Severity.INFO


def test_permissions_policy_quoted_comma_does_not_split_a_feature():
    value = PP_CLOSED + ', camera=("https://a.example,https://b.example")'
    assert severity_for("Permissions-Policy", value) == Severity.INFO


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


@pytest.mark.parametrize("value", ["origin", "origin-when-cross-origin"])
def test_referrer_policy_origin_pair_asks_for_a_check_not_a_change(value):
    """Weaker than the strict- variants for nothing in return, so it reaches the
    worklist — but what it costs depends on whether the page reaches a plain-HTTP
    destination, which only the reader can settle."""
    findings = findings_for("Referrer-Policy", value)
    assert any(is_issue(f.severity) for f in findings)
    assert findings[0].recommendation.startswith("Check")
    assert "plain-HTTP" in findings[0].recommendation


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


# ---------------------------------------------------------------------------
# Cache-Control: the one check whose *correct* value depends on --context
# ---------------------------------------------------------------------------

CACHE_CASES = [
    # value,                        public,          authenticated
    ("no-store",                    Severity.OK,     Severity.OK),
    ("private",                     Severity.OK,     Severity.LOW),
    ("private, max-age=600",        Severity.OK,     Severity.LOW),
    ("no-cache",                    Severity.OK,     Severity.MEDIUM),
    ("max-age=0, must-revalidate",  Severity.OK,     Severity.MEDIUM),
    ("max-age=600",                 Severity.OK,     Severity.HIGH),
    ("s-maxage=600",                Severity.OK,     Severity.HIGH),
    ("public, max-age=600",         Severity.INFO,   Severity.HIGH),
    ('no-cache="Set-Cookie"',       Severity.INFO,   Severity.HIGH),
    ('private="X-Custom"',          Severity.INFO,   Severity.HIGH),
    ("surrogate-control=xyz",       Severity.INFO,   Severity.MEDIUM),
]


@pytest.mark.parametrize("value,expected_public,expected_auth", CACHE_CASES,
                         ids=[v for v, *_ in CACHE_CASES])
def test_cache_control_depends_on_the_assumed_context(value, expected_public, expected_auth):
    assert severity_for("Cache-Control", value, public()) == expected_public
    assert severity_for("Cache-Control", value) == expected_auth      # authenticated by default


def test_only_no_store_is_clean_for_an_authenticated_response():
    """private keeps it off shared caches but not off the disk; no-cache stops
    neither, it only forces revalidation."""
    assert severity_for("Cache-Control", "no-store") == Severity.OK
    assert has(findings_for("Cache-Control", "private"), "not off the disk")
    assert has(findings_for("Cache-Control", "no-cache"), "does not stop a shared cache")


def test_a_cacheable_authenticated_response_names_the_leak():
    finding = findings_for("Cache-Control", "max-age=600")[0]
    assert "serve it to the next person" in finding.description


def test_missing_cache_control_is_a_finding_only_in_the_authenticated_context():
    assert analyze("X-Nothing: x")['cache-control'].worst_severity == Severity.MEDIUM
    assert analyze("X-Nothing: x", config=public())['cache-control'].worst_severity == Severity.INFO


def test_cache_control_with_no_understood_directive_matches_an_absent_header():
    """Unrecognised tokens say nothing to a cache, so heuristic freshness applies
    exactly as it does with no header at all."""
    absent = analyze("X-Nothing: x")['cache-control'].worst_severity
    assert severity_for("Cache-Control", "zzz-bogus") == absent
    assert has(findings_for("Cache-Control", "zzz-bogus"), "no directive a cache understands")


def test_one_understood_directive_is_enough_to_be_judged_on_its_merits():
    assert severity_for("Cache-Control", "max-age=600, zzz-bogus") == Severity.HIGH


# ---------------------------------------------------------------------------
# HSTS: a header a browser would throw away is graded like no header at all
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value,reason", [
    ("max-age=1; max-age=31536000", "appears more than once"),
    ("max-age=31536000; includeSubDomains; includeSubDomains", "appears more than once"),
    ("max-age=31536000; includeSubDomains=true", "must not be given a value"),
    ("max-age=31536000; preload=1", "must not be given a value"),
    ("max-age=forever", "must be a number of seconds"),
    ("max-age=-1", "must be a number of seconds"),
    ("includeSubDomains", "required max-age directive is missing"),
])
def test_hsts_header_that_does_not_conform_is_graded_as_absent(value, reason):
    """RFC 6797 §6.1: a non-conforming header is ignored in full, so the site has
    no HSTS — reporting it as configured would be the worst kind of wrong."""
    absent = analyze("X-Nothing: x")['strict-transport-security'].worst_severity
    findings = findings_for("Strict-Transport-Security", value)
    assert findings[0].severity == absent
    assert has(findings, "the header is not valid")
    assert has(findings, reason)


def test_hsts_names_the_offending_directive_as_it_is_spelled():
    assert has(findings_for("Strict-Transport-Security", "max-age=1; includeSubDomains=true"),
               "includeSubDomains must not be given a value")


def test_hsts_ignores_unrecognised_directives():
    """RFC 6797: unknown directives are skipped and the rest is processed."""
    value = "max-age=31536000; includeSubDomains; some-future-directive"
    assert severity_for("Strict-Transport-Security", value) == Severity.OK


def test_hsts_accepts_the_quoted_form_the_rfc_shows():
    assert severity_for("Strict-Transport-Security",
                        'max-age="31536000"; includeSubDomains') == Severity.OK


# ---------------------------------------------------------------------------
# COOP: one token plus optional parameters, and nothing else applies
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    'same-origin; report-to="coop-endpoint"',
    'same-origin;report-to=coop',
    'same-origin; report-to="a;b"',        # the separator inside a quoted string
])
def test_coop_parameters_do_not_change_the_policy(value):
    """HTML §7.1.3.1 allows the token to carry parameters, of which only report-to
    is defined. None of them decides which policy applies, so a header configured
    with a reporting endpoint is still plain same-origin."""
    assert severity_for("Cross-Origin-Opener-Policy", value) == Severity.OK


@pytest.mark.parametrize("value,reason", [
    ("bogus", "is not a policy browsers recognize"),
    ("restrict-properties", "is not a policy browsers recognize"),
    ("same-origin-plus-COEP", "cannot be set through this header"),
    ("same origin", "is not a valid header value"),        # a space ends the token
    ('"same-origin"', "is not a valid header value"),       # a string, not a token
    ("same-origin;", "is not a valid header value"),        # RFC 8941 §4.2.3.2: no key
    ("same-origin; =x", "is not a valid header value"),
])
def test_coop_value_a_browser_cannot_apply_is_graded_as_absent(value, reason):
    """An unusable value leaves the policy at unsafe-none, which is where a
    response with no COOP already is."""
    absent = analyze("X-Nothing: x")['cross-origin-opener-policy'].worst_severity
    findings = findings_for("Cross-Origin-Opener-Policy", value)
    assert findings[0].severity == absent
    assert has(findings, "the header is not applied")
    assert has(findings, reason)


def test_coop_same_origin_plus_coep_says_how_to_actually_get_it():
    findings = findings_for("Cross-Origin-Opener-Policy", "same-origin-plus-COEP")
    assert "require-corp" in findings[0].recommendation


def test_coop_noopener_allow_popups_is_recognized():
    """A real value (Chromium, Safari) — it must not fall into the unusable branch."""
    findings = findings_for("Cross-Origin-Opener-Policy", "noopener-allow-popups")
    assert not has(findings, "the header is not applied")


def test_coop_noopener_allow_popups_matches_same_origin_allow_popups():
    """Per the Window.open() table in the HTML spec both keep a popup with no COOP
    in the same browsing context group, so both carry the same residual exposure."""
    assert (severity_for("Cross-Origin-Opener-Policy", "noopener-allow-popups")
            == severity_for("Cross-Origin-Opener-Policy", "same-origin-allow-popups"))


@pytest.mark.parametrize("value", ["same-origin-allow-popups", "noopener-allow-popups"])
def test_coop_allow_popups_reaches_the_worklist(value):
    """Weaker than same-origin, so it is an issue and appears in --format list.
    Whether the weakening costs anything depends on what the document opens, which
    the reader can check and the response cannot say — so it is reported, not
    silently accepted."""
    findings = findings_for("Cross-Origin-Opener-Policy", value)
    assert any(is_issue(f.severity) for f in findings)
    assert "window.opener" in findings[0].description
    assert "windows it does not control" in findings[0].description


@pytest.mark.parametrize("value", ["same-origin-allow-popups", "noopener-allow-popups"])
def test_coop_allow_popups_asks_for_a_check_not_a_change(value):
    """The reader cannot act on 'use same-origin' without first knowing what the
    page opens — the finding has to name the check, not just the fix."""
    recommendation = findings_for("Cross-Origin-Opener-Policy", value)[0].recommendation
    assert recommendation.startswith("Check")
    assert "window.open()" in recommendation
    assert "same-origin" in recommendation


# ---------------------------------------------------------------------------
# COEP: the same structured-item shape, graded as one browser state
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "unsafe-none",                  # the default, stated
    "bogus",                        # unrecognised token
    "require-corp;",                # RFC 8941 §4.2.3.2: a parameter needs a key
    "require-corp, require-corp",   # what a browser sees when it is sent twice
])
def test_coep_every_way_of_not_having_it_matches_an_absent_header(value):
    """MDN: 'Setting the header more than once or with multiple tokens is
    equivalent to setting unsafe-none.' unsafe-none is also what a browser applies
    with no header at all, so all of these are one state and carry one severity."""
    absent = analyze("X-Nothing: x")['cross-origin-embedder-policy'].worst_severity
    assert severity_for("Cross-Origin-Embedder-Policy", value) == absent


def test_coep_not_having_it_is_not_reported_as_an_exposure():
    """Losing cross-origin isolation withdraws a capability rather than opening
    anything — the finding has to say so, or the severity reads as an oversight."""
    findings = findings_for("Cross-Origin-Embedder-Policy", "unsafe-none")
    assert "fails safe" in findings[0].description


def test_coep_credentialless_is_not_called_weaker_than_require_corp():
    """Both qualify for cross-origin isolation; credentialless reaches it by
    stripping credentials instead of demanding CORP, which is a different
    mechanism for the same guarantee."""
    findings = findings_for("Cross-Origin-Embedder-Policy", "credentialless")
    assert severity_for("Cross-Origin-Embedder-Policy", "credentialless") == Severity.OK
    assert findings[0].recommendation == ""
    assert "not a weaker one" in findings[0].description


def test_coep_require_corp_does_not_claim_isolation_on_its_own():
    findings = findings_for("Cross-Origin-Embedder-Policy", "require-corp")
    assert "Cross-Origin-Opener-Policy: same-origin" in findings[0].description


def test_coep_report_to_parameter_does_not_change_the_policy():
    assert severity_for("Cross-Origin-Embedder-Policy",
                        'require-corp; report-to="coep"') == Severity.OK


def test_coop_unusable_value_follows_a_config_override():
    """The grading tracks whatever the profile says an absent COOP is worth."""
    from lib.config import AppConfig, HeaderOverride
    config = AppConfig(overrides={
        'cross-origin-opener-policy': HeaderOverride(severity_if_missing='high'),
    })
    assert analyze("X-Nothing: x", config=config)['cross-origin-opener-policy'].worst_severity == Severity.HIGH
    assert severity_for("Cross-Origin-Opener-Policy", "bogus", config) == Severity.HIGH
