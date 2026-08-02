"""Table-driven tests for the per-header value checkers in lib/rules.py."""
import pytest

from lib.models import Severity, is_issue

from conftest import (
    PP_CLOSED, PP_TRACKING, analyze, findings_for, has, severity_for,
)


# (header, value, expected worst severity)
CASES = [
    # --- Strict-Transport-Security ---
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains", Severity.OK),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload", Severity.OK),
    ("Strict-Transport-Security", "MAX-AGE=31536000; INCLUDESUBDOMAINS", Severity.OK),
    ("Strict-Transport-Security", "max-age = 31536000; includeSubDomains", Severity.OK),
    ("Strict-Transport-Security", "max-age=31536000", Severity.MEDIUM),
    ("Strict-Transport-Security", "max-age=300; includeSubDomains", Severity.MEDIUM),
    ("Strict-Transport-Security", "max-age=0; includeSubDomains", Severity.HIGH),
    ("Strict-Transport-Security", "includeSubDomains", Severity.HIGH),

    # --- X-Frame-Options ---
    ("X-Frame-Options", "DENY", Severity.OK),
    ("X-Frame-Options", "deny", Severity.OK),
    ("X-Frame-Options", "SAMEORIGIN", Severity.LOW),   # weaker than DENY, contingent
    # Neither is applied by any browser, so both leave the page where an absent
    # header leaves it.
    ("X-Frame-Options", "ALLOW-FROM https://example.com", Severity.HIGH),
    ("X-Frame-Options", "ALLOWALL", Severity.HIGH),
    # The browser works on a set: repeats collapse, and a mixture that still holds
    # a usable value blocks rather than falling back.
    ("X-Frame-Options", "DENY, DENY", Severity.OK),
    ("X-Frame-Options", "DENY, SAMEORIGIN", Severity.NOTE),
    ("X-Frame-Options", "SAMEORIGIN, bogus", Severity.NOTE),
    ("X-Frame-Options", "bogus, garbage", Severity.HIGH),

    # --- X-Content-Type-Options ---
    ("X-Content-Type-Options", "nosniff", Severity.OK),
    ("X-Content-Type-Options", "NOSNIFF", Severity.OK),
    ("X-Content-Type-Options", "sniff", Severity.MEDIUM),
    # Fetch compares values[0] only: what follows a comma cannot switch it on or off.
    ("X-Content-Type-Options", "nosniff, foo", Severity.OK),
    ("X-Content-Type-Options", "nosniff, nosniff", Severity.OK),
    ("X-Content-Type-Options", "foo, nosniff", Severity.MEDIUM),
    ("X-Content-Type-Options", '"nosniff"', Severity.MEDIUM),

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
    # §8.1 keeps the last valid token and skips the rest, which is what makes a
    # list the recommended shape rather than a mistake.
    ("Referrer-Policy", "no-referrer, strict-origin-when-cross-origin", Severity.OK),
    ("Referrer-Policy", "bogus, no-referrer", Severity.OK),
    ("Referrer-Policy", "no-referrer,", Severity.OK),
    ("Referrer-Policy", "strict-origin-when-cross-origin, unsafe-url", Severity.HIGH),
    ("Referrer-Policy", "unsafe-url, bogus", Severity.HIGH),

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
    ("Permissions-Policy", PP_CLOSED, Severity.OK),                     # both axes closed
    ("Permissions-Policy", "geolocation=()", Severity.LOW),             # neither axis closed
    ("Permissions-Policy", PP_CLOSED + ", camera=*", Severity.MEDIUM),  # a self default widened

    # --- Origin-Agent-Cluster ---
    ("Origin-Agent-Cluster", "?1", Severity.OK),
    ("Origin-Agent-Cluster", "?0", Severity.LOW),
    ("Origin-Agent-Cluster", "1", Severity.INFO),

    # --- CORS ---
    ("Access-Control-Allow-Origin", "https://trusted.example.com", Severity.HIGH),
    ("Access-Control-Allow-Origin", "*", Severity.HIGH),
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


def _every_finding():
    """Every finding the table above can produce, plus those for an absent header."""
    for header, value, _ in CASES:
        yield f"{header}: {value}", findings_for(header, value)
    for result in analyze("X-Nothing: x").values():
        yield f"missing {result.canonical_name}", result.findings


def test_a_finding_never_carries_both_a_check_and_a_recommendation():
    """Until the check is done there is nothing to recommend: offering both invites
    the reader to act on a finding that may not apply to this target."""
    for where, findings in _every_finding():
        for f in findings:
            assert not (f.verify and f.recommendation), f"{where} — {f.title}"


def test_every_check_asks_something_the_reader_can_answer():
    """A check that only says 'confirm this' is a reminder to skip. It has to name
    the question, and the per-finding tests below pin what each outcome means."""
    for where, findings in _every_finding():
        for f in findings:
            if not f.verify:
                continue
            assert len(f.verify) > 80, f"{where} — {f.title}"
            assert '?' in f.verify or f.verify.startswith('Replay'), f"{where} — {f.title}"


def test_a_settled_finding_claims_the_response_is_enough():
    """The empty verify is a claim, not an omission: nothing outside the response
    changes what max-age=300 or a missing CSP means."""
    assert not findings_for("Strict-Transport-Security", "max-age=300")[0].verify
    assert not analyze("X-Nothing: x")['content-security-policy'].findings[0].verify


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


def test_hsts_preload_is_not_asked_about_unless_a_profile_asks():
    """preload is not defined by RFC 6797 — it is a submission convention, so the
    tool says nothing about it until a profile opts in."""
    from lib.config import AppConfig, HeaderOverride
    value = "max-age=31536000; includeSubDomains"
    assert severity_for("Strict-Transport-Security", value) == Severity.OK

    config = AppConfig(overrides={
        'strict-transport-security': HeaderOverride(extra={'require_preload': True}),
    })
    assert has(findings_for("Strict-Transport-Security", value, config), "preload is not declared")


@pytest.mark.parametrize("value,title", [
    ("max-age=31536000; includeSubDomains", "preload is not declared"),
    ("max-age=31536000; includeSubDomains; preload", "not the same as being on the list"),
])
def test_hsts_preload_is_contingent_either_way(value, title):
    """The token is a declaration of intent; membership of the list is a separate
    step the response cannot show. Whichever way the header reads, the same lookup
    settles it — and if the domain is not listed, both land in the same place."""
    from lib.config import AppConfig, HeaderOverride
    config = AppConfig(overrides={
        'strict-transport-security': HeaderOverride(extra={'require_preload': True}),
    })
    finding = next(f for f in findings_for("Strict-Transport-Security", value, config)
                   if 'preload' in f.title)
    assert finding.severity == Severity.LOW
    assert finding.is_contingent
    assert "hstspreload.org" in finding.verify


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


def _issues(value):
    return [f for f in findings_for("Permissions-Policy", value) if is_issue(f.severity)]


def _pp(value, axis):
    return [f for f in findings_for("Permissions-Policy", value) if axis in f.title]


def test_permissions_policy_is_graded_on_two_separate_axes():
    """One finding for what an embedded document can reach, one for what an XSS on
    this origin can reach. They answer different questions and close differently."""
    titles = [f.title for f in findings_for("Permissions-Policy", "payment=()")]
    assert any("available to any embedded document" in t for t in titles)
    assert any("an XSS on this origin" in t for t in titles)


def test_permissions_policy_only_the_xss_axis_reaches_the_worklist():
    """What an ad or analytics frame can measure is the user's privacy toward a
    party the site chose to embed — often the very thing the frame is there for.
    The XSS axis is an exposure of the application, and is graded as one."""
    issues = _issues("payment=()")
    assert len(issues) == 1
    assert "an XSS on this origin" in issues[0].title
    embed = _pp("payment=()", "available to any embedded document")
    assert embed and embed[0].severity == Severity.INFO


@pytest.mark.parametrize("feature", ['camera', 'microphone', 'geolocation'])
def test_permissions_policy_self_does_not_close_a_feature_to_an_xss(feature):
    """(self) authorises this origin, and an XSS runs on this origin. Only ()
    removes the prompt — reading this as 'declared, therefore handled' would be a
    reassuring falsehood."""
    assert any("an XSS on this origin" in f.title for f in _issues(f"{feature}=(self)"))
    closed = ", ".join(f"{f}=()" for f in ('camera', 'microphone', 'geolocation'))
    assert not any("an XSS on this origin" in f.title for f in _issues(closed))


def test_permissions_policy_self_does_close_a_feature_to_an_embed():
    """The other axis works the other way round: (self) excludes every other origin,
    so an embedded document is already shut out."""
    at_self = ", ".join(f"{f}=(self)" for f in PP_TRACKING)
    assert not _pp(at_self, "embedded document")


@pytest.mark.parametrize("feature", PP_TRACKING)
def test_permissions_policy_every_tracking_feature_is_reported_when_left_open(feature):
    left_out = ", ".join(f"{f}=()" for f in PP_TRACKING if f != feature)
    embed = _pp(left_out, "embedded document")
    assert len(embed) == 1
    assert embed[0].title.endswith(feature)


def test_permissions_policy_does_not_dilute_the_embed_finding():
    """gamepad, picture-in-picture and deferred-fetch-minimal are open the same way
    and carry nothing worth reporting; naming them in the title buries the six."""
    embed = _pp("payment=()", "embedded document")[0]
    for noise in ('gamepad', 'picture-in-picture', 'deferred-fetch-minimal'):
        assert noise not in embed.title
        assert noise in embed.description      # accounted for, not silently dropped


def test_permissions_policy_both_findings_carry_their_check():
    for finding in findings_for("Permissions-Policy", "payment=()"):
        assert finding.is_contingent


def test_permissions_policy_absent_matches_a_policy_that_closes_nothing():
    """No header and a policy that closes neither axis leave the same state, so a
    site that declares an unrelated feature must not appear to have improved."""
    absent = analyze("X-Nothing: x")['permissions-policy']
    assert absent.worst_severity == max(f.severity for f in _issues("payment=()"))


def test_permissions_policy_absent_covers_both_axes():
    absent = analyze("X-Nothing: x")['permissions-policy'].findings[0]
    assert 'browsing-topics' in absent.description
    assert 'camera' in absent.description
    assert 'storage-access=()' in absent.recommendation
    assert 'camera=()' in absent.recommendation


def test_permissions_policy_does_not_ask_for_a_directive_that_was_dropped():
    """document-domain is no longer in the directive set, so recommending it would
    tell the reader to add something a browser ignores."""
    for f in findings_for("Permissions-Policy", "camera=()"):
        assert 'document-domain' not in f.title + f.description + f.recommendation


def test_permissions_policy_closing_both_axes_is_ok():
    assert severity_for("Permissions-Policy", PP_CLOSED) == Severity.OK


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


def test_acao_single_origin_is_graded_as_the_reflected_case():
    """An allowlist and a mirror produce the same bytes. If it is a mirror, the
    authorised origin is whichever one asked — the wildcard by another route."""
    findings = findings_for("Access-Control-Allow-Origin", "https://app.example.com")
    assert findings[0].severity == Severity.HIGH
    assert findings[0].is_contingent
    assert severity_for("Access-Control-Allow-Origin", "https://app.example.com") == \
           severity_for("Access-Control-Allow-Origin", "*")


def test_acao_multiple_origins_explains_that_nobody_gets_access():
    """The list never matches a requesting origin, so CORS fails closed."""
    findings = findings_for("Access-Control-Allow-Origin", "https://a.example.com, https://b.example.com")
    assert has(findings, "lists more than one origin")
    assert "no site gets access" in findings[0].description


def test_acao_plaintext_origin_is_reported_before_the_ok_branch():
    findings = findings_for("Access-Control-Allow-Origin", "http://app.example.com")
    assert has(findings, "plaintext origin")
    assert not has(findings, "specific origin")


def test_acao_single_origin_names_the_replay_and_both_outcomes():
    finding = findings_for("Access-Control-Allow-Origin", "https://app.example.com")[0]
    assert "Origin: https://an-origin-you-made-up.example" in finding.verify
    assert "comes back" in finding.verify
    assert "nothing here" in finding.verify
    assert "https://app.example.com" in finding.verify   # what a real allowlist keeps naming


def test_acao_wildcard_names_the_case_that_actually_matters():
    """The old text only mentioned sensitive data, so a reader with an internal
    API concluded it did not apply to them."""
    finding = findings_for("Access-Control-Allow-Origin", "*")[0]
    assert finding.severity == Severity.HIGH
    assert "not by an attacker's server" in finding.description
    assert "reachable" in finding.verify


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

@pytest.mark.parametrize("qualified,bare,bare_severity", [
    ('no-cache="Set-Cookie"', "no-cache", Severity.MEDIUM),
    ('private="X-Custom"', "private", Severity.LOW),
])
def test_a_qualified_directive_is_not_the_same_as_a_bare_one(qualified, bare, bare_severity):
    """With an argument these cover only the fields they name, so the rest of the
    response is treated as if the directive were absent (RFC 9111)."""
    assert severity_for("Cache-Control", bare) == bare_severity
    findings = findings_for("Cache-Control", qualified)
    assert findings[0].severity == Severity.HIGH
    assert "covers only the fields it names" in findings[0].description


def test_the_bare_directives_are_ordered_by_what_they_actually_prevent():
    """no-store keeps it out of every cache, private only out of the shared ones,
    no-cache out of neither — it forces revalidation and nothing more."""
    assert (severity_for("Cache-Control", "no-store")
            < severity_for("Cache-Control", "private")
            < severity_for("Cache-Control", "no-cache"))


def test_a_token_merely_containing_a_directive_name_is_unrecognised():
    """'x-no-store-hack' used to be reported as no-store."""
    findings = findings_for("Cache-Control", "x-no-store-hack")
    assert has(findings, "no directive a cache understands")


def test_a_quoted_comma_does_not_split_a_directive():
    findings = findings_for("Cache-Control", 'no-cache="X-A,X-B"')
    assert "X-A,X-B" in findings[0].description


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
    assert severity_for("Permissions-Policy", PP_CLOSED + ", x-payment=*") == Severity.OK
    assert severity_for("Permissions-Policy", PP_CLOSED + ", payment=*") == Severity.MEDIUM


def test_permissions_policy_self_on_a_self_default_is_not_an_opening():
    """(self) restates the default for these, so it opens nothing to an embed."""
    assert severity_for("Permissions-Policy", PP_CLOSED + ", payment=(self)") == Severity.OK


def test_permissions_policy_quoted_comma_does_not_split_a_feature():
    value = PP_CLOSED + ', payment=("https://a.example,https://b.example")'
    assert severity_for("Permissions-Policy", value) == Severity.OK


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
    assert findings[0].is_contingent
    assert "plain-HTTP" in findings[0].verify


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
# Cache-Control: graded for the case where caching costs something
# ---------------------------------------------------------------------------

CACHE_CASES = [
    ("no-store",                    Severity.OK),
    ("private",                     Severity.LOW),
    ("private, max-age=600",        Severity.LOW),
    ("no-cache",                    Severity.MEDIUM),
    ("max-age=0, must-revalidate",  Severity.MEDIUM),
    ("surrogate-control=xyz",       Severity.MEDIUM),   # nothing a cache understands
    ("max-age=600",                 Severity.HIGH),
    ("s-maxage=600",                Severity.HIGH),
    ("public, max-age=600",         Severity.HIGH),
    ('no-cache="Set-Cookie"',       Severity.HIGH),
    ('private="X-Custom"',          Severity.HIGH),
]


@pytest.mark.parametrize("value,expected", CACHE_CASES, ids=[v for v, _ in CACHE_CASES])
def test_cache_control_grading(value, expected):
    assert severity_for("Cache-Control", value) == expected


def test_only_no_store_is_clean():
    """private keeps it off shared caches but not off the disk; no-cache stops
    neither, it only forces revalidation."""
    assert severity_for("Cache-Control", "no-store") == Severity.OK
    assert has(findings_for("Cache-Control", "private"), "not off the disk")
    assert has(findings_for("Cache-Control", "no-cache"), "does not stop a shared cache")


def test_a_cacheable_response_names_the_leak():
    finding = findings_for("Cache-Control", "max-age=600")[0]
    assert "serve it to the next person" in finding.description


@pytest.mark.parametrize("value", [v for v, sev in CACHE_CASES if sev != Severity.OK])
def test_every_caching_verdict_but_no_store_carries_the_same_question(value):
    """Whether the response carries a signed-in user's data decides all of them,
    and it is not in the response. no-store needs no question: it is right either
    way, at worst costing bandwidth."""
    assert findings_for("Cache-Control", value)[0].is_contingent
    assert not findings_for("Cache-Control", "no-store")[0].is_contingent


def test_missing_cache_control_carries_the_question_too():
    result = analyze("X-Nothing: x")['cache-control']
    assert result.worst_severity == Severity.MEDIUM
    assert result.findings[0].is_contingent
    assert "signed-in user" in result.findings[0].verify


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
    verify = findings_for("Cross-Origin-Opener-Policy", value)[0].verify
    assert "window.open()" in verify
    assert "same-origin" in verify


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


@pytest.mark.parametrize("value", ["max-age=0", "max-age=0; includeSubDomains"])
def test_hsts_max_age_zero_is_the_only_verdict(value):
    """The entry is deleted, so there is no policy left for the other directives to
    qualify — advising includeSubDomains on top would be advice about nothing."""
    findings = findings_for("Strict-Transport-Security", value)
    assert len(findings) == 1
    assert has(findings, "revokes HSTS protection")


def test_hsts_max_age_zero_weighs_the_same_as_an_absent_header():
    """Both leave the site with no HSTS, so both track whatever the profile says
    an absent one is worth."""
    absent = analyze("X-Nothing: x")['strict-transport-security'].worst_severity
    assert severity_for("Strict-Transport-Security", "max-age=0") == absent

    from lib.config import AppConfig, HeaderOverride
    config = AppConfig(overrides={
        'strict-transport-security': HeaderOverride(severity_if_missing='medium'),
    })
    assert severity_for("Strict-Transport-Security", "max-age=0", config) == Severity.MEDIUM


def test_hsts_missing_include_subdomains_does_not_depend_on_having_subdomains():
    """The attacker picks the name, so a site with none is not exempt — the text has
    to say so, or a reader concludes the finding is not about them."""
    finding = next(f for f in findings_for("Strict-Transport-Security", "max-age=31536000")
                   if "includeSubDomains" in f.title)
    assert finding.severity == Severity.MEDIUM
    assert not finding.is_contingent
    assert "no subdomains at all is not exempt" in finding.description
    assert "Domain=example.com" in finding.description      # names the mechanism


# ---------------------------------------------------------------------------
# X-Content-Type-Options: only the first value decides
# ---------------------------------------------------------------------------

def test_nosniff_is_read_as_the_first_value_not_the_whole_header():
    """Fetch's determine-nosniff splits on commas and compares values[0], so a
    proxy that appends to the header instead of adding a line does not switch the
    protection off — and reporting that it did would be a false alarm."""
    assert severity_for("X-Content-Type-Options", "nosniff, nosniff") == Severity.OK
    assert severity_for("X-Content-Type-Options", "nosniff , x") == Severity.OK
    assert severity_for("X-Content-Type-Options", "x, nosniff") != Severity.OK


def test_nosniff_does_not_accept_the_quoted_form():
    """The splitting algorithm keeps the quotes inside the value, so values[0] is
    '"nosniff"' and does not match — unlike HSTS, where the RFC allows quoting."""
    assert severity_for("X-Content-Type-Options", '"nosniff"') != Severity.OK


def test_nosniff_off_weighs_the_same_as_an_absent_header():
    absent = analyze("X-Nothing: x")['x-content-type-options'].worst_severity
    assert severity_for("X-Content-Type-Options", "sniff") == absent

    from lib.config import AppConfig, HeaderOverride
    config = AppConfig(overrides={
        'x-content-type-options': HeaderOverride(severity_if_missing='high'),
    })
    assert severity_for("X-Content-Type-Options", "sniff", config) == Severity.HIGH


def test_nosniff_finding_says_what_is_left_on():
    finding = findings_for("X-Content-Type-Options", "sniff")[0]
    assert "leaves MIME sniffing on" in finding.title
    assert "uploaded" in finding.description


@pytest.mark.parametrize("value", ["ALLOW-FROM https://partner.example", "ALLOWALL", "bogus"])
def test_a_frame_options_value_no_browser_applies_weighs_the_same_as_an_absent_header(value):
    """ALLOW-FROM is the one that misleads: a browser does not ignore the directive
    and keep the header, it discards the header — so the page is framable while the
    response looks like it has a policy."""
    absent = analyze("X-Nothing: x")['x-frame-options'].worst_severity
    findings = findings_for("X-Frame-Options", value)
    assert findings[0].severity == absent
    assert "framable by anyone" in findings[0].title


def test_frame_options_unusable_value_follows_a_config_override():
    from lib.config import AppConfig, HeaderOverride
    config = AppConfig(overrides={'x-frame-options': HeaderOverride(severity_if_missing='medium')})
    assert severity_for("X-Frame-Options", "ALLOWALL", config) == Severity.MEDIUM


def test_frame_options_repeated_value_is_still_a_deny():
    """The values go into a set, so DENY twice is one entry and blocks — reporting
    a framable page would be the false alarm."""
    assert severity_for("X-Frame-Options", "DENY, DENY") == Severity.OK


@pytest.mark.parametrize("value", ["DENY, SAMEORIGIN", "SAMEORIGIN, bogus", "ALLOWALL, DENY"])
def test_frame_options_contradiction_is_stated_not_graded(value):
    """The outcome is the strongest one and the same in every browser, so there is
    no weakness to grade. What is left is a deployment fact: two components are
    writing this header, and they may be writing others."""
    findings = findings_for("X-Frame-Options", value)
    assert findings[0].severity == Severity.NOTE
    assert not is_issue(findings[0].severity)
    assert "contradicting itself" in findings[0].title


def test_a_frame_options_contradiction_is_never_more_permissive():
    """`allowall, bogus` blocks where either value alone would not — which is why
    the contradiction is not graded as a weakness."""
    assert severity_for("X-Frame-Options", "ALLOWALL") == \
           analyze("X-Nothing: x")['x-frame-options'].worst_severity
    assert severity_for("X-Frame-Options", "ALLOWALL, bogus") == Severity.NOTE


def test_frame_options_sameorigin_asks_whether_the_page_needs_framing():
    finding = findings_for("X-Frame-Options", "SAMEORIGIN")[0]
    assert finding.severity == Severity.LOW
    assert finding.is_contingent
    assert "DENY costs nothing" in finding.verify
    assert "every containing document" in finding.description   # as strong as 'self'


# ---------------------------------------------------------------------------
# Referrer-Policy: the last valid token wins, the rest are skipped
# ---------------------------------------------------------------------------

def test_referrer_policy_list_is_the_shape_the_spec_recommends():
    """§8.1's own note: the loop exists so a site can name a new policy after an
    older one and let each browser take the last it understands. Reporting that as
    'no policy in force' flags the deployment the spec asks for."""
    findings = findings_for("Referrer-Policy", "no-referrer, strict-origin-when-cross-origin")
    assert findings[0].severity == Severity.OK
    assert "strict-origin-when-cross-origin" in findings[0].title


def test_referrer_policy_grades_the_token_that_survives_not_the_first():
    """The dangerous direction: a weak token after a strong one is the one applied,
    and calling the whole value unrecognised would report MEDIUM for a HIGH."""
    assert severity_for("Referrer-Policy", "strict-origin-when-cross-origin, unsafe-url") \
           == Severity.HIGH
    assert has(findings_for("Referrer-Policy", "strict-origin-when-cross-origin, unsafe-url"),
               "unsafe-url")


@pytest.mark.parametrize("value", ["unsafe-url, bogus", "unsafe-url,", "unsafe-url, always"])
def test_referrer_policy_unknown_and_empty_tokens_are_skipped_not_honoured(value):
    """An unknown token does not clear the policy — it is passed over, so what a
    browser applies is still the last one it recognised."""
    assert severity_for("Referrer-Policy", value) == Severity.HIGH


def test_referrer_policy_with_no_valid_token_at_all_is_still_absent():
    absent = analyze("X-Nothing: x")['referrer-policy'].worst_severity
    assert severity_for("Referrer-Policy", "bogus, nonsense") == absent
