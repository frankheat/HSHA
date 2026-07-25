"""Table-driven tests for the per-header value checkers in lib/rules.py."""
import pytest

from lib.models import Severity

from conftest import findings_for, has, severity_for

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
    ("Referrer-Policy", "origin", Severity.LOW),
    ("Referrer-Policy", "same-origin", Severity.LOW),
    ("Referrer-Policy", "no-referrer-when-downgrade", Severity.LOW),
    ("Referrer-Policy", "unsafe-url", Severity.HIGH),
    ("Referrer-Policy", "always", Severity.HIGH),
    ("Referrer-Policy", "bogus", Severity.INFO),

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
    ("Access-Control-Allow-Credentials", "false", Severity.OK),
    ("Access-Control-Allow-Credentials", "true", Severity.MEDIUM),

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
    ("X-XSS-Protection", "1", Severity.INFO),
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
