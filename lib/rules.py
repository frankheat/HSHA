"""
OWASP-based header rule engine.
Each checker returns a list[Finding] given (header_value, extra_config_dict).
"""
import re
from typing import Callable, Optional

from .config import AppConfig, HeaderOverride, get_override
from .csp_evaluator import evaluate_csp
from .models import Finding, HeaderResult, Severity

# ---------------------------------------------------------------------------
# Registry of headers to check
# (key, canonical_name, required_by_default, severity_if_missing_default)
# ---------------------------------------------------------------------------
SECURITY_HEADERS: list[tuple[str, str, bool, Severity]] = [
    ("content-security-policy",          "Content-Security-Policy",          True,  Severity.HIGH),
    ("strict-transport-security",        "Strict-Transport-Security",        True,  Severity.HIGH),
    ("x-frame-options",                  "X-Frame-Options",                  True,  Severity.HIGH),
    ("x-content-type-options",           "X-Content-Type-Options",           True,  Severity.MEDIUM),
    ("cross-origin-opener-policy",       "Cross-Origin-Opener-Policy",       True,  Severity.MEDIUM),
    ("permissions-policy",               "Permissions-Policy",               True,  Severity.MEDIUM),
    ("referrer-policy",                  "Referrer-Policy",                  True,  Severity.MEDIUM),
    ("cross-origin-embedder-policy",     "Cross-Origin-Embedder-Policy",     False, Severity.LOW),
    ("cross-origin-resource-policy",     "Cross-Origin-Resource-Policy",     False, Severity.LOW),
    ("x-permitted-cross-domain-policies","X-Permitted-Cross-Domain-Policies",False, Severity.LOW),
    ("cache-control",                    "Cache-Control",                    False, Severity.INFO),
    ("clear-site-data",                  "Clear-Site-Data",                  False, Severity.INFO),
    ("x-dns-prefetch-control",           "X-DNS-Prefetch-Control",           False, Severity.INFO),
    ("origin-agent-cluster",             "Origin-Agent-Cluster",             False, Severity.INFO),
    ("access-control-allow-origin",      "Access-Control-Allow-Origin",      False, Severity.INFO),
    ("access-control-allow-credentials", "Access-Control-Allow-Credentials", False, Severity.INFO),
    ("service-worker-allowed",           "Service-Worker-Allowed",           False, Severity.INFO),
    ("content-disposition",              "Content-Disposition",              False, Severity.INFO),
    ("pragma",                           "Pragma",                           False, Severity.INFO),
    ("expires",                          "Expires",                          False, Severity.INFO),
    ("etag",                             "ETag",                             False, Severity.INFO),
    ("x-download-options",               "X-Download-Options",               False, Severity.INFO),
    # Deprecated — worth flagging if present with wrong value
    ("x-xss-protection",                 "X-XSS-Protection",                 False, Severity.INFO),
    ("expect-ct",                        "Expect-CT",                        False, Severity.INFO),
]

_DEFAULT_KEYS = {k for k, *_ in SECURITY_HEADERS}


def _parse_severity(value: str | None, default: Severity) -> Severity:
    if not value:
        return default
    try:
        return Severity[value.upper()]
    except KeyError:
        valid = ", ".join(s.name for s in Severity)
        raise ValueError(f"Invalid severity '{value}' in config. Valid values: {valid}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def analyze_headers(
    raw_headers: dict[str, str],
    config: AppConfig,
) -> list[HeaderResult]:
    results: list[HeaderResult] = []

    for key, canonical, default_required, default_missing_sev in SECURITY_HEADERS:
        override = get_override(config, key)
        if override.skip:
            continue
        value = raw_headers.get(key)

        required = override.required if override.required is not None else default_required
        missing_sev = (
            _parse_severity(override.severity_if_missing, default_missing_sev)
        )

        findings: list[Finding] = []

        if value is None:
            sev = missing_sev if required else Severity.INFO
            findings.append(Finding(
                header=canonical,
                severity=sev,
                title=f"Missing {canonical}",
                description=f"The {canonical} header is absent from the response.",
                recommendation=_MISSING_RECS.get(key, f"Add the {canonical} header.") if required else "",
            ))
        elif value.strip() == '':
            findings.append(Finding(
                header=canonical,
                severity=Severity.HIGH,
                title=f"{canonical}: present but empty",
                description="A header with an empty value is silently ignored by browsers.",
                recommendation=_MISSING_RECS.get(key, f"Set a valid value for {canonical}."),
            ))
        else:
            findings.extend(_validate_value(key, canonical, value, override))

        results.append(HeaderResult(
            name=key,
            canonical_name=canonical,
            value=value,
            findings=findings,
        ))

    # Custom headers from config that are not in the built-in list
    for name, override in config.overrides.items():
        if name in _DEFAULT_KEYS or override.skip:
            continue
        canonical = name
        value = raw_headers.get(name)
        findings = []

        if value is None:
            if override.required or override.severity_if_missing:
                sev = _parse_severity(override.severity_if_missing, Severity.MEDIUM)
                findings.append(Finding(
                    header=canonical,
                    severity=sev,
                    title=f"Missing custom header: {canonical}",
                    description="",
                ))
        else:
            if override.expected_value and value.strip().lower() != override.expected_value.lower():
                findings.append(Finding(
                    header=canonical,
                    severity=Severity.MEDIUM,
                    title=f"{canonical}: unexpected value",
                    description=f"Expected '{override.expected_value}', found '{value}'.",
                    recommendation=f"Set {canonical}: {override.expected_value}",
                ))
            elif override.expected_pattern and not re.search(override.expected_pattern, value, re.IGNORECASE):
                findings.append(Finding(
                    header=canonical,
                    severity=Severity.MEDIUM,
                    title=f"{canonical}: value does not match expected pattern",
                    description=f"Value '{value}' does not match '{override.expected_pattern}'.",
                ))
            elif override.severity_if_present:
                findings.append(Finding(
                    header=canonical,
                    severity=Severity[override.severity_if_present.upper()],
                    title=f"{canonical} is present (flagged by config)",
                    description="",
                ))

        results.append(HeaderResult(
            name=name,
            canonical_name=canonical,
            value=value,
            findings=findings,
        ))

    return results


def _validate_value(
    key: str,
    canonical: str,
    value: str,
    override: HeaderOverride,
) -> list[Finding]:
    # Config-level value assertions take precedence over built-in checks
    if override.expected_value:
        if value.strip().lower() != override.expected_value.lower():
            return [Finding(
                header=canonical,
                severity=Severity.MEDIUM,
                title=f"{canonical}: unexpected value",
                description=f"Expected '{override.expected_value}', found '{value}'.",
                recommendation=f"Set {canonical}: {override.expected_value}",
            )]
        return []

    if override.expected_pattern:
        if not re.search(override.expected_pattern, value, re.IGNORECASE):
            return [Finding(
                header=canonical,
                severity=Severity.MEDIUM,
                title=f"{canonical}: value does not match expected pattern",
                description=f"Value '{value}' does not match pattern '{override.expected_pattern}'.",
            )]
        return []

    # severity_if_present: emit finding when header exists (e.g. user marks a header as bad)
    if override.severity_if_present:
        checker = _CHECKERS.get(key)
        findings = checker(value, override.extra) if checker else []
        if not findings:
            findings = [Finding(
                header=canonical,
                severity=_parse_severity(override.severity_if_present, Severity.MEDIUM),
                title=f"{canonical} is present (flagged by config)",
                description="",
            )]
        return findings

    # CSP has its own dedicated evaluator
    if key == 'content-security-policy':
        return evaluate_csp(value)

    checker = _CHECKERS.get(key)
    if checker:
        return checker(value, override.extra)

    return []


# ---------------------------------------------------------------------------
# Individual header checkers
# ---------------------------------------------------------------------------

def _check_hsts(value: str, extra: dict) -> list[Finding]:
    findings: list[Finding] = []
    m = re.search(r'max-age\s*=\s*(\d+)', value, re.IGNORECASE)

    if not m:
        return [Finding(
            header='Strict-Transport-Security',
            severity=Severity.HIGH,
            title="HSTS: missing max-age",
            description="The max-age directive is required.",
            recommendation="Strict-Transport-Security: max-age=31536000; includeSubDomains",
        )]

    max_age = int(m.group(1))
    min_age = int(extra.get('min_max_age', 31536000))

    if max_age == 0:
        findings.append(Finding(
            header='Strict-Transport-Security',
            severity=Severity.HIGH,
            title="HSTS: max-age=0 revokes HSTS protection",
            description="Setting max-age=0 instructs browsers to delete the HSTS entry.",
            recommendation="Set max-age to at least 31536000 (1 year).",
        ))
    elif max_age < min_age:
        findings.append(Finding(
            header='Strict-Transport-Security',
            severity=Severity.MEDIUM,
            title=f"HSTS: max-age too short ({max_age}s < {min_age}s)",
            description=f"OWASP recommends at least 1 year ({min_age}s). Short values reduce protection.",
            recommendation=f"Set max-age to at least {min_age}.",
        ))

    if extra.get('require_include_subdomains', True) and 'includesubdomains' not in value.lower():
        findings.append(Finding(
            header='Strict-Transport-Security',
            severity=Severity.LOW,
            title="HSTS: missing includeSubDomains",
            description="Without includeSubDomains, subdomains remain vulnerable to SSL-stripping attacks.",
            recommendation="Add includeSubDomains directive.",
        ))

    if extra.get('require_preload', False) and 'preload' not in value.lower():
        findings.append(Finding(
            header='Strict-Transport-Security',
            severity=Severity.LOW,
            title="HSTS: missing preload",
            description="Without preload, the site is not eligible for browser HSTS preload lists.",
            recommendation="Add preload directive and submit to https://hstspreload.org",
        ))

    if not findings:
        findings.append(Finding(
            header='Strict-Transport-Security',
            severity=Severity.OK,
            title="HSTS correctly configured",
            description="",
        ))

    return findings


def _check_x_frame_options(value: str, extra: dict) -> list[Finding]:
    n = value.strip().upper()
    if n == 'DENY':
        return [Finding('X-Frame-Options', Severity.OK, "X-Frame-Options: DENY (optimal)")]
    if n == 'SAMEORIGIN':
        return [Finding('X-Frame-Options', Severity.OK, "X-Frame-Options: SAMEORIGIN (acceptable)")]
    if n.startswith('ALLOW-FROM'):
        return [Finding(
            header='X-Frame-Options',
            severity=Severity.LOW,
            title="X-Frame-Options: ALLOW-FROM is deprecated",
            description="ALLOW-FROM is not supported in modern browsers.",
            recommendation="Use Content-Security-Policy: frame-ancestors <allowed_origins> instead.",
        )]
    return [Finding(
        header='X-Frame-Options',
        severity=Severity.MEDIUM,
        title=f"X-Frame-Options: unrecognized value '{value}'",
        description="Valid values: DENY, SAMEORIGIN.",
        recommendation="Set X-Frame-Options: DENY",
    )]


def _check_x_content_type_options(value: str, extra: dict) -> list[Finding]:
    if value.strip().lower() == 'nosniff':
        return [Finding('X-Content-Type-Options', Severity.OK, "X-Content-Type-Options: nosniff (correct)")]
    return [Finding(
        header='X-Content-Type-Options',
        severity=Severity.MEDIUM,
        title=f"X-Content-Type-Options: unexpected value '{value}'",
        description="The only valid value is 'nosniff'.",
        recommendation="Set X-Content-Type-Options: nosniff",
    )]


def _check_coop(value: str, extra: dict) -> list[Finding]:
    n = value.strip().lower()
    if n == 'same-origin':
        return [Finding('Cross-Origin-Opener-Policy', Severity.OK, "COOP: same-origin (optimal)")]
    if n == 'same-origin-allow-popups':
        return [Finding(
            header='Cross-Origin-Opener-Policy',
            severity=Severity.LOW,
            title="COOP: same-origin-allow-popups",
            description="Weaker than same-origin; allows popups to cross-origin pages.",
            recommendation="Use same-origin if cross-origin popups are not needed.",
        )]
    if n == 'unsafe-none':
        return [Finding(
            header='Cross-Origin-Opener-Policy',
            severity=Severity.MEDIUM,
            title="COOP: unsafe-none disables cross-origin isolation",
            description="unsafe-none provides no Spectre/XS-Leak protection.",
            recommendation="Set Cross-Origin-Opener-Policy: same-origin",
        )]
    return [Finding(
        header='Cross-Origin-Opener-Policy',
        severity=Severity.INFO,
        title=f"COOP: unrecognized value '{value}'",
    )]


def _check_coep(value: str, extra: dict) -> list[Finding]:
    n = value.strip().lower()
    if n == 'require-corp':
        return [Finding('Cross-Origin-Embedder-Policy', Severity.OK, "COEP: require-corp (optimal)")]
    if n == 'credentialless':
        return [Finding(
            header='Cross-Origin-Embedder-Policy',
            severity=Severity.INFO,
            title="COEP: credentialless",
            description="Allows cross-origin resources without CORP, but strips credentials.",
            recommendation="Consider require-corp for stronger isolation.",
        )]
    if n == 'unsafe-none':
        return [Finding(
            header='Cross-Origin-Embedder-Policy',
            severity=Severity.LOW,
            title="COEP: unsafe-none disables embedding restrictions",
            recommendation="Set Cross-Origin-Embedder-Policy: require-corp",
        )]
    return [Finding('Cross-Origin-Embedder-Policy', Severity.INFO, f"COEP: unrecognized value '{value}'")]


def _check_corp(value: str, extra: dict) -> list[Finding]:
    n = value.strip().lower()
    if n in ('same-origin', 'same-site'):
        return [Finding('Cross-Origin-Resource-Policy', Severity.OK, f"CORP: {n}")]
    if n == 'cross-origin':
        return [Finding(
            header='Cross-Origin-Resource-Policy',
            severity=Severity.LOW,
            title="CORP: cross-origin allows any origin to load this resource",
            description="Provides no Spectre isolation for this resource.",
            recommendation="Use same-origin or same-site unless cross-origin access is intentional.",
        )]
    return [Finding('Cross-Origin-Resource-Policy', Severity.INFO, f"CORP: unrecognized value '{value}'")]


_PP_HIGH_RISK = {
    'camera', 'microphone', 'geolocation', 'payment', 'usb', 'display-capture',
}
_PP_MEDIUM_RISK = {
    'accelerometer', 'gyroscope', 'magnetometer', 'midi', 'screen-wake-lock',
    'xr-spatial-tracking', 'document-domain', 'publickey-credentials-get',
}


def _parse_pp_features(value: str) -> set[str]:
    features = set()
    for part in value.split(','):
        part = part.strip()
        if '=' in part:
            features.add(part.split('=')[0].strip().lower())
    return features


def _check_permissions_policy(value: str, extra: dict) -> list[Finding]:
    findings: list[Finding] = []
    all_sensitive = _PP_HIGH_RISK | _PP_MEDIUM_RISK
    declared = _parse_pp_features(value)

    # Wildcard check
    wildcarded = [
        f for f in all_sensitive
        if re.search(rf'\b{re.escape(f)}\s*=\s*\*', value, re.IGNORECASE)
    ]
    if wildcarded:
        findings.append(Finding(
            header='Permissions-Policy',
            severity=Severity.MEDIUM,
            title=f"Permissions-Policy: wildcard (*) for: {', '.join(wildcarded)}",
            description="Wildcard (*) grants any origin access to these browser features.",
            recommendation="Restrict sensitive features to () (disabled) or (self).",
        ))

    # Completeness check: sensitive features not mentioned are allowed by default
    missing_high = _PP_HIGH_RISK - declared
    missing_medium = _PP_MEDIUM_RISK - declared

    if missing_high:
        findings.append(Finding(
            header='Permissions-Policy',
            severity=Severity.MEDIUM,
            title=f"Permissions-Policy: high-risk features not explicitly disabled: {', '.join(sorted(missing_high))}",
            description="Features absent from the policy are allowed by default. "
                        "OWASP recommends explicitly disabling all sensitive browser features.",
            recommendation=f"Add to policy: {', '.join(f + '=()' for f in sorted(missing_high))}",
        ))

    if missing_medium:
        findings.append(Finding(
            header='Permissions-Policy',
            severity=Severity.LOW,
            title=f"Permissions-Policy: medium-risk features not explicitly disabled: {', '.join(sorted(missing_medium))}",
            description="Features absent from the policy are allowed by default.",
            recommendation=f"Consider adding: {', '.join(f + '=()' for f in sorted(missing_medium))}",
        ))

    if not findings:
        findings.append(Finding('Permissions-Policy', Severity.OK, "Permissions-Policy: all sensitive features explicitly addressed"))
    return findings


def _check_referrer_policy(value: str, extra: dict) -> list[Finding]:
    n = value.strip().lower()
    strong = {'no-referrer', 'strict-origin', 'strict-origin-when-cross-origin'}
    acceptable = {'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin'}
    weak = {'unsafe-url', 'always'}

    if n in strong:
        return [Finding('Referrer-Policy', Severity.OK, f"Referrer-Policy: '{n}' (strong)")]
    if n in acceptable:
        return [Finding(
            header='Referrer-Policy',
            severity=Severity.LOW,
            title=f"Referrer-Policy: '{n}' (leaks some referrer information)",
            recommendation="Consider no-referrer or strict-origin-when-cross-origin.",
        )]
    if n in weak:
        return [Finding(
            header='Referrer-Policy',
            severity=Severity.HIGH,
            title=f"Referrer-Policy: '{n}' (unsafe)",
            description="Sends the full URL as referrer even over plain HTTP, leaking sensitive paths.",
            recommendation="Use no-referrer or strict-origin-when-cross-origin.",
        )]
    if n == '':
        return [Finding(
            header='Referrer-Policy',
            severity=Severity.LOW,
            title="Referrer-Policy: empty (browser default behavior)",
            recommendation="Explicitly set a policy (e.g. strict-origin-when-cross-origin).",
        )]
    return [Finding('Referrer-Policy', Severity.INFO, f"Referrer-Policy: unrecognized value '{value}'")]


def _check_cache_control(value: str, extra: dict) -> list[Finding]:
    findings: list[Finding] = []
    lower = value.lower()

    if 'no-store' in lower:
        findings.append(Finding('Cache-Control', Severity.OK, "Cache-Control: no-store (sensitive data not cached)"))
    elif 'no-cache' in lower:
        findings.append(Finding(
            header='Cache-Control',
            severity=Severity.INFO,
            title="Cache-Control: no-cache (revalidated before use)",
            description="Content may be stored but will be revalidated with the server.",
            recommendation="For sensitive endpoints prefer no-store.",
        ))

    if 'public' in lower:
        findings.append(Finding(
            header='Cache-Control',
            severity=Severity.INFO,
            title="Cache-Control: public (shared caches allowed)",
            description="Ensure public caching is intentional for this response.",
        ))

    if not findings:
        findings.append(Finding('Cache-Control', Severity.INFO, f"Cache-Control: '{value}'"))

    return findings


def _check_x_permitted_cross_domain_policies(value: str, extra: dict) -> list[Finding]:
    n = value.strip().lower()
    if n in ('none', 'master-only'):
        return [Finding('X-Permitted-Cross-Domain-Policies', Severity.OK, f"X-Permitted-Cross-Domain-Policies: '{value}' (restrictive)")]
    if n in ('all', 'by-content-type', 'by-ftp-filename'):
        return [Finding(
            header='X-Permitted-Cross-Domain-Policies',
            severity=Severity.MEDIUM,
            title=f"X-Permitted-Cross-Domain-Policies: '{value}' is permissive",
            description="Allows Flash/PDF plugins to make cross-domain requests.",
            recommendation="Set X-Permitted-Cross-Domain-Policies: none",
        )]
    return [Finding('X-Permitted-Cross-Domain-Policies', Severity.INFO, f"X-Permitted-Cross-Domain-Policies: '{value}'")]


def _check_x_xss_protection(value: str, extra: dict) -> list[Finding]:
    n = value.strip()
    if n == '0':
        return [Finding(
            header='X-XSS-Protection',
            severity=Severity.INFO,
            title="X-XSS-Protection: 0 (deprecated header, disabled correctly)",
            description="The header is deprecated. Setting it to 0 is correct for modern browsers.",
            recommendation="Consider removing this header entirely; rely on CSP instead.",
        )]
    if '1' in n and 'mode=block' in n.lower():
        return [Finding(
            header='X-XSS-Protection',
            severity=Severity.LOW,
            title="X-XSS-Protection: 1; mode=block (deprecated, potentially risky)",
            description="Deprecated and mode=block can cause info leaks in old browsers.",
            recommendation="Set to 0 or remove; use Content-Security-Policy instead.",
        )]
    return [Finding(
        header='X-XSS-Protection',
        severity=Severity.INFO,
        title=f"X-XSS-Protection: '{value}' (deprecated header)",
        recommendation="Remove this header and rely on Content-Security-Policy.",
    )]


def _check_expect_ct(value: str, extra: dict) -> list[Finding]:
    return [Finding(
        header='Expect-CT',
        severity=Severity.INFO,
        title="Expect-CT: deprecated header",
        description="Certificate Transparency is now mandatory for all new certificates; this header is obsolete.",
        recommendation="Remove Expect-CT.",
    )]


def _check_x_dns_prefetch_control(value: str, extra: dict) -> list[Finding]:
    if value.strip().lower() == 'off':
        return [Finding('X-DNS-Prefetch-Control', Severity.OK, "X-DNS-Prefetch-Control: off")]
    return [Finding(
        header='X-DNS-Prefetch-Control',
        severity=Severity.INFO,
        title=f"X-DNS-Prefetch-Control: '{value}' (DNS prefetching enabled)",
        description="DNS prefetching can reveal visited subdomains to DNS resolvers.",
        recommendation="Set X-DNS-Prefetch-Control: off if privacy is a concern.",
    )]


def _check_origin_agent_cluster(value: str, extra: dict) -> list[Finding]:
    n = value.strip()
    if n == '?1':
        return [Finding('Origin-Agent-Cluster', Severity.OK, "Origin-Agent-Cluster: ?1 (origin isolation enabled)")]
    if n == '?0':
        return [Finding(
            header='Origin-Agent-Cluster',
            severity=Severity.LOW,
            title="Origin-Agent-Cluster: ?0 (isolation explicitly disabled)",
            description="Origin isolation is disabled, allowing shared resources with other origins.",
            recommendation="Set Origin-Agent-Cluster: ?1 to enable origin-keyed agent clusters.",
        )]
    return [Finding('Origin-Agent-Cluster', Severity.INFO, f"Origin-Agent-Cluster: unrecognized value '{value}'")]


def _check_acao(value: str, extra: dict) -> list[Finding]:
    n = value.strip()
    if n == '*':
        return [Finding(
            header='Access-Control-Allow-Origin',
            severity=Severity.MEDIUM,
            title="Access-Control-Allow-Origin: * (wildcard)",
            description="Any origin can read this response. Dangerous if the response contains sensitive data.",
            recommendation="Restrict to specific trusted origins: Access-Control-Allow-Origin: https://trusted.example.com",
        )]
    return [Finding('Access-Control-Allow-Origin', Severity.OK, f"Access-Control-Allow-Origin: specific origin ('{n}')")]


def _check_acac(value: str, extra: dict) -> list[Finding]:
    if value.strip().lower() == 'true':
        return [Finding(
            header='Access-Control-Allow-Credentials',
            severity=Severity.MEDIUM,
            title="Access-Control-Allow-Credentials: true",
            description="Cookies and auth headers are sent cross-origin. Ensure Allow-Origin is NOT wildcard (*), "
                        "otherwise browsers will reject the response.",
            recommendation="Verify Access-Control-Allow-Origin is a specific origin, not *.",
        )]
    return [Finding('Access-Control-Allow-Credentials', Severity.OK, "Access-Control-Allow-Credentials: false (credentials not exposed)")]


def _check_service_worker_allowed(value: str, extra: dict) -> list[Finding]:
    n = value.strip()
    if n == '/':
        return [Finding(
            header='Service-Worker-Allowed',
            severity=Severity.LOW,
            title="Service-Worker-Allowed: / (full site scope)",
            description="The service worker can intercept requests for the entire origin. Ensure this is intentional.",
            recommendation="Restrict to the minimum necessary path scope.",
        )]
    return [Finding(
        header='Service-Worker-Allowed',
        severity=Severity.INFO,
        title=f"Service-Worker-Allowed: '{n}'",
        description="Service worker scope is extended. Verify the scope is appropriate.",
    )]


def _check_content_disposition(value: str, extra: dict) -> list[Finding]:
    lower = value.strip().lower()
    if lower.startswith('attachment'):
        return [Finding('Content-Disposition', Severity.OK, "Content-Disposition: attachment (prevents inline rendering)")]
    if lower.startswith('inline'):
        return [Finding(
            header='Content-Disposition',
            severity=Severity.INFO,
            title="Content-Disposition: inline",
            description="Browser will attempt to render the content inline.",
            recommendation="Use 'attachment; filename=...' for file downloads to prevent inline execution.",
        )]
    return [Finding('Content-Disposition', Severity.INFO, f"Content-Disposition: '{value}'")]


def _check_pragma(value: str, extra: dict) -> list[Finding]:
    if value.strip().lower() == 'no-cache':
        return [Finding(
            header='Pragma',
            severity=Severity.INFO,
            title="Pragma: no-cache (HTTP/1.0 legacy header)",
            description="Pragma is a legacy HTTP/1.0 header superseded by Cache-Control.",
            recommendation="Rely on Cache-Control for modern caching directives.",
        )]
    return [Finding('Pragma', Severity.INFO, f"Pragma: '{value}' (legacy HTTP/1.0 header)")]


def _check_expires(value: str, extra: dict) -> list[Finding]:
    if value.strip() in ('0', '-1'):
        return [Finding('Expires', Severity.OK, "Expires: 0 (immediately expired, no caching)")]
    return [Finding(
        header='Expires',
        severity=Severity.INFO,
        title=f"Expires: '{value}' (legacy HTTP/1.0 caching header)",
        description="Expires is a legacy header superseded by Cache-Control: max-age.",
        recommendation="Prefer Cache-Control for cache lifetime control.",
    )]


def _check_etag(value: str, extra: dict) -> list[Finding]:
    if value.strip().startswith('W/'):
        return [Finding('ETag', Severity.INFO, "ETag: weak validator present")]
    return [Finding('ETag', Severity.INFO, "ETag: strong validator present")]


def _check_x_download_options(value: str, extra: dict) -> list[Finding]:
    if value.strip().lower() == 'noopen':
        return [Finding('X-Download-Options', Severity.OK, "X-Download-Options: noopen (IE protection enabled)")]
    return [Finding(
        header='X-Download-Options',
        severity=Severity.INFO,
        title=f"X-Download-Options: '{value}'",
        description="Expected value is 'noopen' to prevent IE from opening downloads in the site context.",
        recommendation="Set X-Download-Options: noopen",
    )]


def _check_clear_site_data(value: str, extra: dict) -> list[Finding]:
    # OWASP recommended: "cache","cookies","storage"
    recommended = {'"cache"', '"cookies"', '"storage"'}

    if '"*"' in value or value.strip() == '*':
        return [Finding('Clear-Site-Data', Severity.OK, 'Clear-Site-Data: * (all data cleared)')]

    present = {d.strip() for d in value.split(',')}
    missing = recommended - present

    if missing:
        return [Finding(
            header='Clear-Site-Data',
            severity=Severity.LOW,
            title=f"Clear-Site-Data: missing directives: {', '.join(sorted(missing))}",
            description="OWASP recommends clearing cache, cookies, and storage on logout/sensitive operations.",
            recommendation='Set Clear-Site-Data: "cache","cookies","storage"',
        )]
    return [Finding('Clear-Site-Data', Severity.OK, 'Clear-Site-Data: cache, cookies and storage cleared')]


_CHECKERS: dict[str, Callable[[str, dict], list[Finding]]] = {
    'strict-transport-security':         _check_hsts,
    'x-frame-options':                   _check_x_frame_options,
    'x-content-type-options':            _check_x_content_type_options,
    'cross-origin-opener-policy':        _check_coop,
    'cross-origin-embedder-policy':      _check_coep,
    'cross-origin-resource-policy':      _check_corp,
    'permissions-policy':                _check_permissions_policy,
    'referrer-policy':                   _check_referrer_policy,
    'cache-control':                     _check_cache_control,
    'x-permitted-cross-domain-policies': _check_x_permitted_cross_domain_policies,
    'x-xss-protection':                  _check_x_xss_protection,
    'expect-ct':                         _check_expect_ct,
    'x-dns-prefetch-control':            _check_x_dns_prefetch_control,
    'origin-agent-cluster':              _check_origin_agent_cluster,
    'access-control-allow-origin':       _check_acao,
    'access-control-allow-credentials':  _check_acac,
    'service-worker-allowed':            _check_service_worker_allowed,
    'content-disposition':               _check_content_disposition,
    'pragma':                            _check_pragma,
    'expires':                           _check_expires,
    'etag':                              _check_etag,
    'x-download-options':                _check_x_download_options,
    'clear-site-data':                   _check_clear_site_data,
}

_MISSING_RECS: dict[str, str] = {
    'content-security-policy':
        "Add a CSP header. Start conservative: Content-Security-Policy: default-src 'self'",
    'strict-transport-security':
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    'x-frame-options':
        "X-Frame-Options: DENY (or use CSP frame-ancestors 'none')",
    'x-content-type-options':
        "X-Content-Type-Options: nosniff",
    'cross-origin-opener-policy':
        "Cross-Origin-Opener-Policy: same-origin",
    'permissions-policy':
        "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
    'referrer-policy':
        "Referrer-Policy: strict-origin-when-cross-origin",
    'cross-origin-embedder-policy':
        "Cross-Origin-Embedder-Policy: require-corp",
    'cross-origin-resource-policy':
        "Cross-Origin-Resource-Policy: same-origin",
    'cache-control':
        "Cache-Control: no-store (for sensitive endpoints)",
}
