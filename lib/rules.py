"""
Header rule engine.
Each checker returns a list[Finding] given (header_value, extra_config_dict).
"""
import re
from typing import Callable, Optional

from .config import CONTEXT_AUTHENTICATED, AppConfig, HeaderOverride, get_override
from .correlations import apply_correlations
from .csp_evaluator import evaluate_csp
from .models import Finding, HeaderResult, Severity, is_issue

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

# Headers whose absence means something different once the response is assumed to
# carry a signed-in user's data. Without a Cache-Control of its own such a
# response is subject to heuristic caching, which is not a remark but a problem.
_CONTEXT_MISSING: dict[str, dict[str, Severity]] = {
    CONTEXT_AUTHENTICATED: {'cache-control': Severity.MEDIUM},
}

# ---------------------------------------------------------------------------
# Duplicate-header resolution, mirroring real browser behavior:
#   first     — first occurrence wins (default; e.g. HSTS per RFC 6797 §8.1)
#   last      — last valid occurrence wins (Referrer-Policy per W3C spec)
#   join      — occurrences combine into one value (RFC list headers; for CSP,
#               multiple headers are all enforced, equivalent to joining with
#               ','). Whether the combined value is still valid is the checker's
#               business: COOP joins into something no browser can parse.
#   strictest — conflicting values make browsers block framing (X-Frame-Options)
# ---------------------------------------------------------------------------
_DUPLICATE_STRATEGIES: dict[str, str] = {
    'referrer-policy':            'last',
    'x-frame-options':            'strictest',
    'content-security-policy':    'join',
    'cache-control':              'join',
    'clear-site-data':            'join',
    'permissions-policy':         'join',
    'pragma':                     'join',
    'cross-origin-opener-policy': 'join',
}


def _resolve_duplicates(
    key: str,
    canonical: str,
    values: list[str],
) -> tuple[str, Optional[Finding]]:
    """
    Collapse multiple occurrences of a header into the value browsers
    would actually apply. Returns (effective_value, note_finding);
    note_finding is None when the header appears only once.
    """
    if len(values) == 1:
        return values[0], None

    strategy = _DUPLICATE_STRATEGIES.get(key, 'first')
    identical = len({v.strip().lower() for v in values}) == 1

    # 'join' is checked before 'identical': a browser concatenates the occurrences
    # whether or not they match, and for a header that must hold a single value
    # (COOP) being identical is no consolation — the concatenation is what breaks it.
    if strategy == 'join':
        effective = ', '.join(values)
        behavior = "browsers combine them into a single header value"
    elif identical:
        effective = values[0]
        behavior = "the duplicate values are identical"
    elif strategy == 'last':
        effective = values[-1]
        behavior = "browsers honor the last valid value"
    elif strategy == 'strictest':
        effective = 'DENY'
        behavior = "browsers block framing when the values conflict"
    else:
        effective = values[0]
        behavior = "browsers honor the first value"

    seen = f"Values sent: {'; '.join(values)}. Evaluated as '{effective}' because {behavior}."

    # A value is only lost when the resolution has to pick one occurrence over the
    # others. Under 'join' no occurrence is discarded, so this stays a NOTE; if the
    # combined value is not valid, its checker grades that on its own.
    if identical or strategy == 'join':
        return effective, Finding(
            header=canonical,
            severity=Severity.NOTE,
            title=f"{canonical}: header sent {len(values)} times",
            description=seen,
            recommendation=(
                f"Configure the server (and any proxy/CDN) to send {canonical} only once."
                if identical else ""
            ),
        )

    # Here one component's value is discarded, so whoever set it is working on a
    # false assumption — and which one wins comes from a resolution rule rather
    # than from anything the site chose.
    return effective, Finding(
        header=canonical,
        severity=Severity.LOW,
        title=f"{canonical}: sent {len(values)} times with conflicting values",
        description=(
            f"{seen} Whichever component set a discarded value is operating on a false "
            "assumption, and the resolution is not guaranteed to be identical in every browser."
        ),
        recommendation=f"Decide which value is intended, then send {canonical} once.",
    )


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
    raw_headers: dict[str, list[str]],
    config: AppConfig,
) -> list[HeaderResult]:
    results: list[HeaderResult] = []

    for key, canonical, default_required, default_missing_sev in SECURITY_HEADERS:
        override = get_override(config, key)
        if override.skip:
            continue
        occurrences = raw_headers.get(key)

        context_sev = _CONTEXT_MISSING.get(config.context, {}).get(key)

        if override.required is not None:
            required = override.required
        elif override.severity_if_missing:
            # Setting a severity for absence states that the header is expected;
            # an explicit `required: false` still wins over that.
            required = True
        elif context_sev is not None:
            required = True
        else:
            required = default_required
        missing_sev = (
            _parse_severity(override.severity_if_missing, context_sev or default_missing_sev)
        )

        findings: list[Finding] = []
        value: Optional[str] = None

        # Browsers ignore a header with an empty value, so its security impact is
        # identical to the header not being sent: both use the same severity.
        absent_sev = missing_sev if required else Severity.INFO

        if occurrences is None:
            findings.append(Finding(
                header=canonical,
                severity=absent_sev,
                title=f"Missing {canonical}",
                description=_MISSING_DESCRIPTIONS.get(
                    key, f"The {canonical} header is absent from the response."),
                # A recommendation written for this header is worth showing whether or
                # not it is required — that is where an INFO finding would otherwise
                # say nothing useful. Only the generic fallback is held back.
                recommendation=_MISSING_RECS.get(
                    key, f"Add the {canonical} header." if required else ""),
            ))
        else:
            value, dup_note = _resolve_duplicates(key, canonical, occurrences)
            if dup_note:
                findings.append(dup_note)
            if value.strip() == '':
                findings.append(Finding(
                    header=canonical,
                    severity=absent_sev,
                    title=f"{canonical}: present but empty",
                    description=(
                        f"{canonical} is present but carries no value. Browsers ignore it "
                        "entirely, so the effect is the same as not sending it at all. "
                        "An empty value usually points at a misconfigured template or proxy."
                    ),
                    recommendation=_MISSING_RECS.get(key, f"Set a valid value for {canonical}."),
                ))
            else:
                findings.extend(_validate_value(key, canonical, value, override, absent_sev, config.context))

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
        canonical = override.display_name or name
        occurrences = raw_headers.get(name)
        findings = []
        value = None

        if occurrences is None:
            if override.required or override.severity_if_missing:
                sev = _parse_severity(override.severity_if_missing, Severity.MEDIUM)
                findings.append(Finding(
                    header=canonical,
                    severity=sev,
                    title=f"Missing custom header: {canonical}",
                    description="",
                ))
        else:
            value, dup_note = _resolve_duplicates(name, canonical, occurrences)
            if dup_note:
                findings.append(dup_note)
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
                    severity=_parse_severity(override.severity_if_present, Severity.MEDIUM),
                    title=f"{canonical} is present (flagged by config)",
                    description="",
                ))

        results.append(HeaderResult(
            name=name,
            canonical_name=canonical,
            value=value,
            findings=findings,
        ))

    apply_correlations(results)
    return results


# Reserved key injected into a checker's `extra`, never settable from a config
# file (unknown options are rejected at load time). It carries the severity the
# header would get if it were absent, for checkers that need to report a value
# whose effect is identical to sending no header at all.
ABSENT_SEVERITY = '_absent_severity'

# Reserved likewise: the assumed content of the response. Only checks whose
# correct value depends on it read this.
CONTEXT = '_context'


def _validate_value(
    key: str,
    canonical: str,
    value: str,
    override: HeaderOverride,
    absent_sev: Severity = Severity.INFO,
    context: str = CONTEXT_AUTHENTICATED,
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

    # severity_if_present: emit finding when header exists (e.g. user marks a header as bad).
    # Real problems found by the checker are more specific and win; otherwise the
    # config severity applies. Checkers report a clean value with an OK finding, so
    # the test is "found no issue", not "returned nothing".
    extra = {**override.extra, ABSENT_SEVERITY: absent_sev, CONTEXT: context}

    if override.severity_if_present:
        checker = _CHECKERS.get(key)
        findings = checker(value, extra) if checker else []
        if not any(is_issue(f.severity) for f in findings):
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
        return checker(value, extra)

    # Defensive: reached only if a SECURITY_HEADERS entry has no checker yet.
    return []  # pragma: no cover


# ---------------------------------------------------------------------------
# Individual header checkers
# ---------------------------------------------------------------------------

def _split_outside_quotes(value: str, separator: str, keep_empty: bool = False) -> list[str]:
    """
    Split on `separator`, ignoring separators inside a quoted-string.

    Header values carry quoted arguments — `no-cache="Set-Cookie"`, and any
    directive value may be quoted per RFC 6797 §6.1 — so a plain split would cut
    a quoted value containing the separator in half.

    Empty segments are dropped, because for a list of directives a stray separator
    means nothing. Pass keep_empty=True where it does mean something: in a
    structured field an empty segment is a parse error, not a directive to skip.
    """
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    for char in value:
        if char == '"':
            in_quotes = not in_quotes
        if char == separator and not in_quotes:
            parts.append(''.join(current))
            current = []
        else:
            current.append(char)
    parts.append(''.join(current))
    return [p.strip() for p in parts if keep_empty or p.strip()]


def _parse_directives(value: str, separator: str) -> dict[str, Optional[str]]:
    """
    Split a header value into `{directive name: argument}`, lowercasing names and
    unquoting arguments. A directive with no argument maps to None.

    Reading the names is what tells `includeSubDomains` apart from a misspelling
    of it, or from the same word appearing inside some other directive's value.
    """
    directives: dict[str, Optional[str]] = {}
    for token in _split_outside_quotes(value, separator):
        name, sep, argument = token.partition('=')
        name = name.strip().lower()
        if not name:
            continue
        argument = argument.strip() if sep else None
        if argument and len(argument) >= 2 and argument[0] == '"' and argument[-1] == '"':
            argument = argument[1:-1]
        directives[name] = argument
    return directives


def _hsts_syntax_error(value: str, directives: dict) -> Optional[str]:
    """
    Why a browser would throw the whole header away, or None if it would not.

    RFC 6797 §6.1 requires every directive to appear at most once, gives
    includeSubDomains and preload no value, and defines max-age as 1*DIGIT. A
    header that does not conform is ignored in full — the site then has no HSTS
    at all, which is why this is graded like the header being absent.
    """
    canonical = {'max-age': 'max-age', 'includesubdomains': 'includeSubDomains',
                 'preload': 'preload'}
    spell = lambda n: canonical.get(n, n)

    names = [t.partition('=')[0].strip().lower() for t in _split_outside_quotes(value, ';')]
    names = [n for n in names if n]
    repeated = sorted({n for n in names if names.count(n) > 1})
    if repeated:
        return f"the {', '.join(spell(n) for n in repeated)} directive appears more than once"

    valued = sorted(n for n in ('includesubdomains', 'preload') if directives.get(n))
    if valued:
        return f"{' and '.join(spell(n) for n in valued)} must not be given a value"

    raw_max_age = directives.get('max-age')
    if raw_max_age is None:
        return "the required max-age directive is missing"
    if not raw_max_age.isdigit():
        return f"max-age must be a number of seconds, not '{raw_max_age}'"
    return None


def _check_hsts(value: str, extra: dict) -> list[Finding]:
    findings: list[Finding] = []
    directives = _parse_directives(value, ';')

    reason = _hsts_syntax_error(value, directives)
    if reason:
        return [Finding(
            header='Strict-Transport-Security',
            severity=extra.get(ABSENT_SEVERITY, Severity.HIGH),
            title=f"HSTS: the header is not valid — {reason}",
            description="A browser ignores a Strict-Transport-Security header that does not "
                        "conform to RFC 6797 §6.1, so this site has no HSTS at all — the same "
                        "position as never sending the header. Nothing in the response says so.",
            recommendation="Strict-Transport-Security: max-age=31536000; includeSubDomains",
        )]

    max_age = int(directives['max-age'])
    try:
        min_age = int(extra.get('min_max_age', 31536000))
    except (TypeError, ValueError):
        raise ValueError(
            f"Invalid min_max_age '{extra.get('min_max_age')}' in config: must be an integer (seconds)."
        )

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

    if extra.get('require_include_subdomains', True) and 'includesubdomains' not in directives:
        findings.append(Finding(
            header='Strict-Transport-Security',
            severity=Severity.LOW,
            title="HSTS: missing includeSubDomains",
            description="Without includeSubDomains, subdomains remain vulnerable to SSL-stripping attacks.",
            recommendation="Add includeSubDomains directive.",
        ))

    if extra.get('require_preload', False) and 'preload' not in directives:
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


# RFC 8941 §3.3.4 (sf-token) and §3.1.2 (parameter names).
_SF_TOKEN = re.compile(r"^[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*$")
_SF_PARAM_NAME = re.compile(r"^[a-z*][a-z0-9_.*-]*$")


def _coop_token(value: str) -> Optional[str]:
    """The policy token a browser reads out of a COOP header, or None when the
    header does not parse.

    COOP is a structured field of type item (HTML §7.1.3.1): one token, which may
    carry parameters — of these only `report-to` is defined, and no parameter
    changes which policy applies. What does matter is that a value which fails to
    parse leaves the policy at unsafe-none, so the header does nothing at all.
    """
    parts = _split_outside_quotes(value, ';', keep_empty=True)
    token = parts[0].strip()
    if not _SF_TOKEN.match(token):
        return None
    if not all(_SF_PARAM_NAME.match(p.partition('=')[0].strip()) for p in parts[1:]):
        return None
    return token.lower()


def _coop_not_applied(extra: dict, reason: str, recommendation: str = "") -> Finding:
    """COOP graded as absent, because that is the position the response is in."""
    return Finding(
        header='Cross-Origin-Opener-Policy',
        severity=extra.get(ABSENT_SEVERITY, Severity.MEDIUM),
        title=f"COOP: the header is not applied — {reason}",
        description="A browser that cannot use this value applies unsafe-none, so this response "
                    "has no COOP at all — the same position as never sending the header, with "
                    "no Spectre/XS-Leak protection. Nothing in the response says so.",
        recommendation=recommendation or "Set Cross-Origin-Opener-Policy: same-origin",
    )


# What the two *-allow-popups values give up, which is the same thing for both:
# per the Window.open() table in HTML §7.1.3.1 a popup that sends no COOP of its
# own stays in the opener's browsing context group.
_COOP_ALLOW_POPUPS_KEPT = {
    'same-origin-allow-popups':
        "No cross-origin document can open this one into an existing browsing context "
        "group, so the protection COOP mainly exists for is in place.",
    'noopener-allow-popups':
        "Only a same-origin document sending this same value can navigate to this one "
        "without a browsing context group switch, and through window.open() not even "
        "that — stricter than same-origin in that direction. It does not provide "
        "cross-origin isolation, though: that needs same-origin plus COEP.",
}


def _coop_allow_popups(token: str) -> Finding:
    """Graded INFO, not as a weakness: the exposure is toward windows this document
    chose to open, and `same-origin` is not available to a site that needs to keep a
    reference to one — an OAuth or payment popup is what these values exist for."""
    return Finding(
        header='Cross-Origin-Opener-Policy',
        severity=Severity.INFO,
        title=f"COOP: {token} keeps a reference to the windows this document opens",
        description=f"{_COOP_ALLOW_POPUPS_KEPT[token]} What it gives up is in the other "
                    "direction: a window this document opens with window.open() stays in its "
                    "browsing context group if that window sends no COOP of its own, so the "
                    "window keeps a window.opener reference back and can probe this document "
                    "through it. That only matters if this document opens windows it does not "
                    "control.",
        recommendation="Use same-origin instead if this document does not need to keep a "
                       "reference to a window it opens.",
    )


def _check_coop(value: str, extra: dict) -> list[Finding]:
    # RFC 8941 §4.2 fails parsing when anything follows the first item, and a comma
    # is how a browser sees the header sent twice, so two occurrences cancel it out
    # even when they say the same thing.
    if len(_split_outside_quotes(value, ',')) > 1:
        return [_coop_not_applied(
            extra,
            "it carries more than one value",
            "Send Cross-Origin-Opener-Policy: same-origin once.",
        )]

    n = _coop_token(value)
    if n is None:
        return [_coop_not_applied(extra, f"'{value.strip()}' is not a valid header value")]
    if n == 'same-origin':
        return [Finding('Cross-Origin-Opener-Policy', Severity.OK, "COOP: same-origin (optimal)")]
    if n in ('same-origin-allow-popups', 'noopener-allow-popups'):
        return [_coop_allow_popups(n)]
    if n == 'unsafe-none':
        return [Finding(
            header='Cross-Origin-Opener-Policy',
            severity=Severity.MEDIUM,
            title="COOP: unsafe-none opts this document out of COOP protection",
            description="Any document that opens this one shares its browsing context group and "
                        "keeps a reference to its window, which is what XS-Leaks are probed "
                        "through. It also rules out cross-origin isolation, which needs "
                        "same-origin together with COEP.",
            recommendation="Set Cross-Origin-Opener-Policy: same-origin",
        )]
    if n == 'same-origin-plus-coep':
        return [_coop_not_applied(
            extra,
            "same-origin-plus-COEP cannot be set through this header",
            "It is the result of Cross-Origin-Opener-Policy: same-origin together with "
            "Cross-Origin-Embedder-Policy: require-corp, not a value to send.",
        )]
    return [_coop_not_applied(extra, f"'{n}' is not a policy browsers recognize")]


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


def _parse_pp_features(value: str) -> dict[str, str]:
    """Map each declared feature to its allowlist, e.g. {'camera': '()'}."""
    features: dict[str, str] = {}
    for part in value.split(','):
        name, sep, allowlist = part.strip().partition('=')
        if sep:
            features[name.strip().lower()] = allowlist.strip()
    return features


def _check_permissions_policy(value: str, extra: dict) -> list[Finding]:
    findings: list[Finding] = []
    all_sensitive = _PP_HIGH_RISK | _PP_MEDIUM_RISK
    declared = _parse_pp_features(value)

    # Read the allowlist of each declared feature rather than searching the raw
    # value: a \b boundary also matches after the hyphen of an unrelated name.
    wildcarded = sorted(f for f in all_sensitive if declared.get(f) == '*')
    if wildcarded:
        findings.append(Finding(
            header='Permissions-Policy',
            severity=Severity.MEDIUM,
            title=f"Permissions-Policy: wildcard (*) for: {', '.join(wildcarded)}",
            description="Wildcard (*) grants any origin access to these browser features.",
            recommendation="Restrict sensitive features to () (disabled) or (self).",
        ))

    # Completeness check: sensitive features not mentioned are allowed by default
    missing_high = _PP_HIGH_RISK - set(declared)
    missing_medium = _PP_MEDIUM_RISK - set(declared)

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
    # Graded on what reaches a third party, since that is the only recipient the
    # site does not already control: nothing, the origin alone, or the full URL.
    # What a policy sends on a same-origin request is not a criterion — that
    # recipient served the URL in the first place, and 'strong' already spans
    # every same-origin behaviour there is.
    sends_nothing = {'no-referrer', 'same-origin'}
    sends_origin = {'strict-origin', 'strict-origin-when-cross-origin'}
    origin_in_clear = {'origin', 'origin-when-cross-origin'}
    # 'always' is not one of them: it belonged to the old <meta name="referrer">
    # syntax, never to this header, so browsers skip it like any unknown token.
    full_url = {'no-referrer-when-downgrade', 'unsafe-url'}

    if n in sends_nothing:
        return [Finding('Referrer-Policy', Severity.OK,
                        f"Referrer-Policy: '{n}' (sends nothing cross-origin)")]
    if n in sends_origin:
        return [Finding('Referrer-Policy', Severity.OK,
                        f"Referrer-Policy: '{n}' (sends only the origin cross-origin)")]
    if n in origin_in_clear:
        # Only the site's identity leaks, never a path or query — and that is the
        # same thing the OK group already hands to every third party over HTTPS.
        # Worth reporting, not worth failing a build.
        return [Finding(
            header='Referrer-Policy',
            severity=Severity.INFO,
            title=f"Referrer-Policy: '{n}' (sends the origin to plain-HTTP destinations too)",
            description="Only the origin is sent, never the path or query, but it reaches "
                        "destinations that are not TLS-protected as well.",
            recommendation="Use strict-origin or strict-origin-when-cross-origin to withhold it "
                           "on a downgrade.",
        )]
    if n in full_url:
        # These differ only in what happens on a downgrade to plain HTTP. Over
        # HTTPS — where practically all third-party traffic goes — both hand over
        # the whole URL, so both are graded on that.
        also_in_clear = n != 'no-referrer-when-downgrade'
        return [Finding(
            header='Referrer-Policy',
            severity=Severity.HIGH,
            title=f"Referrer-Policy: '{n}' (sends the full URL to third parties)",
            description="Every third party the page loads a resource from, or links to, receives "
                        "the complete URL including path and query string — so a password-reset "
                        "token, a search query or an internal path ends up in someone else's logs."
                        + (" It is sent to plain-HTTP destinations too, where anyone on the "
                           "network can read it." if also_in_clear else
                           " It is withheld only on a downgrade to plain HTTP, which is the one "
                           "case browsers increasingly prevent anyway."),
            recommendation="Use no-referrer, or strict-origin-when-cross-origin to send no more "
                           "than the origin.",
        )]
    # Same outcome as sending no header at all, so it carries the same severity —
    # and the site is worse off than if it had not tried, because it believes a
    # policy is in force.
    return [Finding(
        header='Referrer-Policy',
        severity=extra.get(ABSENT_SEVERITY, Severity.MEDIUM),
        title=f"Referrer-Policy: unrecognized value '{value}' — no policy is in force",
        description="A token that is not one of the eight defined policies is skipped, so the "
                    "browser falls back to its own default exactly as if the header had not been "
                    "sent. The policy intended here is not applied, and nothing in the response "
                    "reveals that.",
        recommendation="Check the spelling. The defined values are no-referrer, "
                       "no-referrer-when-downgrade, same-origin, origin, strict-origin, "
                       "origin-when-cross-origin, strict-origin-when-cross-origin, unsafe-url.",
    )]


# Standard Cache-Control directives (response context); token before any '='.
_CACHE_CONTROL_DIRECTIVES = {
    'max-age', 's-maxage', 'no-cache', 'no-store', 'no-transform',
    'must-revalidate', 'proxy-revalidate', 'must-understand',
    'private', 'public', 'immutable',
    'stale-while-revalidate', 'stale-if-error',
}


def _check_cache_control_authenticated(value: str, directives: dict, extra: dict) -> list[Finding]:
    """
    Grade Cache-Control for a response carrying a signed-in user's data.

    Only `no-store` keeps such a response out of every cache. `private` stops the
    shared caches but leaves a copy on the user's disk; `no-cache` stops neither,
    it only forces revalidation. Anything else lets a shared cache keep the
    response and hand it to the next person who asks for the same URL.
    """
    def bare(name: str) -> bool:
        return name in directives and not directives[name]

    # Nothing a cache understands was said, so heuristic freshness applies just as
    # it does with no header at all — and the two are graded alike.
    if not set(directives) & _CACHE_CONTROL_DIRECTIVES:
        return [Finding(
            header='Cache-Control',
            severity=extra.get(ABSENT_SEVERITY, Severity.MEDIUM),
            title=f"Cache-Control: '{value}' holds no directive a cache understands",
            description="None of these tokens is a standard cache directive, so caches ignore "
                        "them and fall back to heuristic freshness — the same position as sending "
                        "no Cache-Control at all. Nothing keeps this user's response out of a "
                        "shared cache.",
            recommendation="Use no-store for a response carrying a signed-in user's data.",
        )]

    if 'no-store' in directives:
        return [Finding('Cache-Control', Severity.OK,
                        "Cache-Control: no-store (not stored by any cache)")]

    if bare('private'):
        return [Finding(
            header='Cache-Control',
            severity=Severity.LOW,
            title="Cache-Control: private keeps this out of shared caches, not off the disk",
            description="Shared caches will not store the response, so it cannot be served to "
                        "another user. The browser still writes it to disk, where it can be "
                        "recovered with the back button after logout, or by whoever uses the "
                        "machine next.",
            recommendation="Use no-store for a response carrying a signed-in user's data.",
        )]

    # `max-age=0` plus a revalidate directive forces the same round trip as a bare
    # `no-cache`, so the two are graded alike.
    always_revalidates = bare('no-cache') or (
        directives.get('max-age') == '0'
        and ('must-revalidate' in directives or 'proxy-revalidate' in directives)
    )
    if always_revalidates:
        return [Finding(
            header='Cache-Control',
            severity=Severity.MEDIUM,
            title=f"Cache-Control: '{value}' revalidates but does not stop a shared cache storing this",
            description="Revalidation before reuse is forced, but storage is not prevented. A "
                        "shared cache may keep this user's response, and nothing here marks it as "
                        "belonging to a single user.",
            recommendation="Use no-store, or at least private, for a response carrying a "
                           "signed-in user's data.",
        )]

    qualified = [n for n in ('private', 'no-cache') if directives.get(n)]
    detail = (f" The qualified form ({n}=\"{directives[n]}\") covers only the fields it names."
              if (n := qualified[0] if qualified else None) else "")

    return [Finding(
        header='Cache-Control',
        severity=Severity.HIGH,
        title=f"Cache-Control: '{value}' lets a shared cache store this response",
        description="Nothing here keeps the response out of a shared cache, so a CDN or proxy may "
                    "store it under this URL and serve it to the next person who asks — one user's "
                    "data handed to another." + detail,
        recommendation="Use no-store for a response carrying a signed-in user's data.",
    )]


def _check_cache_control(value: str, extra: dict) -> list[Finding]:
    findings: list[Finding] = []
    # Directive names have to be read as names: searching the raw value for
    # 'no-store' also matches a token that merely contains it, and misses the
    # difference between `no-cache` and the far weaker `no-cache="Some-Header"`.
    directives = _parse_directives(value, ',')

    if extra.get(CONTEXT) == CONTEXT_AUTHENTICATED:
        return _check_cache_control_authenticated(value, directives, extra)

    if 'no-store' in directives:
        findings.append(Finding('Cache-Control', Severity.OK, "Cache-Control: no-store (sensitive data not cached)"))
    elif 'no-cache' in directives:
        if directives['no-cache']:
            findings.append(Finding(
                header='Cache-Control',
                severity=Severity.INFO,
                title=f"Cache-Control: no-cache is limited to '{directives['no-cache']}'",
                description="With an argument, no-cache only covers the header fields it names: a "
                            "cache may serve the rest of the response without revalidating it "
                            "(RFC 9111). That is much weaker than a bare no-cache, and support "
                            "for the qualified form varies between caches.",
                recommendation="Use a bare no-cache, or no-store, if the whole response must not "
                               "be served from cache unchecked.",
            ))
        else:
            findings.append(Finding(
                header='Cache-Control',
                severity=Severity.OK,
                title="Cache-Control: no-cache (revalidated before use)",
                description="Content may be stored but will be revalidated with the server.",
                recommendation="For sensitive endpoints prefer no-store.",
            ))
    elif 'private' in directives:
        if directives['private']:
            findings.append(Finding(
                header='Cache-Control',
                severity=Severity.INFO,
                title=f"Cache-Control: private is limited to '{directives['private']}'",
                description="With an argument, private only covers the header fields it names: a "
                            "shared cache may store the rest of the response (RFC 9111). That is "
                            "the opposite of what a bare private means, and support for the "
                            "qualified form varies between caches.",
                recommendation="Use a bare private, or no-store, to keep the whole response out "
                               "of shared caches.",
            ))
        else:
            findings.append(Finding(
                header='Cache-Control',
                severity=Severity.OK,
                title="Cache-Control: private (shared caches must not store the response)",
                description="Only the user's browser may cache the response; shared caches (proxies, CDNs) will not.",
                recommendation="For highly sensitive responses prefer no-store (the browser can still cache 'private' to disk).",
            ))

    if 'public' in directives:
        findings.append(Finding(
            header='Cache-Control',
            severity=Severity.INFO,
            title="Cache-Control: public (shared caches allowed)",
            description="Ensure public caching is intentional for this response.",
        ))

    if not findings:
        unknown = set(directives) - _CACHE_CONTROL_DIRECTIVES
        if unknown:
            findings.append(Finding(
                header='Cache-Control',
                severity=Severity.INFO,
                title=f"Cache-Control: unrecognized directive(s): {', '.join(sorted(unknown))}",
                description=f"Value '{value}' contains tokens that are not standard Cache-Control directives.",
            ))
        else:
            findings.append(Finding('Cache-Control', Severity.OK, f"Cache-Control: '{value}' (valid caching directives)"))

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
    # The header is a flag ('0' or '1') optionally followed by directives, so the
    # flag has to be read on its own: searching the whole value for '1' matches
    # the digit inside a directive such as report=1.
    parts = [p.strip().lower() for p in value.split(';')]
    flag, directives = parts[0], parts[1:]

    if flag == '0':
        return [Finding(
            header='X-XSS-Protection',
            severity=Severity.OK,
            title="X-XSS-Protection: 0 (deprecated header, disabled correctly)",
            description="The header is deprecated. Setting it to 0 is correct for modern browsers.",
            recommendation="Consider removing this header entirely; rely on CSP instead.",
        )]
    if flag == '1' and 'mode=block' not in directives:
        return [Finding(
            header='X-XSS-Protection',
            severity=Severity.LOW,
            title="X-XSS-Protection: 1 enables the deprecated XSS filter",
            description="The filter matched text from the URL against the scripts in the page, "
                        "so an attacker could craft a URL that made it neutralise a script the "
                        "page legitimately contains — an anti-CSRF or framebusting script, for "
                        "example. No current browser honours the header, which is what keeps "
                        "this low.",
            recommendation="Set to 0 or remove the header; rely on Content-Security-Policy.",
        )]
    if flag == '1':
        return [Finding(
            header='X-XSS-Protection',
            severity=Severity.LOW,
            title="X-XSS-Protection: 1; mode=block (deprecated, potentially risky)",
            description="mode=block stops the page from rendering when the filter triggers, and "
                        "the filter triggers on scripts the page legitimately contains whenever "
                        "their markup also appears in the URL. Whether a page was blocked is "
                        "observable from another origin, turning 'does this page contain script "
                        "X?' into a yes/no readable from outside. No current browser honours the "
                        "header, which is what keeps this low.",
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
            description="Any site can read this response. That costs nothing if the endpoint is "
                        "genuinely public, which is what the wildcard is for. It matters when the "
                        "endpoint is reachable by a victim's browser but not by an attacker's "
                        "server — an internal API, a service on localhost, a device admin page, "
                        "anything authorised by network or IP rather than by credentials. Without "
                        "the wildcard a browser sends such a request but refuses to hand the "
                        "response to the calling page; with it, an attacker's page reads the "
                        "answer through the browser of whoever can reach the endpoint.",
            recommendation="Check whether this endpoint is reachable from anywhere or only from "
                           "certain networks. If access is limited in any way, name the origins "
                           "allowed to read it instead of using '*'.",
        )]
    if n.lower() == 'null':
        return [Finding(
            header='Access-Control-Allow-Origin',
            severity=Severity.HIGH,
            title="Access-Control-Allow-Origin: null",
            description="The null origin is not a trusted party: any page can obtain it through a "
                        "sandboxed iframe, a data: URL or a cross-origin redirect. Unlike the "
                        "wildcard, it is a concrete origin, so browsers do send credentials with it "
                        "when Access-Control-Allow-Credentials is true — which lets an attacker read "
                        "authenticated responses. It usually comes from reflecting the Origin header.",
            recommendation="Never allowlist 'null'. Echo only origins from a known list.",
        )]
    if ',' in n:
        # Fails closed — nobody gets access — so this is a broken configuration
        # rather than an exposure.
        return [Finding(
            header='Access-Control-Allow-Origin',
            severity=Severity.INFO,
            title=f"Access-Control-Allow-Origin lists more than one origin: '{n}'",
            description="The header carries exactly one origin, or '*', or 'null'. A list never "
                        "matches the requesting origin, so the CORS check fails and no site gets "
                        "access — including the ones it was meant for. A list usually means two "
                        "components are both setting the header, typically the application and a "
                        "proxy in front of it.",
            recommendation="Send a single origin, picked per request from an allowlist.",
        )]
    if n.lower().startswith('http://'):
        return [Finding(
            header='Access-Control-Allow-Origin',
            severity=Severity.LOW,
            title=f"Access-Control-Allow-Origin allows a plaintext origin: '{n}'",
            description="The allowed origin is not protected by TLS, so anyone able to tamper with "
                        "traffic to it can impersonate it and read whatever this endpoint returns "
                        "to it. A localhost origin here usually means a development configuration "
                        "reached production.",
            recommendation="Allow an https:// origin instead.",
        )]
    return [Finding('Access-Control-Allow-Origin', Severity.OK, f"Access-Control-Allow-Origin: specific origin ('{n}')")]


def _check_acac(value: str, extra: dict) -> list[Finding]:
    # "Send the cookies" says nothing without knowing to whom, so this checker
    # states the fact and leaves the verdict to _cors_credentials in
    # lib/correlations.py, which sees Access-Control-Allow-Origin as well.
    if value.strip().lower() == 'true':
        return [Finding(
            header='Access-Control-Allow-Credentials',
            severity=Severity.OK,
            title="Access-Control-Allow-Credentials: true",
            description="Assessed together with Access-Control-Allow-Origin.",
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
    # The disposition type is the first token; 'attachmentx' is not 'attachment'.
    lower = value.split(';')[0].strip().lower()
    if lower == 'attachment':
        return [Finding('Content-Disposition', Severity.OK, "Content-Disposition: attachment (prevents inline rendering)")]
    if lower == 'inline':
        return [Finding(
            header='Content-Disposition',
            severity=Severity.OK,
            title="Content-Disposition: inline",
            description="Browser will attempt to render the content inline.",
            recommendation="Use 'attachment; filename=...' for file downloads to prevent inline execution.",
        )]
    return [Finding('Content-Disposition', Severity.INFO, f"Content-Disposition: '{value}'")]


def _check_pragma(value: str, extra: dict) -> list[Finding]:
    if value.strip().lower() == 'no-cache':
        return [Finding(
            header='Pragma',
            severity=Severity.OK,
            title="Pragma: no-cache (HTTP/1.0 legacy header)",
            description="Pragma is a legacy HTTP/1.0 header superseded by Cache-Control; its presence is harmless.",
        )]
    return [Finding('Pragma', Severity.OK, f"Pragma: '{value}' (legacy HTTP/1.0 header)")]


def _check_expires(value: str, extra: dict) -> list[Finding]:
    if value.strip() in ('0', '-1'):
        return [Finding('Expires', Severity.OK, "Expires: 0 (immediately expired, no caching)")]
    return [Finding(
        header='Expires',
        severity=Severity.OK,
        title=f"Expires: '{value}' (legacy HTTP/1.0 caching header)",
        description="Expires is a legacy header superseded by Cache-Control: max-age; its presence is harmless.",
    )]


def _check_etag(value: str, extra: dict) -> list[Finding]:
    if value.strip().startswith('W/'):
        return [Finding('ETag', Severity.OK, "ETag: weak validator present")]
    return [Finding('ETag', Severity.OK, "ETag: strong validator present")]


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
        "If this response carries data belonging to a signed-in user, send "
        "Cache-Control: no-store.",
}

# Descriptions for headers whose absence needs more than "it is not there".
_MISSING_DESCRIPTIONS: dict[str, str] = {
    'referrer-policy':
        "With no policy of its own, the response inherits whatever default the browser "
        "applies — something the site does not control and that has already changed once. "
        "Current browsers use strict-origin-when-cross-origin, which sends no more than the "
        "origin; older ones send the complete URL, path and query string included, to every "
        "third party reached over HTTPS. Stating the policy makes every browser behave the "
        "same.",
    'cache-control':
        "With no explicit caching instruction, browsers and intermediaries fall back to "
        "heuristic caching and may keep this response on disk. That is harmless for a "
        "static asset. It is a problem for a response carrying a signed-in user's data, "
        "which can then be read from the cache after logout or by the next person to use "
        "a shared machine.",
}
