"""
Header rule engine.
Each checker returns a list[Finding] given (header_value, extra_config_dict).
"""
import re
from typing import Callable, Optional

from .config import AppConfig, HeaderOverride, get_override
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
    # Absence leaves the same state a policy that names none of the any-origin
    # features leaves, and is graded the same — see _MISSING_DESCRIPTIONS.
    ("permissions-policy",               "Permissions-Policy",               True,  Severity.LOW),
    ("referrer-policy",                  "Referrer-Policy",                  True,  Severity.MEDIUM),
    ("cross-origin-embedder-policy",     "Cross-Origin-Embedder-Policy",     False, Severity.LOW),
    ("cross-origin-resource-policy",     "Cross-Origin-Resource-Policy",     False, Severity.LOW),
    ("x-permitted-cross-domain-policies","X-Permitted-Cross-Domain-Policies",False, Severity.LOW),
    ("cache-control",                    "Cache-Control",                    True,  Severity.MEDIUM),
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

# Headers whose absence is the state to be in, so "Missing" would name a
# deficiency on every correctly configured response. These checks exist for the
# responses that do send them.
_ABSENCE_IS_CORRECT = {
    # Deprecated: not to be sent at all, and the filter one of them enables was
    # itself a vulnerability.
    'x-xss-protection', 'expect-ct',
    # No CORS headers means same-origin only, which is the secure default. A
    # response that needed them and lacks them is broken, not exposed.
    'access-control-allow-origin', 'access-control-allow-credentials',
}

# ---------------------------------------------------------------------------
# Duplicate-header resolution, mirroring real browser behavior:
#   first     — first occurrence wins (default; e.g. HSTS per RFC 6797 §8.1)
#   join      — occurrences combine into one value (RFC list headers; for CSP,
#               multiple headers are all enforced, equivalent to joining with
#               ','). Whether the combined value is still valid is the checker's
#               business: COOP and COEP join into something no browser can parse.
# ---------------------------------------------------------------------------
_DUPLICATE_STRATEGIES: dict[str, str] = {
    'referrer-policy':              'join',
    'x-frame-options':              'join',
    'content-security-policy':      'join',
    'cache-control':                'join',
    'clear-site-data':              'join',
    'permissions-policy':           'join',
    'pragma':                       'join',
    'cross-origin-opener-policy':   'join',
    'cross-origin-embedder-policy': 'join',
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

        if override.required is not None:
            required = override.required
        elif override.severity_if_missing:
            # Setting a severity for absence states that the header is expected;
            # an explicit `required: false` still wins over that.
            required = True
        else:
            required = default_required
        missing_sev = _parse_severity(override.severity_if_missing, default_missing_sev)

        findings: list[Finding] = []
        value: Optional[str] = None

        # Browsers ignore a header with an empty value, so its security impact is
        # identical to the header not being sent: both use the same severity.
        absent_sev = missing_sev if required else Severity.INFO

        if occurrences is None:
            if key in _ABSENCE_IS_CORRECT:
                results.append(HeaderResult(name=key, canonical_name=canonical,
                                            value=None, findings=[]))
                continue
            findings.append(Finding(
                header=canonical,
                severity=absent_sev,
                title=f"Missing {canonical}",
                description=_MISSING_DESCRIPTIONS.get(
                    key, f"The {canonical} header is absent from the response."),
                # A recommendation written for this header is worth showing whether or
                # not it is required — that is where an INFO finding would otherwise
                # say nothing useful. Only the generic fallback is held back. A header
                # whose absence is contingent carries the check instead.
                recommendation=("" if key in _MISSING_VERIFY else _MISSING_RECS.get(
                    key, f"Add the {canonical} header." if required else "")),
                verify=_MISSING_VERIFY.get(key, ""),
            ))
        else:
            value, dup_note = _resolve_duplicates(key, canonical, occurrences)
            if dup_note:
                findings.append(dup_note)
            if value.strip() == '' and key in _ABSENCE_IS_CORRECT:
                pass    # ignored by browsers, which is the state this header wants
            elif value.strip() == '':
                findings.append(Finding(
                    header=canonical,
                    severity=absent_sev,
                    title=f"{canonical}: present but empty",
                    description=(
                        f"{canonical} is present but carries no value. Browsers ignore it "
                        "entirely, so the effect is the same as not sending it at all. "
                        "An empty value usually points at a misconfigured template or proxy."
                    ),
                    recommendation=("" if key in _MISSING_VERIFY else
                                    _MISSING_RECS.get(key, f"Set a valid value for {canonical}.")),
                    verify=_MISSING_VERIFY.get(key, ""),
                ))
            else:
                findings.extend(_validate_value(key, canonical, value, override, absent_sev))

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


def _validate_value(
    key: str,
    canonical: str,
    value: str,
    override: HeaderOverride,
    absent_sev: Severity = Severity.INFO,
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
    extra = {**override.extra, ABSENT_SEVERITY: absent_sev}

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

    # Returns rather than falls through: with the entry deleted there is no policy
    # left for the other directives to qualify, and telling a site whose HSTS is
    # switched off to also add includeSubDomains is advice about nothing.
    if max_age == 0:
        return [Finding(
            header='Strict-Transport-Security',
            severity=extra.get(ABSENT_SEVERITY, Severity.HIGH),
            title="HSTS: max-age=0 revokes HSTS protection",
            description="max-age=0 instructs browsers to delete the HSTS entry, so this site "
                        "has no HSTS — the same position as never sending the header, and worse "
                        "for a visitor who had the entry already. It is the documented way to "
                        "turn HSTS off, so it may well be deliberate.",
            recommendation="Set max-age to at least 31536000 (1 year).",
        )]

    if max_age < min_age:
        findings.append(Finding(
            header='Strict-Transport-Security',
            severity=Severity.MEDIUM,
            title=f"HSTS: max-age too short ({max_age}s < {min_age}s)",
            description=f"OWASP recommends at least 1 year ({min_age}s). Short values reduce protection.",
            recommendation=f"Set max-age to at least {min_age}.",
        ))

    # Not contingent on the site having subdomains: the attacker supplies the name.
    # What makes it work is that cookies are scoped by domain and not by origin, so
    # a plaintext channel on any host under the registrable domain reaches the
    # cookie jar of the protected one.
    if extra.get('require_include_subdomains', True) and 'includesubdomains' not in directives:
        findings.append(Finding(
            header='Strict-Transport-Security',
            severity=Severity.MEDIUM,
            title="HSTS: missing includeSubDomains",
            description="HSTS covers this host and nothing else, and a host that does not exist "
                        "is not covered either. An attacker on the network path can answer for "
                        "anything.example.com over plain HTTP, and from there set cookies with "
                        "Domain=example.com — which the browser then sends to the protected site. "
                        "Browsers no longer let such an origin overwrite an existing Secure "
                        "cookie, but injecting one, or shadowing it on another path, still works. "
                        "A site with no subdomains at all is not exempt: the name is the "
                        "attacker's to choose.",
            recommendation="Add includeSubDomains, once every host under the domain is served "
                           "over HTTPS.",
        ))

    # Both branches are graded, and both are contingent on the same fact: the token
    # is a declaration of intent, and membership of the list is a separate step the
    # response cannot show. Absent or merely declared, if the domain is not listed
    # the site is in the same place — carrying the trust-on-first-use gap.
    if extra.get('require_preload', False):
        listed = ("Is the domain on the preload list? Check hstspreload.org. If it is, there "
                  "is nothing here. If it is not, ")
        if 'preload' not in directives:
            findings.append(Finding(
                header='Strict-Transport-Security',
                severity=Severity.LOW,
                title="HSTS: preload is not declared",
                description="Preloading is what closes the one gap HSTS cannot close on its own: "
                            "the first request to this domain, made before the browser has ever "
                            "seen the site, goes out over plain HTTP and can be stripped by "
                            "anyone on the network path.",
                verify=listed + "this stands. Preloading is also hard to undo and covers every "
                       "subdomain, so a site may have declined it deliberately — that is a "
                       "decision to record, not a defect to report.",
            ))
        else:
            findings.append(Finding(
                header='Strict-Transport-Security',
                severity=Severity.LOW,
                title="HSTS: preload is declared, which is not the same as being on the list",
                description="The token is what a domain must send to be accepted, not what puts "
                            "it there: submission at hstspreload.org is a separate step, and it "
                            "can be refused or reversed. A domain can carry this token for years "
                            "without ever being listed.",
                verify=listed + "the first-visit protection this header looks like it provides "
                       "does not exist, and the site is exactly where it would be without the "
                       "token.",
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
    """
    HTML's *check a navigation response's adherence to `X-Frame-Options`* works on
    a **set** of lowercased values, which is why repeating a value is harmless and
    mixing values is not a fallback: if the set holds more than one entry and any
    of them is usable, the browser blocks — "any attempts at applying
    X-Frame-Options which were trying to do something valid, but appear confused".
    Only when every entry is unusable does framing go ahead.
    """
    values = {v.strip().lower()
              for v in _split_outside_quotes(value, ',', keep_empty=True)}
    usable = values & {'deny', 'allowall', 'sameorigin'}

    if len(values) > 1:
        if usable:
            # Not a weakness: the outcome is the strongest one, it is the same in
            # every browser, and a contradiction here can only be stricter than its
            # parts — `allowall, bogus` blocks where either alone would not. What is
            # left to report is a deployment fact, so it is reported as one.
            return [Finding(
                header='X-Frame-Options',
                severity=Severity.NOTE,
                title=f"X-Frame-Options: '{value}' blocks framing by contradicting itself",
                description="More than one value is given, and at least one is usable, so a "
                            "browser refuses the frame rather than guess which was meant. "
                            "Framing is prevented, and a contradiction here can only ever be "
                            "stricter than the values it is made of — but whichever component "
                            "set the value being ignored is working on a false assumption, and "
                            "two components writing this header may be writing others.",
                recommendation="Send X-Frame-Options once, with DENY.",
            )]
        return [Finding(
            header='X-Frame-Options',
            severity=extra.get(ABSENT_SEVERITY, Severity.HIGH),
            title=f"X-Frame-Options: '{value}' leaves the page framable by anyone",
            description="Several values are given and none of them is one a browser applies, "
                        "so the header is treated as if it had been omitted.",
            recommendation="Set X-Frame-Options: DENY",
        )]

    only = next(iter(values))
    if only == 'deny':
        return [Finding('X-Frame-Options', Severity.OK, "X-Frame-Options: DENY (optimal)")]

    if only == 'sameorigin':
        return [Finding(
            header='X-Frame-Options',
            severity=Severity.LOW,
            title="X-Frame-Options: SAMEORIGIN lets another page on this origin frame it",
            description="A browser walks every containing document and refuses the frame as "
                        "soon as one is cross-origin, so this is as strong as frame-ancestors "
                        "'self'. What it still permits is a page on this same origin. That "
                        "matters where an attacker can put markup on one — a stored HTML "
                        "injection that a CSP stops short of script execution, say: they cannot "
                        "read anything through it, but they can frame this page and overlay it, "
                        "which DENY would have prevented outright.",
            verify="Does another page on this origin need to frame this one — an admin console, "
                   "a preview pane, an embedded editor? If one does, this stands and the "
                   "exposure is the price of the feature. If none does, DENY costs nothing and "
                   "closes it.",
        )]

    if only.startswith('allow-from'):
        return [Finding(
            header='X-Frame-Options',
            severity=extra.get(ABSENT_SEVERITY, Severity.HIGH),
            title="X-Frame-Options: ALLOW-FROM leaves the page framable by anyone",
            description="No current browser implements ALLOW-FROM, and none of them ignore just "
                        "the directive: they discard the whole header. The page is in the same "
                        "position as one that never sent it, while the header suggests a policy "
                        "is in force.",
            recommendation="Set X-Frame-Options: DENY, and name the permitted origins in "
                           "Content-Security-Policy: frame-ancestors.",
        )]

    return [Finding(
        header='X-Frame-Options',
        severity=extra.get(ABSENT_SEVERITY, Severity.HIGH),
        title=f"X-Frame-Options: '{value}' leaves the page framable by anyone",
        description="A browser applies this header for DENY and SAMEORIGIN and nothing else. "
                    "Anything else it cannot use, so framing is allowed exactly as if the "
                    "header were absent.",
        recommendation="Set X-Frame-Options: DENY",
    )]


def _check_x_content_type_options(value: str, extra: dict) -> list[Finding]:
    # Fetch's "determine nosniff" splits the value on commas and compares only
    # values[0], ASCII case-insensitively — so `nosniff, anything` is protected and
    # `anything, nosniff` is not. A quoted string is collected with its quotes, so
    # `"nosniff"` does not match: the quoted form the HSTS RFC allows is no good here.
    first = _split_outside_quotes(value, ',', keep_empty=True)[0].strip()
    if first.lower() == 'nosniff':
        return [Finding('X-Content-Type-Options', Severity.OK,
                        "X-Content-Type-Options: nosniff (correct)")]
    return [Finding(
        header='X-Content-Type-Options',
        severity=extra.get(ABSENT_SEVERITY, Severity.MEDIUM),
        title=f"X-Content-Type-Options: '{first}' leaves MIME sniffing on",
        description="Only 'nosniff' switches the protection on, and only as the first value of "
                    "the header. Anything else leaves the browser free to ignore the declared "
                    "Content-Type and guess from the bytes — so a file a user uploaded, served "
                    "as text/plain, can still be read as HTML and run as the site. It also stops "
                    "blocking a script or stylesheet whose response carries the wrong type.",
        recommendation="Set X-Content-Type-Options: nosniff",
    )]


# RFC 8941 §3.3.4 (sf-token) and §3.1.2 (parameter names).
_SF_TOKEN = re.compile(r"^[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*$")
_SF_PARAM_NAME = re.compile(r"^[a-z*][a-z0-9_.*-]*$")


def _structured_token(value: str) -> Optional[str]:
    """The token a browser reads out of a structured field of type item, or None
    when the value does not parse.

    COOP and COEP are both defined this way (HTML §7.1.3.1): one token, which may
    carry parameters — of these only `report-to` is defined, and no parameter
    changes which policy applies. What does matter is that a value which fails to
    parse leaves the policy at unsafe-none, so the header does nothing at all.

    The caller checks for a comma first: that is how a browser sees the header sent
    twice, and it deserves its own explanation.
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
    """Weaker than same-origin, so it is reported — whether the weakening costs
    anything here depends on what the document opens, which the response does not
    say. The finding carries that check rather than a change to make blindly: for a
    site that opens an OAuth or payment provider, this is the value to use."""
    return Finding(
        header='Cross-Origin-Opener-Policy',
        severity=Severity.LOW,
        title=f"COOP: {token} lets a window this document opens keep a reference back",
        description=f"{_COOP_ALLOW_POPUPS_KEPT[token]} What it gives up is in the other "
                    "direction: a window this document opens with window.open() stays in its "
                    "browsing context group if that window sends no COOP of its own, so the "
                    "window keeps a window.opener reference back and can probe this document "
                    "through it. That only matters if this document opens windows it does not "
                    "control.",
        verify="What does this document pass to window.open()? A provider the site chose — an "
               "OAuth or payment flow — is what this value exists for, and there is nothing "
               "here. A URL the site does not control keeps a window.opener reference back to "
               "this document, and then this stands: same-origin severs it.",
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

    n = _structured_token(value)
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


def _coep_no_isolation(extra: dict, title: str, why: str) -> Finding:
    """Every way of not having COEP, graded alike — they are one browser state.

    Unlike COOP, this is not an exposure: losing cross-origin isolation removes a
    capability (SharedArrayBuffer, unthrottled timers) rather than opening
    anything, and the browser withdraws it rather than running unsafely. So these
    carry the severity of an absent COEP, which is what the response amounts to.
    """
    return Finding(
        header='Cross-Origin-Embedder-Policy',
        severity=extra.get(ABSENT_SEVERITY, Severity.INFO),
        title=title,
        description=f"{why} Cross-origin resources requested in no-cors mode load without "
                    "having to opt in through CORP, and the document is not cross-origin "
                    "isolated — the same position as never sending the header. This fails "
                    "safe: features that depend on the isolation are withheld, not left "
                    "running without it.",
        recommendation="Set Cross-Origin-Embedder-Policy: require-corp (with "
                       "Cross-Origin-Opener-Policy: same-origin) if cross-origin isolation "
                       "is wanted.",
    )


def _check_coep(value: str, extra: dict) -> list[Finding]:
    # A comma is how a browser sees the header sent twice; MDN states the outcome
    # outright: "Setting the header more than once or with multiple tokens is
    # equivalent to setting unsafe-none."
    if len(_split_outside_quotes(value, ',')) > 1:
        return [_coep_no_isolation(
            extra,
            "COEP: the header is not applied — it carries more than one value",
            "Cross-Origin-Embedder-Policy must hold a single token, and a browser cannot parse "
            "this one, so it applies unsafe-none. Sending the header twice produces this, even "
            "when both copies are identical.",
        )]

    n = _structured_token(value)
    if n is None:
        return [_coep_no_isolation(
            extra,
            f"COEP: the header is not applied — '{value.strip()}' is not a valid header value",
            "A browser cannot parse this value, so it applies unsafe-none.",
        )]
    if n == 'require-corp':
        return [Finding(
            header='Cross-Origin-Embedder-Policy',
            severity=Severity.OK,
            title="COEP: require-corp",
            description="Cross-origin resources requested in no-cors mode must opt in through "
                        "CORP or CORS. This is the COEP half of cross-origin isolation, which "
                        "also needs Cross-Origin-Opener-Policy: same-origin.",
        )]
    if n == 'credentialless':
        return [Finding(
            header='Cross-Origin-Embedder-Policy',
            severity=Severity.OK,
            title="COEP: credentialless",
            description="Cross-origin resources requested in no-cors mode load without having "
                        "to opt in through CORP, but are fetched with no credentials, so they "
                        "cannot carry anyone's private data. It qualifies for cross-origin "
                        "isolation exactly as require-corp does — a different mechanism for "
                        "the same guarantee, not a weaker one.",
        )]
    if n == 'unsafe-none':
        return [_coep_no_isolation(
            extra,
            "COEP: unsafe-none is the value a browser applies anyway",
            "unsafe-none is the default, so stating it changes nothing.",
        )]
    return [_coep_no_isolation(
        extra,
        f"COEP: the header is not applied — '{n}' is not a policy browsers recognize",
        "A browser that does not recognise the token applies unsafe-none.",
    )]


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


# Every Permissions-Policy directive, with the allowlist a browser applies when a
# policy does not mention it. This is the axis the checks run on, because it is
# what an undeclared feature actually leaves open: only nine directives default to
# `*`, and it is those — not `camera` or `payment` — that an embedded cross-origin
# document can use unless the policy takes them away.
_PP_DEFAULT_ANY_ORIGIN = {
    'attribution-reporting', 'browsing-topics', 'ch-ua-high-entropy-values',
    'deferred-fetch-minimal', 'gamepad', 'picture-in-picture',
    'private-state-token-issuance', 'private-state-token-redemption',
    'storage-access',
}
_PP_DEFAULT_SELF = {
    'accelerometer', 'ambient-light-sensor', 'aria-notify', 'autoplay', 'bluetooth',
    'camera', 'captured-surface-control', 'compute-pressure', 'cross-origin-isolated',
    'deferred-fetch', 'display-capture', 'encrypted-media', 'fullscreen', 'geolocation',
    'gyroscope', 'hid', 'identity-credentials-get', 'idle-detection', 'language-detector',
    'local-fonts', 'local-network', 'local-network-access', 'loopback-network',
    'magnetometer', 'microphone', 'midi', 'on-device-speech-recognition',
    'otp-credentials', 'payment', 'publickey-credentials-create',
    'publickey-credentials-get', 'screen-wake-lock', 'serial', 'speaker-selection',
    'summarizer', 'translator', 'usb', 'web-share', 'window-management',
    'xr-spatial-tracking',
}

# The any-origin features worth naming: what an embedded document gains from them
# is tracking and fingerprinting surface. The other three in that group — gamepad,
# picture-in-picture, deferred-fetch-minimal — are in the same position with no
# consequence worth reporting, and listing them only dilutes the ones that matter.
_PP_TRACKING = {
    'attribution-reporting', 'browsing-topics', 'ch-ua-high-entropy-values',
    'private-state-token-issuance', 'private-state-token-redemption', 'storage-access',
}

# Features an XSS turns into access with a single click. A permission prompt names
# the site, never the code that asked, so a user with no way to tell the two apart
# grants it to whoever is running. What rules the others out is not the prompt but
# the choice after it: display-capture makes the user pick what to share, usb,
# serial, hid and bluetooth make them pick a device, payment opens a payment flow.
# For these three, "Allow" is the whole interaction.
_PP_ONE_CLICK = ('camera', 'microphone', 'geolocation')


def _parse_pp_features(value: str) -> dict[str, str]:
    """Map each declared feature to its allowlist, e.g. {'camera': '()'}."""
    features: dict[str, str] = {}
    for part in _split_outside_quotes(value, ','):
        name, sep, allowlist = part.partition('=')
        if sep:
            features[name.strip().lower()] = allowlist.strip()
    return features


def _pp_allowlist_origins(allowlist: str) -> list[str]:
    """The origins inside an allowlist: `*`, `(self)`, `("https://a.example")`."""
    a = allowlist.strip()
    if a.startswith('(') and a.endswith(')'):
        a = a[1:-1]
    return [token.strip().strip('"') for token in a.split() if token.strip()]


def _pp_effective(feature: str, declared: dict[str, str]) -> list[str]:
    """The origins a feature ends up allowed to, declared or not."""
    if feature in declared:
        return _pp_allowlist_origins(declared[feature])
    return ['*'] if feature in _PP_DEFAULT_ANY_ORIGIN else ['self']


def _pp_reaches_an_embed(feature: str, declared: dict[str, str]) -> bool:
    """Whether a cross-origin document embedded in the page can use the feature.
    `(self)` closes that door; only `()` also closes it to this origin."""
    return any(origin != 'self' for origin in _pp_effective(feature, declared))


def _pp_reaches_this_origin(feature: str, declared: dict[str, str]) -> bool:
    """Whether script running on this origin — an XSS included — can use it."""
    origins = _pp_effective(feature, declared)
    return '*' in origins or 'self' in origins


def _check_permissions_policy(value: str, extra: dict) -> list[Finding]:
    findings: list[Finding] = []
    declared = _parse_pp_features(value)

    # Read the allowlist of each declared feature rather than searching the raw
    # value: a \b boundary also matches after the hyphen of an unrelated name.
    opened = sorted(
        f for f, allowlist in declared.items()
        if f in _PP_DEFAULT_SELF and '*' in _pp_allowlist_origins(allowlist)
    )
    if opened:
        findings.append(Finding(
            header='Permissions-Policy',
            severity=Severity.MEDIUM,
            title=f"Permissions-Policy: opened to any origin: {', '.join(opened)}",
            description="A browser allows these features to this origin only. The policy "
                        "widens them to '*', so any document embedded in this page can use "
                        "them — the policy is granting access rather than restricting it.",
            recommendation="Restrict these to () or (self) unless an embedded third party "
                           "genuinely needs them.",
        ))

    reaches_embeds = sorted(f for f in _PP_TRACKING if _pp_reaches_an_embed(f, declared))
    if reaches_embeds:
        findings.append(Finding(
            header='Permissions-Policy',
            severity=Severity.INFO,
            title=f"Permissions-Policy: available to any embedded document: {', '.join(reaches_embeds)}",
            description="A browser allows these to every origin, so any cross-origin document "
                        "this page embeds can use them until the policy says otherwise: reading "
                        "the user's inferred interest topics, asking for high-entropy user-agent "
                        "hints, registering ad attributions, issuing and redeeming tracking "
                        "tokens, requesting its own third-party cookies. (gamepad, "
                        "picture-in-picture and deferred-fetch-minimal are open the same way, "
                        "with nothing worth reporting behind them.) This is the user's privacy "
                        "toward parties the site chose to embed, and for an advertising or "
                        "analytics frame it is what the frame was embedded to do — which is why "
                        "it is stated rather than counted as a defect. It is worth a look when "
                        "the embed is there for something else entirely and picks these up "
                        "along the way. Closing them to an embed takes (self); () also takes "
                        "them from this origin.",
            verify="What does this page embed? For an advertising or analytics frame, reading "
                   "topics and registering attributions is what it was embedded to do, and "
                   "there is nothing here. For a frame that is there for something else — a "
                   "chat widget, a video player — it picks these up along the way, and closing "
                   f"them costs nothing: {', '.join(f + '=()' for f in reaches_embeds)}",
        ))

    one_click = [f for f in _PP_ONE_CLICK if _pp_reaches_this_origin(f, declared)]
    if one_click:
        findings.append(Finding(
            header='Permissions-Policy',
            severity=Severity.LOW,
            title=f"Permissions-Policy: an XSS on this origin could ask for {', '.join(one_click)}",
            description="Nothing embedded cross-origin can reach these — a browser keeps them "
                        "to this origin either way. What is left open is script that achieves "
                        "execution here: it can raise the permission prompt, and the prompt "
                        "names the site, never the code that asked, so a user who has no way "
                        "to tell the two apart grants it. One click is the whole interaction. "
                        "Disabling them removes the prompt itself; (self) does not, because "
                        "an XSS runs on this origin.",
            verify="Does this response need them? If it does not, this stands — script that "
                   "reaches execution here can raise the prompt, and one click grants it: "
                   f"{', '.join(f + '=()' for f in one_click)}. If it does, the header is "
                   "per-response, so they can still be closed on every other response.",
        ))

    if not findings:
        findings.append(Finding('Permissions-Policy', Severity.OK,
                                "Permissions-Policy: every feature addressed"))
    return findings


_REFERRER_POLICIES = {
    'no-referrer', 'no-referrer-when-downgrade', 'same-origin', 'origin',
    'strict-origin', 'origin-when-cross-origin', 'strict-origin-when-cross-origin',
    'unsafe-url',
}


def _check_referrer_policy(value: str, extra: dict) -> list[Finding]:
    # W3C Referrer Policy §8.1 walks every comma-separated token and keeps the last
    # one that names a policy, skipping empty and unknown tokens rather than
    # failing on them. The spec's own note says the loop is there so a site can
    # write `no-referrer, strict-origin-when-cross-origin` and have old browsers
    # take the first and new ones the second — so a list is the recommended shape,
    # not a mistake, and only the token that survives it can be graded.
    n = ''
    for token in _split_outside_quotes(value, ','):
        token = token.strip().lower()
        if token in _REFERRER_POLICIES:
            n = token

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
        # Never a path or query, so the disclosure is small — but it is strictly
        # more than the strict- variants give up, for nothing in return. Whether
        # it costs anything here depends on what the page reaches, which the
        # response does not say, so the finding carries the check to run.
        return [Finding(
            header='Referrer-Policy',
            severity=Severity.LOW,
            title=f"Referrer-Policy: '{n}' (sends the origin to plain-HTTP destinations too)",
            description="Only the origin is sent, never the path or query, but it reaches "
                        "destinations that are not TLS-protected as well, where anyone on the "
                        "network path reads which site the user is on. The strict- variants are "
                        "identical except that they withhold it on such a downgrade.",
            verify="Does the page link to, or load anything from, a plain-HTTP destination? If "
                   "it does, the origin reaches whoever is on the network path and this stands. "
                   "If it does not, nothing leaks today — but the strict- variants behave "
                   "identically over HTTPS, so they give up strictly less for nothing in return "
                   "and the change is free either way.",
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


# The question every non-OK caching verdict below turns on. Asked once, because
# the answer is the same for all of them and it is not in the response.
_CACHE_CONTROL_VERIFY = (
    "Does this response carry data belonging to a signed-in user? If it does not, there "
    "is nothing here — storing a public resource is what these directives are for, and "
    "no-store would only cost bandwidth. If it does, how is the user identified? "
    "By a session cookie: this stands, and a shared cache can hand the response to the "
    "next person who asks for the same URL. "
    "By an Authorization header: RFC 9111 §3.5 already bars a shared cache from reusing "
    "it, so what is left is the copy on the user's own disk — unless the value also "
    "carries public, s-maxage or must-revalidate, the three directives that switch "
    "shared-cache reuse back on for exactly those requests."
)


def _check_cache_control(value: str, extra: dict) -> list[Finding]:
    """
    Graded for a response carrying a signed-in user's data, which is the case
    where caching costs something. Whether this response is one of those is a
    question about the endpoint, so every verdict but `no-store` carries it.

    Only `no-store` keeps such a response out of every cache. `private` stops the
    shared caches but leaves a copy on the user's disk; `no-cache` stops neither,
    it only forces revalidation. Anything else lets a shared cache keep the
    response and hand it to the next person who asks for the same URL.
    """
    # Directive names have to be read as names: searching the raw value for
    # 'no-store' also matches a token that merely contains it, and misses the
    # difference between `no-cache` and the far weaker `no-cache="Some-Header"`.
    directives = _parse_directives(value, ',')

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
                        "no Cache-Control at all. Nothing keeps this response out of a shared "
                        "cache.",
            verify=_CACHE_CONTROL_VERIFY,
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
            verify=_CACHE_CONTROL_VERIFY,
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
                        "shared cache may keep the response, and nothing here marks it as "
                        "belonging to a single user.",
            verify=_CACHE_CONTROL_VERIFY,
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
        verify=_CACHE_CONTROL_VERIFY,
    )]


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
        severity=extra.get(ABSENT_SEVERITY, Severity.INFO),
        title=f"X-DNS-Prefetch-Control: '{value}' (DNS prefetching enabled)",
        description="DNS prefetching resolves domains linked in the page before the user clicks. "
                    "The DNS resolver learns every hostname the page links to — internal services, "
                    "private subdomains, an admin panel the page references — whether or not the "
                    "user navigates there. And an attacker with HTML injection can exfiltrate data "
                    "through it: <link rel=dns-prefetch> resolves before any CSP directive can "
                    "stop it, so a page whose CSP blocks scripts, images and connections still "
                    "leaks data through DNS queries to a resolver the attacker controls.",
        recommendation="Set X-DNS-Prefetch-Control: off",
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
            severity=Severity.HIGH,
            title="Access-Control-Allow-Origin: * (wildcard)",
            description="Any site can read this response. That costs nothing if the endpoint is "
                        "genuinely public, which is what the wildcard is for. It matters when the "
                        "endpoint is reachable by a victim's browser but not by an attacker's "
                        "server — an internal API, a service on localhost, a device admin page, "
                        "anything authorised by network or IP rather than by credentials. Without "
                        "the wildcard a browser sends such a request but refuses to hand the "
                        "response to the calling page; with it, an attacker's page reads the "
                        "answer through the browser of whoever can reach the endpoint.",
            verify="Is this endpoint reachable from anywhere, or only from certain networks? "
                   "Reachable from anywhere and it costs nothing — that is what the wildcard is "
                   "for. Limited in any way — an internal network, a VPN, localhost — and this "
                   "stands: name the origins allowed to read it instead of '*'.",
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
    # A response that echoes the request's Origin is byte-for-byte this one, and a
    # single saved response cannot tell an allowlist from a mirror. Graded as the
    # case it cannot rule out: a reflected origin makes this the wildcard, since
    # whatever the attacker sends comes back.
    return [Finding(
        header='Access-Control-Allow-Origin',
        severity=Severity.HIGH,
        title=f"Access-Control-Allow-Origin: single origin ('{n}') — an allowlist or a mirror",
        description="One origin is authorised, which is how CORS is meant to be used. But a "
                    "server that copies the request's Origin header into the response produces "
                    "exactly this, and then the authorised origin is whichever one asked: any "
                    "site reads what this endpoint returns, the same as '*'.",
        verify="Replay the request with Origin: https://an-origin-you-made-up.example. If it "
               "comes back here, the origin is reflected and this stands. If the header keeps "
               f"naming {n} or disappears, the allowlist is real and there is nothing here.",
    )]


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


# Every value a browser might act on, not only the five §4.1 switches on: two more
# ship in Chromium without being in the specification at all. The quotes are part
# of the comparison — the grammar is `1#( quoted-string )` and values are extracted
# with their quotes intact, so an unquoted token matches nothing and is passed over.
_CSD_TYPES = {
    '"cache"', '"cookies"', '"storage"', '"executionContexts"', '"clientHints"',
    '"prefetchCache"', '"prerenderCache"',      # Chromium only, outside the spec
}
_CSD_WILDCARD = '"*"'

# What a response that clears data is asked to name: the three every current
# browser acts on. The rest are recognised above so that naming them is never
# mistaken for naming nothing, but are not required —
#   executionContexts  no shipping browser implements it. Chrome and Edge never
#                      did; Firefox carried it 63→68 and Safari 17→18.3, and both
#                      withdrew it, so asking for it asks for what runs nowhere.
#   clientHints        `"cache"` and `"cookies"` already imply it.
#   prefetch/prerenderCache  Chromium-only extensions, absent from the spec.
_CSD_EXPECTED = {'"cache"', '"cookies"', '"storage"'}

# The one question every verdict here turns on. This header only has a job on a
# response that ends something, and which response that is lives in the request
# and the application, not in the headers.
_CSD_VERIFY = (
    "Is this a response that ends a session — a logout, a password change, an account "
    "deletion? If it is not, there is nothing here: this header only has a job where data "
    "should stop being available, and clearing a visitor's storage on an ordinary page "
    "would be the defect. If it is, what the response leaves behind stays readable to "
    "whoever uses the browser next."
)


def _check_clear_site_data(value: str, extra: dict) -> list[Finding]:
    declared = {t.strip() for t in _split_outside_quotes(value, ',')}
    known = declared & (_CSD_TYPES | {_CSD_WILDCARD})

    if not known:
        # Every token was skipped, so the list of types is empty and nothing is
        # cleared — while the response looks like it clears something.
        return [Finding(
            header='Clear-Site-Data',
            severity=Severity.LOW,
            title=f"Clear-Site-Data: '{value}' clears nothing",
            description="Every value has to be a quoted string — the grammar is "
                        "1#( quoted-string ) — and a browser compares each one with its quotes "
                        "still attached. None of these matches a type it knows, so the list it "
                        "builds is empty and no data is removed. Writing * or cookies without "
                        "quotes is the usual way to land here.",
            verify=_CSD_VERIFY,
        )]

    if _CSD_WILDCARD in known:
        return [Finding('Clear-Site-Data', Severity.OK,
                        'Clear-Site-Data: "*" (every type cleared)')]

    missing = _CSD_EXPECTED - known
    if missing:
        return [Finding(
            header='Clear-Site-Data',
            severity=Severity.LOW,
            title=f"Clear-Site-Data: missing directives: {', '.join(sorted(missing))}",
            description="Some types are cleared and these are not. Leaving one out can be "
                        "deliberate — the specification has an example of a site clearing a "
                        "subset on purpose, because sweeping every subdomain does damage of its "
                        "own, and on Chromium `\"cache\"` is the least dependable of the three, "
                        "with documented multi-second hangs.",
            verify=_CSD_VERIFY + " Was leaving these out a decision? What the session relies on "
                   "decides whether it matters: a token in localStorage outlives a policy that "
                   "clears only cookies.",
        )]
    return [Finding('Clear-Site-Data', Severity.OK,
                    'Clear-Site-Data: cache, cookies and storage cleared')]


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
        "Close what this response does not need: "
        + ", ".join(f + '=()' for f in sorted(_PP_TRACKING) + list(_PP_ONE_CLICK)),
    'referrer-policy':
        "Referrer-Policy: strict-origin-when-cross-origin",
    'cross-origin-embedder-policy':
        "Cross-Origin-Embedder-Policy: require-corp",
    'cross-origin-resource-policy':
        "Cross-Origin-Resource-Policy: same-origin",
    'x-dns-prefetch-control':
        "X-DNS-Prefetch-Control: off",
}

# Where the absence of a header only matters under a condition the response does
# not state, the finding carries that check instead of a recommendation.
_MISSING_VERIFY: dict[str, str] = {
    'cache-control': _CACHE_CONTROL_VERIFY,
    'clear-site-data': _CSD_VERIFY,
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
    'clear-site-data':
        "This response clears no site data. On almost every response that is the right "
        "outcome — the header exists to end things, not to be present.",
    'permissions-policy':
        "Every feature stays at the allowlist a browser applies by default, which leaves "
        "two things open. A cross-origin document embedded in this page can use the "
        f"features a browser allows to every origin — {', '.join(sorted(_PP_TRACKING))} — "
        "which is tracking and fingerprinting surface. And script that achieves execution "
        f"on this origin can raise the permission prompt for {', '.join(_PP_ONE_CLICK)}: "
        "the prompt names the site, never the code that asked, so one click from a user "
        "who cannot tell the two apart is the whole interaction. A policy is the only "
        "thing that removes the prompt.",
    'x-dns-prefetch-control':
        "Browsers resolve domains linked in the page before the user navigates, by default. "
        "The DNS resolver learns every hostname the page references — internal services, "
        "private subdomains — whether or not the user clicks. And an attacker with HTML "
        "injection can exfiltrate data through it: <link rel=dns-prefetch> resolves before "
        "any CSP directive can stop it, so a page whose CSP blocks scripts, images and "
        "connections still leaks data through DNS queries to a resolver the attacker controls.",
}
