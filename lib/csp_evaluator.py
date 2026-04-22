"""
CSP evaluation engine (built-in Python implementation).
"""
import re
from typing import Optional

from .models import Finding, Severity

# ---------------------------------------------------------------------------
# Known domains/base-domains that host JSONP endpoints or Angular, enabling
# CSP bypass even when listed as trusted script sources.
# ---------------------------------------------------------------------------
_BYPASS_EXACT_HOSTS = {
    'ajax.googleapis.com',
    'www.googleapis.com',
    'maps.googleapis.com',
    'clients1.google.com',
    'accounts.google.com',
    'ssl.google-analytics.com',
    'www.google-analytics.com',
    'cdn.jsdelivr.net',
    'cdnjs.cloudflare.com',
    'code.jquery.com',
    'maxcdn.bootstrapcdn.com',
    'yandex.st',
}

# wildcard *.base matches any subdomain, some of which host bypass endpoints
_BYPASS_BASE_DOMAINS = {
    'googleapis.com',
    'googleusercontent.com',
    'jsdelivr.net',
    'cloudflare.com',
    'bootstrapcdn.com',
}

_BROAD_WILDCARDS = {'*.com', '*.net', '*.org', '*.edu', '*.gov', '*.io', '*.co'}

# CSP directive names — used to detect missing semicolons
_KNOWN_DIRECTIVES = {
    'default-src', 'script-src', 'script-src-elem', 'script-src-attr',
    'style-src', 'style-src-elem', 'style-src-attr', 'img-src', 'font-src',
    'connect-src', 'media-src', 'object-src', 'frame-src', 'worker-src',
    'manifest-src', 'prefetch-src', 'navigate-to', 'base-uri', 'form-action',
    'frame-ancestors', 'sandbox', 'report-uri', 'report-to',
    'upgrade-insecure-requests', 'block-all-mixed-content',
    'require-trusted-types-for', 'trusted-types',
    'reflected-xss', 'referrer', 'disown-opener',
}

# Keywords that must be surrounded by single quotes to be valid CSP keywords
_UNQUOTED_KEYWORDS = {
    'unsafe-inline', 'unsafe-eval', 'unsafe-hashes',
    'strict-dynamic', 'none', 'self', 'report-sample',
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate_csp(csp_value: str) -> list[Finding]:
    return _python_evaluate(csp_value)


# ---------------------------------------------------------------------------
# Python evaluator
# ---------------------------------------------------------------------------

class _CSPParser:
    def __init__(self, raw: str):
        self.directives: dict[str, list[str]] = {}
        for part in raw.split(';'):
            tokens = part.strip().split()
            if tokens:
                self.directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]

    def effective(self, directive: str) -> Optional[list[str]]:
        if directive in self.directives:
            return self.directives[directive]
        return self.directives.get('default-src')


def _python_evaluate(csp_value: str) -> list[Finding]:
    findings: list[Finding] = []
    csp = _CSPParser(csp_value)

    _check_missing_semicolon(csp, findings)
    _check_invalid_keyword(csp, findings)
    _check_missing_script_src(csp, findings)
    _check_script_src(csp, findings)
    _check_style_src(csp, findings)
    _check_object_src(csp, findings)
    _check_base_uri(csp, findings)
    _check_frame_ancestors(csp, findings)
    _check_default_src(csp, findings)
    _check_misc(csp, findings)

    return findings


def _check_missing_semicolon(csp: _CSPParser, findings: list[Finding]):
    for directive, values in csp.directives.items():
        for value in values:
            if value in _KNOWN_DIRECTIVES:
                findings.append(Finding(
                    header='Content-Security-Policy',
                    severity=Severity.HIGH,
                    title=f"Possible missing semicolon: '{value}' in '{directive}'",
                    description=f"'{value}' is a known CSP directive but appears as a value of '{directive}'. "
                                "A missing ';' causes it to be silently ignored.",
                    recommendation=f"Separate '{directive}' and '{value}' with a semicolon.",
                ))


def _check_invalid_keyword(csp: _CSPParser, findings: list[Finding]):
    for directive, values in csp.directives.items():
        for value in values:
            if value in _UNQUOTED_KEYWORDS:
                findings.append(Finding(
                    header='Content-Security-Policy',
                    severity=Severity.HIGH,
                    title=f"Invalid keyword '{value}' in '{directive}' (missing single quotes)",
                    description=f"'{value}' without single quotes is treated as a hostname, not a CSP keyword. "
                                "The intended restriction is silently not applied.",
                    recommendation=f"Replace '{value}' with \"'{value}'\" (surround with single quotes).",
                ))
            elif (value.startswith('nonce-') or
                  value.startswith('sha256-') or
                  value.startswith('sha384-') or
                  value.startswith('sha512-')):
                findings.append(Finding(
                    header='Content-Security-Policy',
                    severity=Severity.HIGH,
                    title=f"Unquoted nonce/hash '{value}' in '{directive}'",
                    description="Nonces and hashes must be surrounded by single quotes to be recognized as CSP keywords. "
                                "Without quotes the browser treats the value as a hostname.",
                    recommendation=f"Replace '{value}' with \"'{value}'\" (surround with single quotes).",
                ))


def _check_missing_script_src(csp: _CSPParser, findings: list[Finding]):
    if 'script-src' not in csp.directives and 'default-src' not in csp.directives:
        findings.append(Finding(
            header='Content-Security-Policy',
            severity=Severity.HIGH,
            title="Missing script-src and default-src",
            description="Without script-src or default-src the CSP places no restrictions on script loading.",
            recommendation="Add at minimum: script-src 'none' or default-src 'none'.",
        ))


def _extract_hostname(source: str) -> tuple[str, bool]:
    """Return (hostname, is_wildcard)."""
    host = re.sub(r'^https?://', '', source)
    is_wildcard = host.startswith('*.')
    host = host.split('/')[0].split(':')[0]
    if host.startswith('*.'):
        host = host[2:]
    return host, is_wildcard


def _check_script_src(csp: _CSPParser, findings: list[Finding]):
    sources = csp.effective('script-src')
    if sources is None:
        return

    has_nonce = any(s.startswith("'nonce-") for s in sources)
    has_hash = any(re.match(r"'sha(256|384|512)-", s) for s in sources)
    has_strict_dynamic = "'strict-dynamic'" in sources

    if has_strict_dynamic and not has_nonce and not has_hash:
        findings.append(Finding(
            header='Content-Security-Policy',
            severity=Severity.MEDIUM,
            title="script-src: 'strict-dynamic' without nonce or hash",
            description="'strict-dynamic' takes effect only when paired with a nonce or hash. "
                        "Without them it blocks all scripts.",
            recommendation="Add a per-request nonce (e.g. 'nonce-<random>') or a hash to script-src.",
        ))

    if "'unsafe-inline'" in sources:
        if not (has_strict_dynamic and (has_nonce or has_hash)):
            findings.append(Finding(
                header='Content-Security-Policy',
                severity=Severity.HIGH,
                title="script-src: 'unsafe-inline'",
                description="Allows execution of arbitrary inline scripts, defeating XSS protection.",
                recommendation="Remove 'unsafe-inline'. Use nonces or hashes with 'strict-dynamic'.",
            ))

    if "'unsafe-eval'" in sources:
        findings.append(Finding(
            header='Content-Security-Policy',
            severity=Severity.HIGH,
            title="script-src: 'unsafe-eval'",
            description="Allows code execution via eval() and similar APIs (Function(), setTimeout(string), ...).",
            recommendation="Remove 'unsafe-eval' and refactor code to avoid dynamic code evaluation.",
        ))

    if "'unsafe-hashes'" in sources:
        findings.append(Finding(
            header='Content-Security-Policy',
            severity=Severity.MEDIUM,
            title="script-src: 'unsafe-hashes'",
            description="Enables hashing of event handler attributes, still weaker than avoiding inline handlers.",
            recommendation="Remove event handler attributes and use addEventListener instead.",
        ))

    for source in sources:
        if source in ('*', 'http:', 'https:'):
            findings.append(Finding(
                header='Content-Security-Policy',
                severity=Severity.CRITICAL if source in ('*', 'http:') else Severity.HIGH,
                title=f"script-src: overly broad source '{source}'",
                description=f"'{source}' allows loading scripts from any origin.",
                recommendation="Replace with explicit trusted origins.",
            ))
        elif source == 'data:':
            findings.append(Finding(
                header='Content-Security-Policy',
                severity=Severity.HIGH,
                title="script-src: 'data:' URI scheme",
                description="data: URIs in script-src can be abused to execute arbitrary scripts.",
                recommendation="Remove 'data:' from script-src.",
            ))
        elif source == 'blob:':
            findings.append(Finding(
                header='Content-Security-Policy',
                severity=Severity.MEDIUM,
                title="script-src: 'blob:' URI scheme",
                description="blob: URIs may allow bypassing CSP if an attacker can control blob creation.",
                recommendation="Remove 'blob:' from script-src if not strictly necessary.",
            ))
        elif source not in ("'self'", "'none'", "'strict-dynamic'", "'report-sample'"):
            if source in _BROAD_WILDCARDS:
                findings.append(Finding(
                    header='Content-Security-Policy',
                    severity=Severity.HIGH,
                    title=f"script-src: broad wildcard '{source}'",
                    description=f"'{source}' covers an entire TLD — any domain under it can serve scripts.",
                    recommendation=f"Replace '{source}' with specific trusted domains.",
                ))
                continue

            hostname, is_wildcard = _extract_hostname(source)
            if is_wildcard and hostname in _BYPASS_BASE_DOMAINS:
                findings.append(Finding(
                    header='Content-Security-Policy',
                    severity=Severity.HIGH,
                    title=f"script-src: known bypass via wildcard '{source}'",
                    description=f"'{source}' covers subdomains (e.g. ajax.{hostname}) that host JSONP or Angular, "
                                 "enabling CSP bypass.",
                    recommendation="Use nonce/hash + 'strict-dynamic' instead of allowlisting CDNs.",
                ))
            elif not is_wildcard and hostname in _BYPASS_EXACT_HOSTS:
                findings.append(Finding(
                    header='Content-Security-Policy',
                    severity=Severity.HIGH,
                    title=f"script-src: known bypass host '{hostname}'",
                    description=f"'{hostname}' hosts JSONP endpoints or Angular that can be used to bypass CSP.",
                    recommendation="Remove this host or switch to nonce-based CSP with 'strict-dynamic'.",
                ))

    # Nonce length check
    for source in sources:
        if source.startswith("'nonce-"):
            nonce = source[7:].rstrip("'")
            if len(nonce) < 20:
                findings.append(Finding(
                    header='Content-Security-Policy',
                    severity=Severity.MEDIUM,
                    title="script-src: nonce too short",
                    description=f"Nonce '{nonce}' is too short. Minimum 128 bits (≥22 base64 chars) recommended.",
                    recommendation="Generate cryptographically random nonces of at least 128 bits per request.",
                ))


def _check_style_src(csp: _CSPParser, findings: list[Finding]):
    sources = csp.effective('style-src')
    if sources is None:
        return
    if "'unsafe-inline'" in sources:
        findings.append(Finding(
            header='Content-Security-Policy',
            severity=Severity.MEDIUM,
            title="style-src: 'unsafe-inline'",
            description="Allows arbitrary inline styles. Can enable CSS injection leading to data exfiltration.",
            recommendation="Use nonces or hashes for inline styles.",
        ))


def _check_object_src(csp: _CSPParser, findings: list[Finding]):
    sources = csp.effective('object-src')
    if sources is None:
        findings.append(Finding(
            header='Content-Security-Policy',
            severity=Severity.HIGH,
            title="Missing object-src directive",
            description="Without object-src or default-src, plugins (Flash, Java applets) can load from any source.",
            recommendation="Add 'object-src 'none'' to block all plugins.",
        ))
    elif "'none'" not in sources:
        findings.append(Finding(
            header='Content-Security-Policy',
            severity=Severity.HIGH,
            title="Permissive object-src",
            description="Any object-src value other than 'none' allows plugin loading. "
                        "Same-origin and CDN-hosted plugins can be exploited for XSS.",
            recommendation="Set 'object-src 'none''.",
        ))


def _check_base_uri(csp: _CSPParser, findings: list[Finding]):
    if 'base-uri' not in csp.directives:
        findings.append(Finding(
            header='Content-Security-Policy',
            severity=Severity.MEDIUM,
            title="Missing base-uri directive",
            description="Without base-uri, attackers can inject a <base href> tag to redirect relative URLs "
                        "to an attacker-controlled origin.",
            recommendation="Add 'base-uri 'self'' or 'base-uri 'none''.",
        ))
    else:
        sources = csp.directives['base-uri']
        if any(s in sources for s in ('*', 'http:', 'https:')):
            findings.append(Finding(
                header='Content-Security-Policy',
                severity=Severity.HIGH,
                title="Permissive base-uri",
                description="base-uri allows any URL as the base, enabling <base href> injection to redirect "
                            "relative URLs to an attacker-controlled origin.",
                recommendation="Set 'base-uri 'self'' or 'base-uri 'none''.",
            ))


def _check_frame_ancestors(csp: _CSPParser, findings: list[Finding]):
    if 'frame-ancestors' not in csp.directives:
        findings.append(Finding(
            header='Content-Security-Policy',
            severity=Severity.INFO,
            title="Missing frame-ancestors directive",
            description="frame-ancestors is the modern replacement for X-Frame-Options for clickjacking protection.",
            recommendation="Add 'frame-ancestors 'none'' or 'frame-ancestors 'self''.",
        ))
    else:
        sources = csp.directives['frame-ancestors']
        if '*' in sources or 'http:' in sources:
            findings.append(Finding(
                header='Content-Security-Policy',
                severity=Severity.HIGH,
                title="Permissive frame-ancestors",
                description="Allows embedding from any origin, enabling clickjacking attacks.",
                recommendation="Restrict frame-ancestors to specific trusted origins or use 'none'.",
            ))


def _check_default_src(csp: _CSPParser, findings: list[Finding]):
    if 'default-src' not in csp.directives:
        findings.append(Finding(
            header='Content-Security-Policy',
            severity=Severity.MEDIUM,
            title="Missing default-src directive",
            description="Without default-src, resource types not covered by specific directives are unrestricted.",
            recommendation="Add 'default-src 'none'' as a baseline, then explicitly allow needed sources.",
        ))
    else:
        sources = csp.directives['default-src']
        if '*' in sources or 'http:' in sources:
            findings.append(Finding(
                header='Content-Security-Policy',
                severity=Severity.HIGH,
                title="Permissive default-src",
                description="default-src is too broad; it applies to all resource types not covered by specific directives.",
                recommendation="Use 'default-src 'none'' and add per-type directives.",
            ))


def _check_misc(csp: _CSPParser, findings: list[Finding]):
    deprecated = {
        'reflected-xss': "Deprecated — use CSP instead.",
        'referrer': "Deprecated — use Referrer-Policy header.",
        'block-all-mixed-content': "Deprecated — use upgrade-insecure-requests.",
        'prefetch-src': "Deprecated — removed from the CSP spec; browsers may ignore it.",
    }
    for directive, msg in deprecated.items():
        if directive in csp.directives:
            findings.append(Finding(
                header='Content-Security-Policy',
                severity=Severity.INFO,
                title=f"Deprecated CSP directive: {directive}",
                description=msg,
                recommendation=f"Remove '{directive}' from CSP.",
            ))

    if 'form-action' not in csp.directives:
        findings.append(Finding(
            header='Content-Security-Policy',
            severity=Severity.MEDIUM,
            title="Missing form-action directive",
            description="Without form-action, forms can submit data to any URL including attacker-controlled origins, "
                        "bypassing other CSP restrictions.",
            recommendation="Add 'form-action 'self'' to restrict form submissions to the same origin.",
        ))

    if 'upgrade-insecure-requests' not in csp.directives:
        findings.append(Finding(
            header='Content-Security-Policy',
            severity=Severity.INFO,
            title="Missing upgrade-insecure-requests",
            description="upgrade-insecure-requests automatically upgrades HTTP sub-resources to HTTPS.",
            recommendation="Consider adding 'upgrade-insecure-requests' to CSP.",
        ))
