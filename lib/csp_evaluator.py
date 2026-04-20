"""
CSP evaluation engine.

Primary path: delegates to @google/csp-evaluator via Node.js (csp_wrapper.js).
Fallback: built-in Python evaluator implementing the same key checks.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path
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

_WRAPPER = Path(__file__).parent.parent / 'csp_wrapper.js'

_csp_engine_used: str = ""


def get_csp_engine() -> str:
    """Returns which CSP engine was used in the last evaluate_csp() call."""
    return _csp_engine_used


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate_csp(csp_value: str, use_nodejs: bool = True) -> list[Finding]:
    global _csp_engine_used
    if use_nodejs:
        result = _try_nodejs(csp_value)
        if result is not None:
            _csp_engine_used = "Google CSP Evaluator (Node.js)"
            return result
    _csp_engine_used = "built-in Python evaluator"
    return _python_evaluate(csp_value)


# ---------------------------------------------------------------------------
# Node.js path
# ---------------------------------------------------------------------------

def _try_nodejs(csp_value: str) -> Optional[list[Finding]]:
    if not shutil.which('node') or not _WRAPPER.exists():
        return None
    try:
        proc = subprocess.run(
            ['node', str(_WRAPPER), csp_value],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode == 0:
            return _parse_nodejs_output(json.loads(proc.stdout))
    except Exception:
        pass
    return None


def _parse_nodejs_output(data: list) -> list[Finding]:
    # Google CSP Evaluator severity constants: 0=ok,1=info,2=low,3=medium,10=high,100=critical
    sev_map = {
        0: Severity.OK, 1: Severity.INFO, 2: Severity.LOW,
        3: Severity.MEDIUM, 10: Severity.HIGH, 100: Severity.CRITICAL,
    }
    findings = []
    for item in data:
        sev = sev_map.get(item.get('severity', 1), Severity.MEDIUM)
        directive = item.get('directive', '')
        type_name = item.get('type', '')
        description = item.get('description', '')
        # Build title from description (human-readable); add directive and type as context
        title_parts = []
        if directive:
            title_parts.append(f"({directive})")
        if type_name:
            title_parts.append(type_name)
        title = " ".join(title_parts) if title_parts else "CSP Issue"
        findings.append(Finding(
            header='Content-Security-Policy',
            severity=sev,
            title=title,
            description=description,
        ))
    return findings


# ---------------------------------------------------------------------------
# Python fallback evaluator
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

    _check_script_src(csp, findings)
    _check_style_src(csp, findings)
    _check_object_src(csp, findings)
    _check_base_uri(csp, findings)
    _check_frame_ancestors(csp, findings)
    _check_default_src(csp, findings)
    _check_misc(csp, findings)

    return findings


def _extract_hostname(source: str) -> tuple[str, bool]:
    """Return (hostname, is_wildcard)."""
    is_wildcard = source.startswith('*.')
    host = re.sub(r'^https?://', '', source)
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
        if 'default-src' not in csp.directives:
            findings.append(Finding(
                header='Content-Security-Policy',
                severity=Severity.HIGH,
                title="Missing object-src directive",
                description="Without object-src, plugins (Flash, Java applets) can load from any source.",
                recommendation="Add 'object-src 'none'' to block all plugins.",
            ))
    elif "'none'" not in sources:
        if any(s in sources for s in ('*', 'http:', 'https:')):
            findings.append(Finding(
                header='Content-Security-Policy',
                severity=Severity.HIGH,
                title="Permissive object-src",
                description="object-src is too broad. Plugins can be exploited for XSS.",
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
        if "'unsafe-inline'" in sources or '*' in sources:
            findings.append(Finding(
                header='Content-Security-Policy',
                severity=Severity.HIGH,
                title="Permissive base-uri",
                description="base-uri should be restricted to 'self' or 'none'.",
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
