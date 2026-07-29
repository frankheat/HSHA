"""Shared helpers for the HSHA test suite."""
from pathlib import Path

from lib.config import CONTEXT_PUBLIC, AppConfig, load_config
from lib.models import Finding, HeaderResult, Severity
from lib.parser import parse_http_response
from lib.rules import analyze_headers

ROOT = Path(__file__).parent.parent


def build_response(*header_lines: str, status: str = "HTTP/1.1 200 OK") -> str:
    """Assemble a raw HTTP response (CRLF terminated, empty body)."""
    return "\r\n".join([status, *header_lines]) + "\r\n\r\n"


def analyze(*header_lines: str, config: AppConfig | None = None) -> dict[str, HeaderResult]:
    """Run the full pipeline on the given header lines, keyed by lowercase name."""
    raw = parse_http_response(build_response(*header_lines))
    results = analyze_headers(raw, config if config is not None else AppConfig())
    return {r.name: r for r in results}


def result_for(header: str, value: str, config: AppConfig | None = None) -> HeaderResult:
    return analyze(f"{header}: {value}", config=config)[header.lower()]


def findings_for(header: str, value: str, config: AppConfig | None = None) -> list[Finding]:
    return result_for(header, value, config).findings


def severity_for(header: str, value: str, config: AppConfig | None = None) -> Severity:
    return result_for(header, value, config).worst_severity


def has(findings: list[Finding], substring: str) -> bool:
    """True if any finding title contains `substring`."""
    return any(substring in f.title for f in findings)


def public() -> AppConfig:
    """Config assuming the response carries nothing specific to a signed-in user."""
    return AppConfig(context=CONTEXT_PUBLIC)


def profile(name: str) -> AppConfig:
    return load_config(str(ROOT / 'profiles' / f'{name}.yaml'))


# A response that satisfies every required header of the basic profile.
CLEAN_HEADERS = [
    "Content-Security-Policy: default-src 'none'; script-src 'self'; object-src 'none'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
    "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "X-Frame-Options: DENY",
    "X-Content-Type-Options: nosniff",
    "Cross-Origin-Opener-Policy: same-origin",
    "Referrer-Policy: no-referrer",
    "Cache-Control: no-store",
]
