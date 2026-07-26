"""
Checks that need more than one header.

The checkers in lib/rules.py each see a single header value, which is enough for
almost every rule. A few verdicts cannot be reached that way at all — CORS
credentials being the clearest case, since `Access-Control-Allow-Credentials:
true` says "send the cookies" without saying to whom. Those run here, after every
header has been evaluated, with the whole result set in view.

A correlation only ever appends findings. Where a single-header checker cannot
reach a verdict it stays neutral instead (see _check_acac in lib/rules.py), so
nothing here has to suppress or rewrite what another check already reported.
"""
from typing import Callable

from .models import Finding, HeaderResult, Severity

_ACAO = 'access-control-allow-origin'
_ACAC = 'access-control-allow-credentials'


def _cors_credentials(results: dict[str, HeaderResult]) -> list[tuple[str, Finding]]:
    """
    Judge Access-Control-Allow-Credentials against the origin it applies to.

    Emits exactly one finding whenever credentials are enabled, so the header
    carries a single verdict rather than one per contributing check.
    """
    acac = results.get(_ACAC)
    if acac is None or not acac.is_present:
        return []
    if (acac.value or '').strip().lower() != 'true':
        return []

    def finding(severity: Severity, title: str, description: str, recommendation: str = ""):
        return [(_ACAC, Finding(
            header='Access-Control-Allow-Credentials',
            severity=severity,
            title=title,
            description=description,
            recommendation=recommendation,
        ))]

    if _ACAO not in results:
        return finding(
            Severity.INFO,
            "Credentials are enabled but Access-Control-Allow-Origin was not evaluated",
            "This profile excludes Access-Control-Allow-Origin, so there is no way to tell "
            "which origins may read authenticated responses.",
            "Enable Access-Control-Allow-Origin in the profile to have this checked.",
        )

    acao = results[_ACAO]
    if not acao.is_present:
        return finding(
            Severity.INFO,
            "Access-Control-Allow-Credentials has no effect without Access-Control-Allow-Origin",
            "No origin is authorised to read the response, so enabling credentials changes "
            "nothing. The header is most likely left over from an earlier configuration.",
            "Remove Access-Control-Allow-Credentials, or set the origin it is meant for.",
        )

    origin = (acao.value or '').strip()

    if origin == '*':
        # Not a security finding: browsers reject the credentialed request, so
        # nothing is exposed that the wildcard on ACAO does not already expose,
        # and that is graded there. What is left is a functional contradiction.
        return finding(
            Severity.INFO,
            "Access-Control-Allow-Origin: * with credentials enabled — the request fails",
            "Browsers refuse the wildcard together with credentials, so every credentialed "
            "cross-origin request to this endpoint is rejected. Nothing is exposed by the "
            "combination itself: whoever wanted authenticated cross-origin access does not "
            "have it. (The wildcard's own effect on non-credentialed requests is reported "
            "on Access-Control-Allow-Origin.)",
            "Allowlist the specific origins that need authenticated access, or drop "
            "Access-Control-Allow-Credentials. Do not echo back the request's Origin header "
            "to make it work — that would let any site read logged-in users' data.",
        )

    if ',' in origin:
        return finding(
            Severity.INFO,
            "Access-Control-Allow-Credentials has no effect: the allowed origin is not usable",
            "Access-Control-Allow-Origin lists more than one origin, which never matches the "
            "requesting origin, so no site can read the response with or without credentials.",
            "Fix Access-Control-Allow-Origin first; this header cannot take effect until then.",
        )

    if origin.lower() == 'null':
        return finding(
            Severity.CRITICAL,
            "Access-Control-Allow-Origin: null with credentials enabled",
            "Any page can obtain the null origin through a sandboxed iframe, a data: URL or a "
            "cross-origin redirect, and null is a concrete origin, so browsers do send cookies "
            "with it. An attacker's page can therefore read this endpoint's responses as the "
            "logged-in user.",
            "Never allowlist 'null'. Echo only origins from a fixed list.",
        )

    return finding(
        Severity.INFO,
        f"Authenticated cross-origin access is granted to {origin}",
        f"This response lets {origin} read data using the user's cookies. Check that the "
        "origin comes from a fixed allowlist and is not copied from the request's Origin "
        "header: if it is reflected, any site can read the data of logged-in users.",
        "To verify, replay the request with Origin: https://an-origin-you-made-up.example "
        "and see whether it comes back in the response.",
    )


_CORRELATIONS: list[Callable[[dict[str, HeaderResult]], list[tuple[str, Finding]]]] = [
    _cors_credentials,
]


def apply_correlations(results: list[HeaderResult]) -> None:
    """Append the findings of every correlation rule, in place."""
    by_key = {r.name: r for r in results}
    for rule in _CORRELATIONS:
        for key, finding in rule(by_key):
            target = by_key.get(key)
            if target is not None:
                target.findings.append(finding)
