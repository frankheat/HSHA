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
_CSP = 'content-security-policy'
_XFO = 'x-frame-options'


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

    def finding(severity: Severity, title: str, description: str, recommendation: str = "",
                verify: str = ""):
        return [(_ACAC, Finding(
            header='Access-Control-Allow-Credentials',
            severity=severity,
            title=title,
            description=description,
            recommendation=recommendation,
            verify=verify,
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

    # Graded for the case the response cannot rule out. An echoed Origin is
    # byte-for-byte identical to an allowlisted one, and if that is what this is,
    # the outcome is the null case reached more easily — no sandboxed iframe, just
    # a page on the attacker's own domain.
    return finding(
        Severity.CRITICAL,
        f"Authenticated cross-origin access is granted to {origin}",
        f"This response lets {origin} read data using the user's cookies. A response that "
        "echoes back the request's Origin header looks exactly like one that allowlists that "
        "origin, and a single saved response cannot tell them apart — so this is graded as "
        "the reflected case until a request settles it.",
        verify="Replay the request with Origin: https://an-origin-you-made-up.example. If it "
               "comes back in Access-Control-Allow-Origin, the server reflects whatever it is "
               "sent and any site reads this endpoint as the logged-in user — this stands. If "
               "it does not come back, the allowlist is real, this is correct authenticated "
               "CORS, and there is nothing here.",
    )


def _frame_ancestors_replaces_x_frame_options(
    results: dict[str, HeaderResult],
) -> list[tuple[str, Finding]]:
    """
    Say so when the CSP has taken the framing decision away from X-Frame-Options
    and given it away.

    HTML's *check a navigation response's adherence to `X-Frame-Options`* returns
    early — the header unread — as soon as an enforced policy carries a
    frame-ancestors directive, whatever that directive says. So a correct
    X-Frame-Options next to a permissive frame-ancestors protects nothing but the
    browsers too old to implement CSP, and the header's own verdict, on its own,
    reads as reassurance the response has not earned.

    The exposure itself is already graded on the CSP; this only stops the other row
    from showing a clean result. Nothing fires when frame-ancestors is restrictive:
    that is the recommended pairing, one header covering what the other cannot.
    """
    xfo, csp = results.get(_XFO), results.get(_CSP)
    if xfo is None or csp is None or not xfo.is_present:
        return []
    if not any(f.title == "Permissive frame-ancestors" for f in csp.findings):
        return []
    return [(_XFO, Finding(
        header='X-Frame-Options',
        severity=Severity.INFO,
        title="X-Frame-Options: replaced by the CSP, which allows framing",
        description="A browser that implements CSP frame-ancestors does not read this header "
                    "at all — the directive's presence replaces it, whatever its value. Here it "
                    "is permissive, so the page can be framed by anyone, and this header "
                    "protects only browsers old enough to ignore CSP entirely. The exposure is "
                    "graded on the Content-Security-Policy row; what is said here is that this "
                    "one does not offset it.",
        recommendation="Restrict frame-ancestors, and keep this header for the browsers that "
                       "do not implement it.",
    ))]


_CORRELATIONS: list[Callable[[dict[str, HeaderResult]], list[tuple[str, Finding]]]] = [
    _cors_credentials,
    _frame_ancestors_replaces_x_frame_options,
]


def apply_correlations(results: list[HeaderResult]) -> None:
    """Append the findings of every correlation rule, in place."""
    by_key = {r.name: r for r in results}
    for rule in _CORRELATIONS:
        for key, finding in rule(by_key):
            target = by_key.get(key)
            if target is not None:
                target.findings.append(finding)
