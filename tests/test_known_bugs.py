"""Executable specifications for confirmed defects.

Every test here asserts the behaviour HSHA *should* have and is marked
``xfail(strict=True)``. They report as XFAIL today; the moment a bug is fixed
the test turns XPASS, which strict mode reports as a failure — that is the
signal to delete the marker (and this test's entry) rather than leave a
silently-passing exception behind.
"""
import pytest

from lib.models import Severity

from conftest import analyze

bug = pytest.mark.xfail(strict=True)


# ---------------------------------------------------------------------------
# 1. lib/rules.py:90 — the 'strictest' strategy rewrites conflicting
# X-Frame-Options values to DENY, and the checker then reports "DENY (optimal)".
# A real server misconfiguration is surfaced as a pass.
# ---------------------------------------------------------------------------

@bug
def test_conflicting_x_frame_options_is_not_reported_as_optimal():
    result = analyze("X-Frame-Options: deny", "X-Frame-Options: sameorigin")['x-frame-options']
    assert result.worst_severity > Severity.NOTE, [f.title for f in result.findings]
