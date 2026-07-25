"""Executable specifications for confirmed defects.

Every test here asserts the behaviour HSHA *should* have and is marked
``xfail(strict=True)``. They report as XFAIL today; the moment a bug is fixed
the test turns XPASS, which strict mode reports as a failure — that is the
signal to delete the marker (and this test's entry) rather than leave a
silently-passing exception behind.
"""
import pytest

from lib.config import load_config
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


# ---------------------------------------------------------------------------
# 2. lib/config.py:82 lowercases config keys and lib/rules.py:179 reuses that
# key as the display name, so a custom header loses its casing in the output.
# ---------------------------------------------------------------------------

@bug
def test_custom_header_keeps_its_configured_casing_in_the_output(tmp_path):
    path = tmp_path / 'custom.yaml'
    path.write_text("headers:\n  X-Request-Id:\n    required: true\n")
    config = load_config(str(path))
    result = analyze("X-Nothing: x", config=config)['x-request-id']
    assert result.canonical_name == 'X-Request-Id'
