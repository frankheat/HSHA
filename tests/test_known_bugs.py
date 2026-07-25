"""Executable specifications for confirmed defects.

Every test here asserts the behaviour HSHA *should* have and is marked
``xfail(strict=True)``. They report as XFAIL today; the moment a bug is fixed
the test turns XPASS, which strict mode reports as a failure — that is the
signal to delete the marker (and this test's entry) rather than leave a
silently-passing exception behind.
"""
import json

import pytest

from lib.config import AppConfig, HeaderOverride, load_config
from lib.models import Severity

from conftest import CLEAN_HEADERS, analyze, build_response, findings_for, severity_for
from test_cli import run

bug = pytest.mark.xfail(strict=True)


# ---------------------------------------------------------------------------
# 1. lib/rules.py:258 — severity_if_present is ignored whenever the header has
# a built-in checker, because checkers always return at least one finding
# (often a harmless OK one) and the fallback only fires on an empty list.
# ---------------------------------------------------------------------------

@bug
def test_severity_if_present_applies_to_headers_that_have_a_checker():
    config = AppConfig(overrides={'cache-control': HeaderOverride(severity_if_present='critical')})
    assert severity_for("Cache-Control", "no-store", config) == Severity.CRITICAL


# ---------------------------------------------------------------------------
# 2. lib/rules.py:145 — `sev = missing_sev if required else Severity.INFO`
# discards severity_if_missing unless `required: true` is also set. The custom
# header branch (lib/rules.py:185) honours it, so the two disagree.
# ---------------------------------------------------------------------------

@bug
def test_severity_if_missing_applies_without_an_explicit_required_flag():
    config = AppConfig(overrides={'clear-site-data': HeaderOverride(severity_if_missing='critical')})
    assert analyze("X-Nothing: x", config=config)['clear-site-data'].worst_severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# 3. lib/config.py:47 — anything not in _KNOWN_KEYS silently lands in `extra`,
# and checkers read it with .get(default). A typo therefore disables the
# setting with no diagnostic at all.
# ---------------------------------------------------------------------------

@bug
def test_unknown_config_key_is_rejected(tmp_path):
    path = tmp_path / 'typo.yaml'
    path.write_text("headers:\n  Strict-Transport-Security:\n    min_maxage: 99999999\n")
    with pytest.raises(ValueError, match="min_maxage"):
        load_config(str(path))


@bug
def test_typo_in_min_max_age_does_not_silently_use_the_default_threshold():
    config = AppConfig(overrides={
        'strict-transport-security': HeaderOverride(extra={'min_maxage': 99999999}),
    })
    findings = findings_for("Strict-Transport-Security",
                            "max-age=31536000; includeSubDomains", config)
    assert any("max-age too short" in f.title for f in findings)


# ---------------------------------------------------------------------------
# 4. lib/reporter.py:64 uses `> NOTE` (INFO counts as a failure) while
# check_headers.py:105 uses `> INFO` for the exit code. The two disagree about
# what an "issue" is, so `--format list` can name headers while exiting 0.
# ---------------------------------------------------------------------------

@bug
def test_list_output_and_exit_code_agree(tmp_path):
    path = tmp_path / 'response.txt'
    path.write_text(build_response(*CLEAN_HEADERS))
    result = run(str(path), '--format', 'list')
    listed = 'No issues found' not in result.stdout
    assert listed == (result.returncode == 1), result.stdout


@bug
def test_absent_optional_header_is_not_marked_fail(tmp_path):
    path = tmp_path / 'response.txt'
    path.write_text(build_response(*CLEAN_HEADERS))
    data = json.loads(run(str(path), '--format', 'json').stdout)
    cache = next(r for r in data if r['header'] == 'Cache-Control')
    assert cache['severity'] == 'INFO'
    assert 'Cache-Control' not in run(str(path), '--format', 'list').stdout


# ---------------------------------------------------------------------------
# 5. lib/rules.py:90 — the 'strictest' strategy rewrites conflicting
# X-Frame-Options values to DENY, and the checker then reports "DENY (optimal)".
# A real server misconfiguration is surfaced as a pass.
# ---------------------------------------------------------------------------

@bug
def test_conflicting_x_frame_options_is_not_reported_as_optimal():
    result = analyze("X-Frame-Options: deny", "X-Frame-Options: sameorigin")['x-frame-options']
    assert result.worst_severity > Severity.NOTE, [f.title for f in result.findings]


# ---------------------------------------------------------------------------
# 6. lib/rules.py:694 — every ACAO value other than '*' is reported OK, but
# `null` is a well-known bypass (sandboxed iframes, redirects, file:// origins)
# and is dangerous alongside Access-Control-Allow-Credentials: true.
# ---------------------------------------------------------------------------

@bug
def test_access_control_allow_origin_null_is_flagged():
    assert severity_for("Access-Control-Allow-Origin", "null") >= Severity.MEDIUM


# ---------------------------------------------------------------------------
# 7. lib/config.py:82 lowercases config keys and lib/rules.py:179 reuses that
# key as the display name, so a custom header loses its casing in the output.
# ---------------------------------------------------------------------------

@bug
def test_custom_header_keeps_its_configured_casing_in_the_output(tmp_path):
    path = tmp_path / 'custom.yaml'
    path.write_text("headers:\n  X-Request-Id:\n    required: true\n")
    config = load_config(str(path))
    result = analyze("X-Nothing: x", config=config)['x-request-id']
    assert result.canonical_name == 'X-Request-Id'
