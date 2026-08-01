"""End-to-end tests for check_headers.py: exit status and output formats.

The exit status says whether a report could be produced, not what is in it: any
response that analyses successfully exits 0, however bad its headers are. Only
being unable to produce a report at all — an unreadable response, an invalid
config — exits 2.
"""
import json
import subprocess
import sys

import pytest

from conftest import CLEAN_HEADERS, ROOT, build_response

CLEAN = build_response(*CLEAN_HEADERS)
NO_CSP = build_response(*[h for h in CLEAN_HEADERS if not h.startswith("Content-Security-Policy")])


def run(*args, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, 'check_headers.py', *args],
        cwd=ROOT, input=stdin, capture_output=True, text=True,
    )


@pytest.fixture
def response_file(tmp_path):
    def write(content: str, name: str = 'response.txt'):
        path = tmp_path / name
        path.write_text(content)
        return str(path)
    return write


# ---------------------------------------------------------------------------
# Exit status
# ---------------------------------------------------------------------------

def test_clean_response_exits_zero(response_file):
    assert run(response_file(CLEAN)).returncode == 0


def test_a_response_with_findings_still_exits_zero(response_file):
    """A HIGH finding is a result, not a failure of the run: it belongs in the
    report the reader works from, and reporting it is the tool succeeding."""
    result = run(response_file(NO_CSP))
    assert 'Missing Content-Security-Policy' in result.stdout
    assert result.returncode == 0


def test_severity_never_reaches_the_exit_status(response_file):
    """Nothing about a response can make the process exit non-zero."""
    for content in (CLEAN, NO_CSP, build_response("Cross-Origin-Opener-Policy: unsafe-none")):
        assert run(response_file(content)).returncode == 0


def test_missing_file_exits_two():
    result = run('does-not-exist.txt')
    assert result.returncode == 2
    assert 'cannot read' in result.stdout
    assert 'No such file' in result.stdout


def test_missing_config_file_exits_two(response_file):
    result = run(response_file(CLEAN), '--config', 'nope.yaml')
    assert result.returncode == 2
    assert 'cannot read config file' in result.stdout


def test_directory_as_input_exits_two(response_file, tmp_path):
    """Regression: this used to raise IsADirectoryError and exit 1, which the
    tool's own contract reads as 'security findings were reported'."""
    directory = tmp_path / 'adir'
    directory.mkdir()
    result = run(str(directory))
    assert result.returncode == 2
    assert 'Traceback' not in result.stderr


def test_unreadable_file_exits_two(response_file, tmp_path):
    path = tmp_path / 'locked.txt'
    path.write_text(CLEAN)
    path.chmod(0o000)
    try:
        result = run(str(path))
    finally:
        path.chmod(0o644)
    assert result.returncode == 2
    assert 'Traceback' not in result.stderr


def test_directory_as_config_exits_two(response_file, tmp_path):
    directory = tmp_path / 'cfgdir'
    directory.mkdir()
    result = run(response_file(CLEAN), '--config', str(directory))
    assert result.returncode == 2
    assert 'Traceback' not in result.stderr


def test_undecodable_bytes_do_not_crash(response_file, tmp_path):
    path = tmp_path / 'binary.txt'
    path.write_bytes(b"HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\xff\xfe\r\n\r\n")
    assert run(str(path)).returncode in (0, 1)


def test_invalid_yaml_config_exits_two(response_file, tmp_path):
    bad = tmp_path / 'bad.yaml'
    bad.write_text("headers:\n  - [unclosed\n")
    result = run(response_file(CLEAN), '--config', str(bad))
    assert result.returncode == 2
    assert 'Error' in result.stdout


def test_non_mapping_config_exits_two(response_file, tmp_path):
    bad = tmp_path / 'bad.yaml'
    bad.write_text("just a string\n")
    result = run(response_file(CLEAN), '--config', str(bad))
    assert result.returncode == 2


def test_invalid_severity_in_config_exits_two(response_file, tmp_path):
    bad = tmp_path / 'bad.yaml'
    bad.write_text("headers:\n  Content-Security-Policy:\n    severity_if_missing: catastrophic\n")
    result = run(response_file(NO_CSP), '--config', str(bad))
    assert result.returncode == 2
    assert 'Invalid severity' in result.stdout


def test_invalid_regex_in_config_exits_two(response_file, tmp_path):
    bad = tmp_path / 'bad.yaml'
    bad.write_text("headers:\n  ETag:\n    expected_pattern: '['\n")
    result = run(response_file(CLEAN), '--config', str(bad))
    assert result.returncode == 2


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

def test_reads_from_stdin():
    result = run('-', stdin=CLEAN)
    assert result.returncode == 0


def test_stdin_and_file_agree(response_file):
    from_file = run(response_file(CLEAN), '--format', 'json').stdout
    from_stdin = run('-', '--format', 'json', stdin=CLEAN).stdout
    assert from_file == from_stdin


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------

def test_json_output_is_parseable_and_shaped(response_file):
    result = run(response_file(NO_CSP), '--format', 'json')
    data = json.loads(result.stdout)
    assert isinstance(data, list) and data
    csp = next(r for r in data if r['header'] == 'Content-Security-Policy')
    assert csp['present'] is False
    assert csp['value'] is None
    assert csp['severity'] == 'HIGH'
    assert csp['findings'][0]['title'].startswith('Missing')
    assert set(csp['findings'][0]) == {'severity', 'title', 'description',
                                       'recommendation', 'verify'}


def test_json_severities_are_valid_names(response_file):
    data = json.loads(run(response_file(CLEAN), '--format', 'json').stdout)
    valid = {'OK', 'NOTE', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
    assert {r['severity'] for r in data} <= valid


def test_text_output_shows_levels(response_file):
    out = run(response_file(NO_CSP)).stdout
    assert 'HIGH' in out and 'Overall' in out


def test_a_clean_response_says_so(response_file):
    """With every optional header also satisfied there is nothing to report."""
    full = build_response(*CLEAN_HEADERS, *[
        "Cross-Origin-Embedder-Policy: require-corp",
        "Cross-Origin-Resource-Policy: same-origin",
        "X-Permitted-Cross-Domain-Policies: none",
        'Clear-Site-Data: "cache", "cookies", "storage"',
    ])
    assert 'No issues found' in run(response_file(full)).stdout


def test_extended_profile_checks_deprecated_headers(response_file):
    response = build_response(*CLEAN_HEADERS, "X-XSS-Protection: 1; mode=block")
    data = json.loads(run(response_file(response), '-c', 'profiles/extended.yaml',
                          '--format', 'json').stdout)
    xss = next(r for r in data if r['header'] == 'X-XSS-Protection')
    assert xss['severity'] == 'LOW'


def test_basic_profile_ignores_deprecated_headers(response_file):
    response = build_response(*CLEAN_HEADERS, "X-XSS-Protection: 1; mode=block")
    data = json.loads(run(response_file(response), '--format', 'json').stdout)
    assert not any(r['header'] == 'X-XSS-Protection' for r in data)


# ---------------------------------------------------------------------------
# Nothing is summarised away
# ---------------------------------------------------------------------------

def test_an_absent_optional_header_is_reported_at_its_level(response_file):
    data = json.loads(run(response_file(CLEAN), '--format', 'json').stdout)
    coep = next(r for r in data if r['header'] == 'Cross-Origin-Embedder-Policy')
    assert coep['severity'] == 'INFO'
    assert 'Missing Cross-Origin-Embedder-Policy' in run(response_file(CLEAN)).stdout


def test_the_report_separates_what_is_settled_from_what_is_not(response_file):
    """A CSP that is simply absent is settled; a caching verdict is not."""
    out = run(response_file(NO_CSP)).stdout
    assert 'Findings' in out and 'To confirm' in out
    assert out.index('Missing Content-Security-Policy') < out.index('To confirm')


def test_the_removed_flags_are_gone(response_file):
    """Pass/fail and the header-name list were verdicts the tool is not in a
    position to reach; both were removed rather than reinterpreted."""
    for flag in (['--mode', 'simple'], ['--format', 'list']):
        assert run(response_file(CLEAN), *flag).returncode == 2
