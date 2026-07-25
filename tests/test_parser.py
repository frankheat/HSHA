import pytest

from lib.parser import parse_http_response


@pytest.mark.parametrize("status", [
    "HTTP/1.0 200 OK",
    "HTTP/1.1 301 Moved Permanently",
    "HTTP/2 200",
    "HTTP/3 204 No Content",
    "http/1.1 200 OK",          # case-insensitive match
])
def test_status_line_is_skipped(status):
    headers = parse_http_response(f"{status}\r\nX-Frame-Options: DENY\r\n\r\n")
    assert headers == {'x-frame-options': ['DENY']}


def test_missing_status_line_still_parses_headers():
    headers = parse_http_response("X-Frame-Options: DENY\r\nServer: nginx\r\n\r\n")
    assert headers == {'x-frame-options': ['DENY'], 'server': ['nginx']}


def test_names_are_lowercased_and_values_stripped():
    headers = parse_http_response("HTTP/1.1 200 OK\r\nX-Frame-Options:    DENY   \r\n\r\n")
    assert headers == {'x-frame-options': ['DENY']}


def test_duplicates_are_preserved_in_order():
    raw = ("HTTP/1.1 200 OK\r\n"
           "Set-Cookie: a=1\r\n"
           "Set-Cookie: b=2\r\n"
           "Set-Cookie: c=3\r\n\r\n")
    assert parse_http_response(raw)['set-cookie'] == ['a=1', 'b=2', 'c=3']


def test_value_containing_colons_is_kept_whole():
    raw = "HTTP/1.1 302 Found\r\nLocation: https://example.com:8443/a?b=c\r\n\r\n"
    assert parse_http_response(raw)['location'] == ['https://example.com:8443/a?b=c']


def test_empty_value_is_preserved_as_empty_string():
    headers = parse_http_response("HTTP/1.1 200 OK\r\nReferrer-Policy:\r\n\r\n")
    assert headers['referrer-policy'] == ['']


@pytest.mark.parametrize("continuation", [" more-value", "\tmore-value"])
def test_obs_fold_continuation_is_appended(continuation):
    raw = f"HTTP/1.1 200 OK\r\nX-Long: start\r\n{continuation}\r\n\r\n"
    assert parse_http_response(raw)['x-long'] == ['start more-value']


def test_obs_fold_appends_to_last_occurrence_only():
    raw = ("HTTP/1.1 200 OK\r\n"
           "X-Dup: first\r\n"
           "X-Dup: second\r\n"
           " continued\r\n\r\n")
    assert parse_http_response(raw)['x-dup'] == ['first', 'second continued']


def test_body_after_blank_line_is_ignored():
    raw = ("HTTP/1.1 200 OK\r\n"
           "Content-Type: text/html\r\n"
           "\r\n"
           "<html>X-Frame-Options: DENY</html>\r\n")
    headers = parse_http_response(raw)
    assert 'x-frame-options' not in headers
    assert headers['content-type'] == ['text/html']


def test_lf_only_line_endings_are_supported():
    headers = parse_http_response("HTTP/1.1 200 OK\nX-Frame-Options: DENY\n\n")
    assert headers == {'x-frame-options': ['DENY']}


def test_empty_input_yields_no_headers():
    assert parse_http_response("") == {}


def test_lines_without_colon_are_ignored():
    raw = "HTTP/1.1 200 OK\r\ngarbage line\r\nX-Frame-Options: DENY\r\n\r\n"
    assert parse_http_response(raw) == {'x-frame-options': ['DENY']}


def test_parse_http_response_file_reads_from_disk(tmp_path):
    """Convenience wrapper; currently unused by the CLI but part of the API."""
    from lib.parser import parse_http_response_file
    path = tmp_path / 'r.txt'
    path.write_text("HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\n")
    assert parse_http_response_file(str(path)) == {'x-frame-options': ['DENY']}


def test_invalid_utf8_bytes_do_not_crash(tmp_path):
    from lib.parser import parse_http_response_file
    path = tmp_path / 'r.txt'
    path.write_bytes(b"HTTP/1.1 200 OK\r\nX-Weird: \xff\xfe\r\n\r\n")
    assert 'x-weird' in parse_http_response_file(str(path))
