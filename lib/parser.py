import re


def parse_http_response(content: str) -> dict[str, str]:
    """
    Parse HTTP response headers into a lowercase-keyed dict.
    Handles HTTP/1.0, HTTP/1.1, HTTP/2 status lines, obs-fold (header folding),
    and duplicate headers (joined with ', ' per RFC 7230).
    """
    headers: dict[str, str] = {}
    lines = content.splitlines()

    start = 0
    if lines and re.match(r'^HTTP/', lines[0], re.IGNORECASE):
        start = 1

    current_name: str | None = None
    for line in lines[start:]:
        if not line.strip():
            break

        # Obsolete header folding: continuation lines start with whitespace
        if line[0] in (' ', '\t') and current_name:
            headers[current_name] = headers[current_name] + ' ' + line.strip()
            continue

        if ':' in line:
            name, _, value = line.partition(':')
            current_name = name.strip().lower()
            value = value.strip()
            if current_name in headers:
                headers[current_name] = headers[current_name] + ', ' + value
            else:
                headers[current_name] = value

    return headers


def parse_http_response_file(file_path: str) -> dict[str, str]:
    with open(file_path, encoding='utf-8', errors='replace') as f:
        return parse_http_response(f.read())
