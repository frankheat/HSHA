import re


def parse_http_response(content: str) -> dict[str, list[str]]:
    """
    Parse HTTP response headers into a lowercase-keyed dict.
    Each value is the ordered list of occurrences, so duplicate headers are
    preserved as-is; how duplicates combine is decided per header by the
    rule engine. Handles HTTP/1.0, HTTP/1.1, HTTP/2 status lines and
    obs-fold (header folding).
    """
    headers: dict[str, list[str]] = {}
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
            headers[current_name][-1] += ' ' + line.strip()
            continue

        if ':' in line:
            name, _, value = line.partition(':')
            current_name = name.strip().lower()
            headers.setdefault(current_name, []).append(value.strip())

    return headers


def parse_http_response_file(file_path: str) -> dict[str, list[str]]:
    with open(file_path, encoding='utf-8', errors='replace') as f:
        return parse_http_response(f.read())
