# HSHA — HTTP Security Header Analyzer

A CLI tool that parses raw HTTP responses and evaluates security headers. Produces color-coded findings with severity levels, each explained in [`RULES.md`](RULES.md).

![Python](https://img.shields.io/badge/python-3.10+-blue) ![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

- Checks presence and correct configuration of security headers
- Two built-in profiles: **basic** (11 headers) and **extended** (24 headers)
- Three output formats: rich table (`text`), plain list (`list`), machine-readable (`json`)
- Response context (`--context authenticated|public`) for the checks whose correct value depends on it
- Two display modes: `severity` (CRITICAL/HIGH/MEDIUM/LOW/INFO/NOTE) and `simple` (PASS/FAIL)
- Duplicate headers resolved per header the way browsers do (first wins, last wins, join, strictest); losing a value to the resolution is a LOW finding, otherwise a NOTE — and the resolved value is then checked like any other, which is how two `Cross-Origin-Opener-Policy` headers are caught cancelling each other out
- CSP deep analysis via built-in Python evaluator
- Fully customizable via YAML config: override severities, mark headers as required/optional, assert expected values
- Full documentation of every check, condition, and severity in [`RULES.md`](RULES.md)

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/frankheat/HSHA
cd HSHA

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

Save a raw HTTP response to a file (including status line and headers), then run:

```bash
python check_headers.py response.txt
```

**Get a response with curl:**

```bash
curl -si https://example.com > response.txt
python check_headers.py response.txt
```

**Read from stdin:**

```bash
curl -si https://example.com | python check_headers.py -
```

---

## Output Formats

### `--format text` (default)

Rich color-coded table with findings detail and summary.

### `--format list`

Minimal output — just the names of headers with an issue, one per line:

```
The following headers are missing or misconfigured:

Content-Security-Policy
Strict-Transport-Security
Referrer-Policy
```

Only findings of LOW or above are listed, so an optional header that is simply
absent does not appear here — its absence is INFO. Nothing is printed when the
response is clean.

### `--format json`

Machine-readable JSON, suitable for CI pipelines:

```bash
python check_headers.py response.txt --format json
```

---

## Display Modes

### `--mode simple` (default)

Shows PASS/FAIL per header with a list of issues.

### `--mode severity`

Shows severity level (CRITICAL / HIGH / MEDIUM / LOW / INFO / NOTE / OK) for each header and finding.

A finding counts as an issue from LOW upwards. OK, NOTE and INFO never mark a header as FAIL and never appear in `--format list` — they are still printed, grouped under their own section in `--mode simple`.

---

## Response Context

Most checks give the same verdict whatever the response carries. Caching does
not: `Cache-Control: public, max-age=31536000` is correct for a static asset and
a data leak on an account page. HSHA therefore asks instead of guessing.

```bash
# Default — assumes the response carries data belonging to a signed-in user
python check_headers.py response.txt

# The response carries nothing user-specific
python check_headers.py response.txt --context public
```

The default is `authenticated` because under-reporting on a sensitive page is
worse than the reverse: a missing finding goes unnoticed, an inapplicable one is
obvious and fixed with a flag. The report states which assumption it was produced
under.

Only `Cache-Control` is affected; every other check gives the same verdict either
way. [`RULES.md`](RULES.md) explains why.

---

## Configuration Profiles

The tool loads `profiles/basic.yaml` by default. Switch to the extended profile with `--config`:

```bash
# Basic profile — 11 core headers (default)
python check_headers.py response.txt

# Extended profile — 24 headers including legacy, deprecated, CORS, caching
python check_headers.py response.txt --config profiles/extended.yaml
```

### Checked Headers

| Header | Basic | Extended |
|---|:---:|:---:|
| Content-Security-Policy | ✓ | ✓ |
| Strict-Transport-Security | ✓ | ✓ |
| X-Frame-Options | ✓ | ✓ |
| X-Content-Type-Options | ✓ | ✓ |
| Cross-Origin-Opener-Policy | ✓ | ✓ |
| Referrer-Policy | ✓ | ✓ |
| Cross-Origin-Embedder-Policy | ✓ | ✓ |
| Cross-Origin-Resource-Policy | ✓ | ✓ |
| X-Permitted-Cross-Domain-Policies | ✓ | ✓ |
| Cache-Control | ✓ | ✓ |
| Clear-Site-Data | ✓ | ✓ |
| Permissions-Policy | | ✓ |
| Origin-Agent-Cluster | | ✓ |
| Access-Control-Allow-Origin | | ✓ |
| Access-Control-Allow-Credentials | | ✓ |
| Content-Disposition | | ✓ |
| X-DNS-Prefetch-Control | | ✓ |
| Service-Worker-Allowed | | ✓ |
| Pragma / Expires / ETag | | ✓ |
| X-Download-Options | | ✓ |
| X-XSS-Protection *(deprecated)* | | ✓ |
| Expect-CT *(deprecated)* | | ✓ |

---

## Custom Configuration

Both `profiles/basic.yaml` and `profiles/extended.yaml` can be edited. You can also create your own config file and pass it with `--config`.

```yaml
headers:

  # Change minimum HSTS max-age
  Strict-Transport-Security:
    min_max_age: 63072000        # 2 years

  # Mark an optional header as required
  Clear-Site-Data:
    required: true
    severity_if_missing: medium

  # Flag a header that should never appear in production
  X-Powered-By:
    severity_if_present: medium

  # Assert a specific value
  Cache-Control:
    expected_value: "no-store, no-cache"

  # Skip a header entirely
  Expect-CT:
    skip: true

  # Add a custom application header
  X-Request-Id:
    required: true
    severity_if_missing: low
    expected_pattern: "^[0-9a-f-]{36}$"
```

Valid severity values: `critical`, `high`, `medium`, `low`, `info`, `note`.

Notes on the options:

- `severity_if_missing` implies the header is required — an explicit `required: false` still wins.
- `severity_if_present` yields to a real problem found by the built-in checker, which is more specific.
- Any option that is not recognised for that header — a misspelling, or an HSTS-only option set elsewhere — is rejected when the config loads, with exit code `2`. An unrecognised option would otherwise be dropped in silence and the setting would never take effect.

---

## Exit Status

`0` once a report has been produced, whatever is in it, and `2` when no report
could be produced at all — an unreadable response, a missing or invalid config.

The severity of a response never reaches the exit status. Grading a response is a
judgement the reader makes from the report; a header set is not something the
program is in a position to declare passed or failed on its own.

---

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest
```

A confirmed defect that is not being fixed yet is recorded as a test asserting
the behaviour the tool *should* have, marked `xfail(strict=True)` in
`tests/test_known_bugs.py`. Strict mode turns the eventual XPASS into a failure,
so fixing the bug forces the marker to be removed. That file is absent whenever
there is nothing outstanding, as is the case now.

---

## Project Structure

```
check_headers.py       # CLI entry point
lib/
  parser.py            # HTTP response parser
  rules.py             # Per-header rules
  correlations.py      # Checks that need more than one header
  csp_evaluator.py     # CSP evaluation engine
  config.py            # YAML config loader
  reporter.py          # Output formatting
  models.py            # Data types
profiles/
  basic.yaml           # Basic profile (default)
  extended.yaml        # Extended profile
tests/                 # pytest suite
RULES.md               # Every check, condition and severity
pytest.ini
requirements.txt
requirements-dev.txt
```
