# HSHA — HTTP Security Header Analyzer

A CLI tool that parses raw HTTP responses and evaluates security headers. Produces color-coded findings with severity levels, each explained in [`RULES.md`](RULES.md).

![Python](https://img.shields.io/badge/python-3.10+-blue) ![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

- Checks presence and correct configuration of security headers
- Two built-in profiles: **basic** (12 headers) and **extended** (24 headers)
- Two output formats: rich table (`text`) and machine-readable (`json`)
- Findings the response cannot settle carry the check that would, and what each outcome means
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

## Output

`--format text` (default) prints a table of every checked header, the findings
grouped by whether the response settles them, and a summary.

`--format json` prints the same analysis machine-readably, including the `verify`
field described below.

There is no pass/fail view and no list of header names. A header set is not
something the tool is in a position to declare passed or failed: what it can do
is rank findings by severity, say which ones it has settled, and say what would
settle the rest.

---

## To confirm

Some checks the response settles on its own: `max-age=300` is too short whatever
the site does with it. Others are true statements whose weight depends on
something a saved response cannot show — whether the page uses the camera,
whether it embeds third-party frames, whether this endpoint returns a signed-in
user's data.

Those findings carry the check that settles them, and what each outcome means:

```
To confirm (what these are worth depends on something the response cannot say)

Cache-Control
  Value: max-age=600
  [HIGH] Cache-Control: 'max-age=600' lets a shared cache store this response
        ? Does this response carry data belonging to a signed-in user — anything the
          server decided from a cookie or an Authorization header? If it does, this
          stands. If it carries nothing user-specific, there is nothing here.
```

The severity is what the finding is worth **if it applies**; the `?` beside a
header in the table says nothing settled has reached that level. The summary
counts the two apart, and a finding carries either a check or a recommendation —
never both, since until the check is done there is nothing to recommend.

---

## Configuration Profiles

The tool loads `profiles/basic.yaml` by default. Switch to the extended profile with `--config`:

```bash
# Basic profile — 12 core headers (default)
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
| Permissions-Policy | ✓ | ✓ |
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
