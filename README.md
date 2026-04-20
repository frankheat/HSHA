# HSHA — HTTP Security Header Analyzer

A CLI tool that parses raw HTTP responses and evaluates security headers against OWASP guidelines. Produces color-coded findings with severity levels and optional integration with [Google's CSP Evaluator](https://github.com/google/csp-evaluator).

![Python](https://img.shields.io/badge/python-3.10+-blue) ![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

- Checks presence and correct configuration of security headers
- Two built-in profiles: **basic** (11 headers) and **extended** (24+ headers)
- Three output formats: rich table (`text`), plain list (`list`), machine-readable (`json`)
- Two display modes: `severity` (CRITICAL/HIGH/MEDIUM/LOW/INFO) and `simple` (PASS/FAIL)
- CSP deep analysis via Google's CSP Evaluator (Node.js) with Python fallback
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

### Optional: Google CSP Evaluator (Node.js)

For more accurate CSP analysis, install the Google CSP Evaluator. Requires Node.js 14+.

```bash
npm install github:google/csp-evaluator
```

When available, the tool uses it automatically. The banner will show which engine is active. To force the built-in Python evaluator:

```bash
python check_headers.py response.txt --no-nodejs-csp
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

Minimal output — just the names of headers with issues:

```
The following headers are missing or misconfigured:

  Content-Security-Policy
  Cross-Origin-Embedder-Policy
  Cache-Control
```

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

Shows severity level (CRITICAL / HIGH / MEDIUM / LOW / INFO / OK) for each header and finding.

---

## Configuration Profiles

The tool loads `profiles/basic.yaml` by default. Switch to the extended profile with `--config`:

```bash
# Basic profile — 11 core OWASP headers (default)
python check_headers.py response.txt

# Extended profile — 24+ headers including legacy, deprecated, CORS, caching
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

Valid severity values: `critical`, `high`, `medium`, `low`, `info`.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No issues, or INFO only |
| `1` | At least one LOW/MEDIUM/HIGH/CRITICAL finding |
| `2` | File not found |

This makes the tool suitable for use in CI/CD pipelines.

---

## Project Structure

```
check_headers.py       # CLI entry point
lib/
  parser.py            # HTTP response parser
  rules.py             # OWASP header rules
  csp_evaluator.py     # CSP evaluation engine
  config.py            # YAML config loader
  reporter.py          # Output formatting
  models.py            # Data types
csp_wrapper.js         # Node.js wrapper for Google CSP Evaluator
profiles/
  basic.yaml           # Basic profile (default)
  extended.yaml        # Extended profile
requirements.txt
```
