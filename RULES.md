# HSHA — Security Rules Reference

This document describes every check implemented by HSHA — what triggers a finding, the severity assigned, and the security rationale. It is intended as a reference for users who want to understand the analysis without reading the source code.

---

## Severity Scale

| Level | Meaning |
|---|---|
| **CRITICAL** | Severe misconfiguration with direct, exploitable impact |
| **HIGH** | Significant weakness that substantially reduces security |
| **MEDIUM** | Misconfiguration that weakens the security posture |
| **LOW** | Minor weakness or deprecated configuration |
| **INFO** | Informational — worth reviewing but not necessarily a problem |
| **OK** | Correctly configured |

The tool exits with code `1` if at least one finding is LOW or above, and `0` if all findings are INFO or OK.

---

## General Checks (all headers)

These checks apply to every header before any value-specific logic runs.

| Condition | Severity | Rationale |
|---|---|---|
| Header absent + required | Per-header default | Missing required security header |
| Header absent + optional | INFO | Absent but not mandatory in current profile |
| Header present, value is empty | **HIGH** | Browsers silently ignore headers with no value |

---

## Headers — Basic Profile

The following headers are checked by default when using `profiles/basic.yaml`.

---

### Content-Security-Policy

**Required:** yes — **Severity if missing:** HIGH

CSP is evaluated by the built-in Python engine.

#### Syntax / structural checks

| Condition | Severity | Rationale |
|---|---|---|
| Both `script-src` and `default-src` absent | HIGH | No restrictions on script loading whatsoever |
| A directive name appears as a value of another directive | HIGH | Almost certainly a missing `;`; the misplaced directive is silently ignored |
| CSP keyword without single quotes (e.g. `unsafe-inline` instead of `'unsafe-inline'`) | HIGH | Browser treats it as a hostname, not a keyword — protection is silently not applied |
| Nonce/hash value without single quotes (e.g. `nonce-abc` instead of `'nonce-abc'`) | HIGH | Same as above — nonce/hash is ignored by the browser |

#### script-src (or default-src as fallback)

| Condition | Severity | Rationale |
|---|---|---|
| `'strict-dynamic'` without nonce or hash | MEDIUM | `strict-dynamic` only takes effect with a nonce or hash; alone it blocks all scripts |
| `'unsafe-inline'` present (without nonce+strict-dynamic) | HIGH | Allows execution of arbitrary inline scripts, defeating XSS protection |
| `'unsafe-eval'` present | HIGH | Allows code execution via `eval()`, `Function()`, `setTimeout(string)` |
| `'unsafe-hashes'` present | MEDIUM | Enables hashing of event handler attributes; weaker than avoiding inline handlers |
| `*` or `http:` or `https:` present | CRITICAL/HIGH | Allows loading scripts from any origin |
| `data:` present | HIGH | `data:` URIs can be used to execute arbitrary scripts |
| `blob:` present | MEDIUM | `blob:` URIs may allow CSP bypass if attacker controls blob creation |
| Broad wildcard (e.g. `*.com`, `*.io`) | HIGH | Covers an entire TLD — any domain under it can serve scripts |
| Known bypass domain (e.g. `*.googleapis.com`, `cdnjs.cloudflare.com`) | HIGH | These domains host JSONP endpoints or Angular that can bypass CSP |
| Nonce shorter than 20 characters | MEDIUM | Short nonces are guessable; minimum 128 bits recommended |

#### style-src (or default-src as fallback)

| Condition | Severity | Rationale |
|---|---|---|
| `'unsafe-inline'` present | MEDIUM | Allows arbitrary inline styles; enables CSS injection |

#### object-src

| Condition | Severity | Rationale |
|---|---|---|
| Missing (no default-src either) | HIGH | Without restriction, plugins (Flash, Java) load from any origin |
| Present but not `'none'` | HIGH | Any allowed origin for plugins is a risk; same-origin and CDN-hosted plugins can be exploited for XSS |

#### base-uri

| Condition | Severity | Rationale |
|---|---|---|
| Missing | MEDIUM | Attackers can inject `<base href>` to redirect relative URLs |
| Present with `*`, `http:` or `https:` | HIGH | Allows any URL as base, enabling `<base href>` injection to an attacker-controlled origin |

#### frame-ancestors

| Condition | Severity | Rationale |
|---|---|---|
| Missing | INFO | Recommend using `frame-ancestors` over `X-Frame-Options` |
| Present with `*` or `http:` | HIGH | Allows embedding from any origin — clickjacking risk |

#### default-src

| Condition | Severity | Rationale |
|---|---|---|
| Missing | MEDIUM | Resource types without a specific directive are unrestricted |
| Present with `*` or `http:` | HIGH | Too broad; applies to all uncovered resource types |

#### form-action

| Condition | Severity | Rationale |
|---|---|---|
| Missing | MEDIUM | Forms can submit to any URL, bypassing other CSP restrictions |

#### Miscellaneous

| Condition | Severity | Rationale |
|---|---|---|
| `upgrade-insecure-requests` missing | INFO | Upgrading HTTP sub-resources to HTTPS is recommended |
| Deprecated directives (`reflected-xss`, `referrer`, `block-all-mixed-content`, `prefetch-src`) | INFO | These directives have been removed from the spec or are ignored by browsers |

---

### Strict-Transport-Security

**Required:** yes — **Severity if missing:** HIGH

| Condition | Severity | Rationale |
|---|---|---|
| `max-age` directive missing | HIGH | `max-age` is required for HSTS to function |
| `max-age=0` | HIGH | Explicitly revokes HSTS — browsers delete the entry |
| `max-age` < threshold *(default: 31536000s / 1 year)* | MEDIUM | Short values reduce protection window against SSL-stripping |
| `includeSubDomains` missing *(configurable)* | LOW | Subdomains remain vulnerable to SSL-stripping attacks |
| `preload` missing *(extended profile only)* | LOW | Site cannot be submitted to browser HSTS preload lists |

Threshold values are configurable in the profile:
```yaml
Strict-Transport-Security:
  min_max_age: 31536000          # basic profile
  require_include_subdomains: true
  require_preload: false         # true in extended profile
```

---

### X-Frame-Options

**Required:** yes — **Severity if missing:** HIGH

| Value | Severity | Rationale |
|---|---|---|
| `DENY` | OK | Optimal — prevents all framing |
| `SAMEORIGIN` | OK | Acceptable — allows framing by same origin only |
| `ALLOW-FROM ...` | LOW | Deprecated and not supported by modern browsers |
| Any other value | MEDIUM | Unrecognized value; header is effectively ignored |

---

### X-Content-Type-Options

**Required:** yes — **Severity if missing:** MEDIUM

| Value | Severity | Rationale |
|---|---|---|
| `nosniff` | OK | Prevents MIME-type sniffing |
| Any other value | MEDIUM | The only valid value is `nosniff` |

---

### Cross-Origin-Opener-Policy

**Required:** yes — **Severity if missing:** MEDIUM

| Value | Severity | Rationale |
|---|---|---|
| `same-origin` | OK | Full cross-origin isolation — optimal |
| `same-origin-allow-popups` | LOW | Weaker; allows popups to cross-origin pages |
| `unsafe-none` | MEDIUM | Disables cross-origin isolation; no Spectre/XS-Leak protection |
| Any other value | INFO | Unrecognized value |

---

### Referrer-Policy

**Required:** yes — **Severity if missing:** MEDIUM

| Value | Severity | Rationale |
|---|---|---|
| `no-referrer`, `strict-origin`, `strict-origin-when-cross-origin` | OK | Strong policies — no or minimal referrer leakage |
| `no-referrer-when-downgrade`, `origin`, `origin-when-cross-origin`, `same-origin` | LOW | Acceptable but leaks some referrer information |
| `unsafe-url`, `always` | HIGH | Sends full URL as referrer even over HTTP — leaks sensitive paths |
| Empty value | LOW | Browser default behavior varies |
| Any other value | INFO | Unrecognized value |

---

### Cross-Origin-Embedder-Policy

**Required:** no (basic) — **Severity if missing:** INFO

| Value | Severity | Rationale |
|---|---|---|
| `require-corp` | OK | Optimal — enables cross-origin isolation |
| `credentialless` | INFO | Allows cross-origin resources without CORP, strips credentials |
| `unsafe-none` | LOW | Disables embedding restrictions |
| Any other value | INFO | Unrecognized value |

---

### Cross-Origin-Resource-Policy

**Required:** no (basic) — **Severity if missing:** INFO

| Value | Severity | Rationale |
|---|---|---|
| `same-origin`, `same-site` | OK | Restricts resource loading to same origin/site |
| `cross-origin` | LOW | No isolation — any origin can load the resource |
| Any other value | INFO | Unrecognized value |

---

### X-Permitted-Cross-Domain-Policies

**Required:** no (basic) — **Severity if missing:** INFO

| Value | Severity | Rationale |
|---|---|---|
| `none`, `master-only` | OK | Restrictive — blocks Flash/PDF cross-domain requests |
| `all`, `by-content-type`, `by-ftp-filename` | MEDIUM | Permissive — allows plugin cross-domain requests |
| Any other value | INFO | Unrecognized value |

---

### Cache-Control

**Required:** no — **Severity if missing:** INFO

| Condition | Severity | Rationale |
|---|---|---|
| Contains `no-store` | OK | Sensitive data not stored in any cache |
| Contains `no-cache` (without `no-store`) | INFO | Content may be stored but is revalidated before use |
| Contains `public` | INFO | Shared caches (CDN, proxies) are allowed — verify intentionality |
| Any other value | INFO | Informational |

---

### Clear-Site-Data

**Required:** no — **Severity if missing:** INFO

| Condition | Severity | Rationale |
|---|---|---|
| Contains `"*"` | OK | All browsing data cleared |
| All three directives present: `"cache"`, `"cookies"`, `"storage"` | OK | OWASP recommended configuration |
| One or more of `"cache"`, `"cookies"`, `"storage"` missing | LOW | Incomplete data clearing — residual data may persist after logout |

---

## Headers — Extended Profile Only

The following headers are checked only when using `profiles/extended.yaml`.

---

### Permissions-Policy

**Required:** yes (extended) — **Severity if missing:** MEDIUM

| Condition | Severity | Rationale |
|---|---|---|
| Wildcard `*` for any sensitive feature | MEDIUM | Any origin gains access to that browser capability |
| High-risk features not explicitly declared: `camera`, `microphone`, `geolocation`, `payment`, `usb`, `display-capture` | MEDIUM | Undeclared features are allowed by default per spec |
| Medium-risk features not explicitly declared: `accelerometer`, `gyroscope`, `magnetometer`, `midi`, `screen-wake-lock`, `xr-spatial-tracking`, `document-domain`, `publickey-credentials-get` | LOW | Undeclared features are allowed by default |

---

### Origin-Agent-Cluster

**Required:** no — **Severity if missing:** INFO

| Value | Severity | Rationale |
|---|---|---|
| `?1` | OK | Origin isolation enabled |
| `?0` | LOW | Isolation explicitly disabled |
| Any other value | INFO | Unrecognized value |

---

### Access-Control-Allow-Origin

**Required:** no — **Severity if missing:** INFO *(absent = same-origin only, which is secure by default)*

| Value | Severity | Rationale |
|---|---|---|
| `*` | MEDIUM | Any origin can read the response — dangerous with sensitive data |
| Specific origin | OK | Correctly restricted to a trusted origin |

---

### Access-Control-Allow-Credentials

**Required:** no — **Severity if missing:** INFO

| Value | Severity | Rationale |
|---|---|---|
| `true` | MEDIUM | Cookies/auth headers sent cross-origin — must not be combined with `ACAO: *` |
| `false` | OK | Credentials not exposed cross-origin |

---

### X-DNS-Prefetch-Control

**Required:** no — **Severity if missing:** INFO

| Value | Severity | Rationale |
|---|---|---|
| `off` | OK | DNS prefetching disabled |
| Any other value | INFO | DNS prefetching enabled — can reveal visited subdomains |

---

### Service-Worker-Allowed

**Required:** no — **Severity if missing:** INFO *(absent = scope limited to script directory, secure default)*

| Value | Severity | Rationale |
|---|---|---|
| `/` | LOW | Service worker can intercept requests for the entire origin |
| Any other value | INFO | Extended scope — verify intentionality |

---

### Content-Disposition

**Required:** no — **Severity if missing:** INFO

| Value | Severity | Rationale |
|---|---|---|
| Starts with `attachment` | OK | Download forced — prevents inline execution |
| Starts with `inline` | INFO | Browser attempts inline rendering |
| Any other value | INFO | Unrecognized value |

---

### Pragma

**Required:** no — **Severity if missing:** INFO

| Value | Severity | Rationale |
|---|---|---|
| `no-cache` | INFO | Legacy HTTP/1.0 header, superseded by `Cache-Control` |
| Any other value | INFO | Legacy header |

---

### Expires

**Required:** no — **Severity if missing:** INFO

| Value | Severity | Rationale |
|---|---|---|
| `0` or `-1` | OK | Immediately expired — no caching |
| Any other value | INFO | Legacy HTTP/1.0 caching header, superseded by `Cache-Control: max-age` |

---

### ETag

**Required:** no — **Severity if missing:** INFO

| Condition | Severity | Rationale |
|---|---|---|
| Starts with `W/` | INFO | Weak validator present |
| Any other value | INFO | Strong validator present |

---

### X-Download-Options

**Required:** no — **Severity if missing:** INFO *(IE-specific header)*

| Value | Severity | Rationale |
|---|---|---|
| `noopen` | OK | Prevents IE from opening downloads in the site context |
| Any other value | INFO | Expected value is `noopen` |

---

### X-XSS-Protection *(deprecated)*

**Required:** no — **Severity if missing:** INFO

| Value | Severity | Rationale |
|---|---|---|
| `0` | INFO | Deprecated header correctly disabled — consider removing entirely |
| `1; mode=block` | LOW | Deprecated and `mode=block` can cause info leaks in old browsers |
| Any other value | INFO | Deprecated header |

---

### Expect-CT *(deprecated)*

**Required:** no — **Severity if missing:** INFO

| Condition | Severity | Rationale |
|---|---|---|
| Header present | INFO | Certificate Transparency is now mandatory; this header is obsolete and can be removed |

---

## Customizing Rules

While the security logic is defined in code, the following parameters can be adjusted per-header in any profile YAML:

| Parameter | Effect |
|---|---|
| `required: true/false` | Override whether absence is reported as a finding |
| `severity_if_missing: <level>` | Override the severity when the header is absent |
| `severity_if_present: <level>` | Emit a finding when the header is present (e.g. flag info-disclosure headers) |
| `expected_value: "..."` | Assert an exact value — bypasses all built-in checks |
| `expected_pattern: "regex"` | Assert the value matches a regex — bypasses all built-in checks |
| `skip: true` | Exclude this header entirely from analysis and output |
| `min_max_age: N` | *(HSTS only)* Minimum acceptable `max-age` in seconds |
| `require_include_subdomains: true/false` | *(HSTS only)* Whether `includeSubDomains` is required |
| `require_preload: true/false` | *(HSTS only)* Whether `preload` is required |
