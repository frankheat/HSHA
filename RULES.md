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
| **NOTE** | Informational note only (e.g. duplicate header) — never counted as a failure |
| **OK** | Correctly configured |

A finding counts as an issue from **LOW** upwards. OK, NOTE and INFO are informational: they never mark a header as FAIL, never appear in `--format list`, and never affect the exit code — the tool exits `1` only if at least one finding is LOW or above. Informational findings are still printed, under their own section in `--mode simple` and with their level in `--mode severity`.

---

## General Checks (all headers)

These checks apply to every header before any value-specific logic runs.

| Condition | Severity | Rationale |
|---|---|---|
| Header absent + required | Per-header default | Missing required security header |
| Header absent + optional | INFO | Absent but not mandatory in current profile |

An optional header that is absent is reported at INFO, so it never fails a build.
Where a specific recommendation exists for that header it is shown anyway — that
is precisely where the finding would otherwise say nothing beyond repeating its
own title. Marking such a header `required: true` in a profile switches it to the
per-header severity in the tables below.
| Header present, value is empty | Same as absent | Browsers ignore a header with no value, so the impact is identical to not sending it. Reported under its own title because an empty value usually means a misconfigured template or proxy |
| Header sent more than once, same value | **NOTE** | Harmless: a proxy/CDN repeating an instruction the origin already sent |
| Header sent more than once, conflicting values | **LOW** | A misconfiguration — see below |

### Duplicate headers

When a header appears multiple times in the response, HSHA resolves the
effective value the same way browsers do, then evaluates that value:

| Strategy | Headers | Behavior |
|---|---|---|
| Identical values | any | Collapsed to the single value |
| First wins | default (e.g. `Strict-Transport-Security`, RFC 6797 §8.1) | First occurrence is evaluated |
| Last wins | `Referrer-Policy` | Browsers honor the last valid value |
| Join | `Content-Security-Policy`, `Cache-Control`, `Clear-Site-Data`, `Permissions-Policy`, `Pragma` | Occurrences combine into a single list/policy set |
| Strictest | `X-Frame-Options` | Conflicting values make browsers block framing — evaluated as `DENY` |

The finding always reports the original values, the effective value chosen, and
why.

**Why conflicting values are a finding of their own.** Repeating the same value
is noise. Contradictory values mean two components disagree — typically the
application and a CDN or WAF in front of it — and the resolution silently
discards one of them, so whoever configured the losing value is operating on a
false assumption. The winning value is also decided by a resolution rule rather
than by anything the site chose, and that resolution is not guaranteed to be
identical in every browser.

The severity is deliberately LOW rather than higher: the resolved value is
usually the safe one, so this is a configuration defect to fix rather than an
exposure. It is reported even when the resolved value is perfectly good — for
example `X-Frame-Options: deny` plus `sameorigin` resolves to `DENY`, which is
optimal, but the site did not choose it and a change in header ordering could
change the outcome.

---

## Headers — Basic Profile

The following headers are checked by default when using `profiles/basic.yaml`.

---

### Content-Security-Policy

**Required:** yes — **Severity if missing:** HIGH

CSP is evaluated by the built-in Python engine.

#### Multiple policies

A comma separates independent policies: `Content-Security-Policy: a, b` is the
wire equivalent of sending the header twice (and is what the `join` duplicate
strategy above produces). A resource must be allowed by **every** policy, so the
effective policy is their intersection. Findings combine as follows:

| Finding type | Combination | Rationale |
|---|---|---|
| `Missing X` | Reported only if **no** policy declares `X` | One policy declaring a directive is enough to restrict the whole response |
| Everything else | Reported if **any** policy carries it | A policy that says nothing about a directive restricts nothing, so a weakness is only neutralised when another policy actually constrains that directive. Resolving this exactly would require intersecting the source lists, which the engine does not do — it reports instead, which can be conservative but never hides a weakness |

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

**Required:** no — **Severity if missing:** INFO *(with no explicit caching
instruction browsers fall back to heuristic caching and may keep the response on
disk — harmless for a static asset, a problem for a response carrying a signed-in
user's data, which can then be read after logout or by the next person on a
shared machine. HSHA cannot tell the two apart, so the finding asks)*

| Condition | Severity | Rationale |
|---|---|---|
| Contains `no-store` | OK | Sensitive data not stored in any cache |
| Contains `no-cache` (without `no-store`) | OK | Content may be stored but is revalidated before use; prefer `no-store` for sensitive endpoints |
| Contains `private` (without `no-store` or `no-cache`) | OK | Shared caches must not store the response; the browser still may |
| Contains `public` | INFO | Shared caches (CDN, proxies) are allowed — verify intentionality |
| Only standard directives, none of the above | OK | Valid caching directives |
| Contains a token that is not a standard directive | INFO | Likely a typo or a non-standard extension; browsers ignore it |

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
| `*` | MEDIUM | Any site can read the response — see below |
| `null` | **HIGH** | Forgeable by any attacker and, unlike `*`, usable with credentials — see below |
| More than one origin (`https://a.example, https://b.example`) | INFO | The header carries exactly one origin, `*` or `null`. A list never matches the requesting origin, so the CORS check fails and no site gets access, including the intended ones. Fails closed, so it is a broken configuration rather than an exposure. Usually means two components are both setting the header — typically the application and a proxy in front of it |
| `http://` origin | LOW | The allowed origin is not protected by TLS, so anyone able to tamper with traffic to it can impersonate it and read what this endpoint returns to it. A `localhost` origin here usually means a development configuration reached production |
| Specific `https://` origin | OK | Correctly restricted to a trusted origin |

#### When the wildcard actually costs something

On a genuinely public endpoint `*` costs nothing — that is what the wildcard is
for, and public APIs, CDNs and font services set it on purpose.

It matters when the endpoint is **reachable by a victim's browser but not by an
attacker's server**: an internal API, a service on `localhost`, a device admin
page, anything authorised by network location or source IP rather than by
credentials. Without the wildcard, a browser will send such a cross-origin
request but refuses to hand the response back to the calling page. With it, an
attacker's page reads the answer through the browser of whoever can reach the
endpoint — the victim's browser becomes a tunnel into a network the attacker
cannot otherwise touch.

HSHA reads a saved response, so it cannot tell the two situations apart: it sees
the header, not where the endpoint lives or what the body holds. The finding
stays MEDIUM and asks the question the reader has to answer — is this endpoint
reachable from anywhere, or only from certain networks?

#### Why `null` outranks `*`

`*` looks like the more permissive of the two, so the severity ordering is worth
explaining.

**`*` is usually a decision.** Public APIs and CDNs set it deliberately. It also
carries a safety catch built into the browser: the wildcard is incompatible with
credentials, so a response sent with `Access-Control-Allow-Origin: *` is never
readable together with the victim's cookies. Whatever leaks is data that was
already served without authentication. MEDIUM is a "confirm this is intended"
signal.

**`null` is almost never a decision.** Nobody sets out to grant access to
sandboxed iframes and `file://` pages. It nearly always comes from code that
reflects the `Origin` header without validating it: some requests legitimately
arrive with `Origin: null`, the value is echoed back, and the allowlist now
contains an origin that *any* attacker can assume — a sandboxed iframe, a `data:`
URL or a cross-origin redirect all produce it.

The decisive difference is that `null` is a **concrete origin**, not a wildcard,
so the browser's safety catch does not apply: with
`Access-Control-Allow-Credentials: true` the browser sends cookies, and the
attacker's page reads authenticated responses.

The value that reads as the more cautious of the two is therefore the one that
can expose authenticated data, which is why it is reported as the more severe.

---

### Access-Control-Allow-Credentials

**Required:** no — **Severity if missing:** INFO

`true` means "send the cookies", which says nothing on its own — it matters who
receives them. This header is therefore graded against
`Access-Control-Allow-Origin`, and carries a single verdict:

| Access-Control-Allow-Origin | Severity | Rationale |
|---|---|---|
| `null` | **CRITICAL** | The null origin is forgeable by any page and is a concrete origin, so cookies are sent with it: an attacker's page reads this endpoint as the logged-in user |
| `*` | INFO | Browsers refuse the wildcard together with credentials, so every credentialed request is rejected. Nothing is exposed by the combination itself — it is a functional contradiction, not a weakness, and the wildcard's own effect on non-credentialed requests is graded on `Access-Control-Allow-Origin` |
| A specific origin | INFO | Correct authenticated CORS. Reported so the origin can be verified — see below |
| Absent | INFO | No origin is authorised to read the response, so credentials change nothing; usually a leftover |
| Not evaluated (excluded by the profile) | INFO | Stated explicitly, because silence would read as approval |

`false` is OK regardless of the origin.

**Why a specific origin is still reported.** A response that echoes back the
request's `Origin` header is byte-for-byte identical to one that allowlists that
origin, and HSHA analyses a single saved response — it never issues requests, so
it cannot tell them apart. Reflection is at least as dangerous as `null` and
easier to exploit: the attacker just serves a page from their own domain. The
finding therefore explains how to check, by replaying the request with an
invented `Origin` and seeing whether it comes back. It stays INFO because that is
a one-off verification; failing every build for it would get the whole check
suppressed, including the cases that matter.

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
| Starts with `inline` | OK | Browser renders the content inline; benign in itself, but `attachment` is safer for file downloads |
| Any other value | INFO | Unrecognized value |

---

### Pragma

**Required:** no — **Severity if missing:** INFO

| Value | Severity | Rationale |
|---|---|---|
| `no-cache` | OK | Legacy HTTP/1.0 header, superseded by `Cache-Control`; harmless |
| Any other value | OK | Legacy header; harmless |

---

### Expires

**Required:** no — **Severity if missing:** INFO

| Value | Severity | Rationale |
|---|---|---|
| `0` or `-1` | OK | Immediately expired — no caching |
| Any other value | OK | Legacy HTTP/1.0 caching header, superseded by `Cache-Control: max-age`; harmless |

---

### ETag

**Required:** no — **Severity if missing:** INFO

| Condition | Severity | Rationale |
|---|---|---|
| Starts with `W/` | OK | Weak validator present |
| Any other value | OK | Strong validator present |

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
| `0` | OK | Deprecated header correctly disabled — consider removing entirely |
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
| `severity_if_missing: <level>` | Severity when the header is absent. Implies `required: true`, since asking for a severity states that the header is expected — an explicit `required: false` still wins |
| `severity_if_present: <level>` | Emit a finding when the header is present (e.g. flag info-disclosure headers). A real problem found by the built-in checker is more specific and takes precedence |
| `expected_value: "..."` | Assert an exact value — bypasses all built-in checks |
| `expected_pattern: "regex"` | Assert the value matches a regex — bypasses all built-in checks |
| `skip: true` | Exclude this header entirely from analysis and output |
| `min_max_age: N` | *(HSTS only)* Minimum acceptable `max-age` in seconds |
| `require_include_subdomains: true/false` | *(HSTS only)* Whether `includeSubDomains` is required |
| `require_preload: true/false` | *(HSTS only)* Whether `preload` is required |

Any other option — including a misspelling of one of the above, or an HSTS-only
option set on a different header — is rejected when the config is loaded, with
exit code `2`. An unrecognised option would otherwise be dropped in silence and
the setting you believed you had made would never take effect.
