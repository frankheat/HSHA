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

A finding counts as an issue from **LOW** upwards. OK, NOTE and INFO are informational: they never mark a header as FAIL and never appear in `--format list`. They are still printed, under their own section in `--mode simple` and with their level in `--mode severity`. No severity reaches the process exit status, which only reports whether the analysis could be run at all.

---

## General Checks (all headers)

These checks apply to every header before any value-specific logic runs.

| Condition | Severity | Rationale |
|---|---|---|
| Header absent + required | Per-header default | Missing required security header |
| Header absent + optional | INFO | Absent but not mandatory in current profile |
| Header present, value is empty | Same as absent | Browsers ignore a header with no value, so the impact is identical to not sending it. Reported under its own title because an empty value usually means a misconfigured template or proxy |
| Header sent more than once, values combine | **NOTE** | Nothing is lost: the occurrences merge, or they were identical to begin with |
| Header sent more than once, one value discarded | **LOW** | A misconfiguration — see below |

An optional header that is absent is reported at INFO, so it never fails a build.
Where a specific recommendation exists for that header it is shown anyway — that
is precisely where the finding would otherwise say nothing beyond repeating its
own title. Marking such a header `required: true` in a profile switches it to the
per-header severity in the tables below.

### Duplicate headers

When a header appears multiple times in the response, HSHA resolves the
effective value the same way browsers do, then evaluates that value:

| Strategy | Headers | Behavior |
|---|---|---|
| Join | `Content-Security-Policy`, `Cache-Control`, `Clear-Site-Data`, `Permissions-Policy`, `Pragma`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy` | Occurrences combine into a single value |
| Identical values | any other header | Collapsed to the single value |
| First wins | default (e.g. `Strict-Transport-Security`, RFC 6797 §8.1) | First occurrence is evaluated |
| Last wins | `Referrer-Policy` | Browsers honor the last valid value |
| Strictest | `X-Frame-Options` | Conflicting values make browsers block framing — evaluated as `DENY` |

Join is applied before the identical-values shortcut, because a browser
concatenates the occurrences whether or not they agree — and for a header that
must hold exactly one value, that is the whole point (see COOP below).

The finding always reports the original values, the effective value chosen, and
why.

**When repetition is a finding, and when it is not.** What matters is whether the
resolution has to throw a value away.

Under **join** nothing is thrown away: sending the header more than once is how a
combined list is expressed, so `Cache-Control: max-age=600` followed by
`Cache-Control: must-revalidate` means exactly what the two directives on one line
would mean. Two CSP headers are likewise both enforced. These stay a NOTE, and
there is nothing to fix.

The duplicate finding stays a NOTE under join even when the combined value turns
out to be unusable — the repetition still discarded nothing. Whether the result
parses is graded separately by that header's own check, which is where a
duplicated `Cross-Origin-Opener-Policy` or `Cross-Origin-Embedder-Policy` is
reported: both must hold a single token, so the joined value fails to parse and
the browser applies `unsafe-none`. Two identical COOP headers therefore leave the
response with no COOP at all, and that is graded like the header being absent.

Under **first**, **last** and **strictest** one occurrence wins and the others are
discarded. That is a misconfiguration: two components disagree — typically the
application and a CDN or WAF in front of it — and whoever configured the losing
value is operating on a false assumption. The winning value is decided by a
resolution rule rather than by anything the site chose, and that resolution is not
guaranteed to be identical in every browser.

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
| Header does not conform to RFC 6797 §6.1 | Same as absent | A browser ignores such a header in full, so the site has no HSTS at all. Covers a missing or non-numeric `max-age`, a directive repeated (`max-age=1; max-age=2`), and `includeSubDomains` or `preload` given a value. The value may be quoted (`max-age="31536000"`), which the RFC allows |
| `max-age=0` | HIGH | Explicitly revokes HSTS — browsers delete the entry |
| `max-age` < threshold *(default: 31536000s / 1 year)* | MEDIUM | Short values reduce protection window against SSL-stripping |
| `includeSubDomains` missing *(configurable)* | LOW | Subdomains remain vulnerable to SSL-stripping attacks |
| `preload` missing *(extended profile only)* | LOW | Site cannot be submitted to browser HSTS preload lists |

Directive names are matched as names, not searched for in the value. A
misspelling such as `includeSubDomainss`, or the word appearing inside another
directive's value, counts as the directive being missing — which is what a
browser does too, since it ignores a directive name it does not recognise. Note
the asymmetry the RFC draws: an *unrecognised* directive is skipped and the rest
of the header still applies, but a *recognised* one used wrongly — repeated, or
given a value it must not have — invalidates the whole header.

`preload` is not defined by RFC 6797. It is a convention for submission to the
browser preload lists, checked only when a profile asks for it.

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
| `same-origin` | OK | Only a same-origin document sending it shares a browsing context group — optimal |
| `same-origin-allow-popups`, `noopener-allow-popups` | LOW | A window they open that sends no COOP of its own keeps a reference back to this document |
| `unsafe-none` | MEDIUM | Any document that opens this one keeps a reference to it — no XS-Leak protection |
| Anything a browser cannot apply | Same as absent | No policy applies, so the response is where it would be with no header |

**What the header may contain.** COOP is a structured field of type *item* (HTML
§7.1.3.1): a single token, which may carry parameters — of these only `report-to`
is defined, and no parameter decides which policy applies. So
`same-origin; report-to="coop-endpoint"` is plain `same-origin` and is graded as
such.

**When a browser cannot apply the value.** Anything else leaves the policy at the
`unsafe-none` default, which is the same position as sending no header at all —
and nothing in the response says so. That covers four cases:

- a token no browser recognises, such as `bogus`
- `same-origin-plus-COEP`, which is not settable here: it is the *result* of
  `Cross-Origin-Opener-Policy: same-origin` together with a
  `Cross-Origin-Embedder-Policy` compatible with cross-origin isolation
- a value that is not a token followed by valid parameters — `same origin`,
  `"same-origin"`, or a `;` with no parameter name after it (RFC 8941 §4.2.3.2)
- the header sent more than once: a browser joins the occurrences with a comma,
  and RFC 8941 §4.2 fails parsing when anything follows the first item, so **two
  COOP headers cancel each other out — including two identical ones**

**What the two `*-allow-popups` values give up.** Both keep the protection COOP
mainly exists for: no cross-origin document can open this one into an existing
browsing context group, so an attacker cannot open the page and probe it through
the returned window. What they give up is the other direction — per the
`Window.open()` table in HTML §7.1.3.1, a window this document opens stays in its
group if that window sends no COOP of its own, and so keeps a `window.opener`
reference back.

Whether that costs anything here depends on something the response cannot say: if
the document opens only an OAuth or payment provider it chose, the other party is
trusted and this is the value to use. The finding therefore carries **the check to
run** — what does this document pass to `window.open()`? — rather than a change to
make blindly. It is still an issue and still reaches `--format list`, because only
`same-origin` closes both directions and the reader is the one who can settle the
condition in a few seconds.

The two differ only in a direction that does not change this. `noopener-allow-popups`
is *stricter* about being opened than either of the others: only a same-origin
document sending the same value can navigate to it without a group switch, and
through `window.open()` it is always a new group, whoever the opener is. It is
weaker in the other direction, though, and the algorithm says so directly: in
*check if popup COOP values require a browsing context group switch*, the step
that keeps an opened `unsafe-none` window in the opener's group applies when the
opener is `same-origin-allow-popups` **or `noopener-allow-popups`** — and not
when it is `same-origin`. So the two are not ordered against each other, while
against `same-origin-allow-popups` it is better or equal on both directions. What it does not do is provide cross-origin isolation, which
needs `same-origin` plus COEP. Since the exposure that keeps a value out of OK is
the outgoing one, and that is identical for both, they carry one verdict.

---

### Referrer-Policy

**Required:** yes — **Severity if missing:** MEDIUM

The `Referer` header tells every destination a page reaches — a CDN serving a
font, an analytics endpoint, a site the user clicks through to — which URL the
request came from. URLs carry password-reset tokens, search queries, internal
paths and record identifiers, so what the policy discloses is what those parties
get to write in their logs.

**What the grading follows.** Only what leaves the site counts: how a policy
behaves on a *same-origin* request is not a criterion, because that recipient
served the URL in the first place. Among what does leave, the deciding question
is whether a **path or query string** escapes, since that is where tokens and
internal structure live. The identity of the site on its own is a much smaller
disclosure — and one every value graded OK below already makes.

| Value | Severity | What leaves the site |
|---|---|---|
| `no-referrer`, `same-origin` | OK | Nothing |
| `strict-origin`, `strict-origin-when-cross-origin` | OK | The origin, and only to TLS-protected destinations |
| `origin`, `origin-when-cross-origin` | LOW | The origin, to plain-HTTP destinations as well |
| `no-referrer-when-downgrade` | **HIGH** | The full URL, to every destination reached over HTTPS |
| `unsafe-url` | **HIGH** | The full URL, to plain-HTTP destinations as well |
| Anything else | Same as absent | Nothing — no policy is applied at all |

Values are paired where they differ only in same-origin behaviour, which the
grading ignores: `no-referrer` and `same-origin` disclose nothing outside the
site whatever they do inside it, and the same holds for the other two pairs.

**Why the plain-HTTP destinations decide one pair and not the other.** The
severity is set by the worst thing that leaves. For the full-URL pair the HTTPS
destinations already put both at the top — the token reaches a third party's logs
either way — so where else the URL goes cannot raise them any further, and
`unsafe-url` is the worse of the two in its description rather than in its level.
For the origin pair the HTTPS destinations are harmless, since the values graded
OK disclose exactly the same thing to exactly the same recipients; the plain-HTTP
destinations are the only difference left, so they are what the pair is graded on.

Whether that difference costs anything depends on whether the page reaches a
plain-HTTP destination at all, which the response does not say — so the finding
carries that check. It is still an issue rather than a note, because the pair
gives up strictly more than `strict-origin-when-cross-origin` and gets nothing
back: over HTTPS the two behave identically, so there is no case in which the
weaker value is the one a site needs.

**Absent, or set to something the grammar does not define.** The header defines
eight tokens and nothing else; a browser skips an unknown one and applies its own
default, which is exactly what it does when no header arrives. The two cases are
graded alike, so an unrecognised value carries whatever severity a missing header
carries in the active profile. That severity is MEDIUM by default because the
outcome is genuinely uncertain: current browsers apply
`strict-origin-when-cross-origin`, graded OK above, older ones apply
`no-referrer-when-downgrade`, graded HIGH — and a site that states no policy has
chosen neither of them. An unrecognised value is the worse of the two in one
respect: it looks like a policy, so nothing in the response reveals that none is
in force.

---

### Cross-Origin-Embedder-Policy

**Required:** no (basic) — **Severity if missing:** INFO

| Value | Severity | Rationale |
|---|---|---|
| `require-corp` | OK | Cross-origin no-cors resources must opt in through CORP or CORS |
| `credentialless` | OK | They load without opting in, but with no credentials, so they carry nobody's private data |
| `unsafe-none`, and anything a browser cannot apply | Same as absent | One browser state — see below |

**What the header may contain.** COEP is a structured field of type *item*, the
same shape as COOP: a single token, optionally carrying a `report-to` parameter
that never decides which policy applies. So `require-corp; report-to="coep"` is
plain `require-corp`.

**Every way of not having COEP is one state.** `unsafe-none` is the value a
browser applies when the header is absent, so stating it explicitly changes
nothing. A value that cannot be parsed or is not recognised ends in the same
place — the spec says the processing model *"fails open (by defaulting to
unsafe-none)"* — and so does a header sent twice, which MDN puts plainly:
*"Setting the header more than once or with multiple tokens is equivalent to
setting `unsafe-none`."* All of them are graded as an absent COEP, because that
is what the response amounts to.

**Why not having COEP is graded far below the equivalent for COOP.** Not having
COEP is not an exposure. It withdraws a capability rather than opening anything:
without cross-origin isolation the browser refuses `SharedArrayBuffer` and
unthrottled timers instead of allowing them over resources that never consented.
A COEP that silently fails to apply therefore breaks a feature, not a boundary —
the site notices, and nothing is at risk in the meantime. A COOP that silently
fails to apply leaves a document open to being probed by anything that opens it,
with nothing to reveal that the protection is gone.

**`credentialless` is not a weaker `require-corp`.** Both qualify a document for
cross-origin isolation. They differ in mechanism: `require-corp` demands that
every cross-origin no-cors resource opt in, while `credentialless` lets it load
but strips the credentials, so it cannot contain private data in the first place.
Neither overrides a CORP header the resource already sets. Same guarantee, two
routes to it.

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

**Required:** no in `--context public`, yes in `--context authenticated`

This is the one header whose *correct* value depends on what the response
carries, which is why HSHA asks rather than guesses. `public, max-age=31536000`
is right for a static asset and wrong for an account page; there is no single
verdict that serves both.

Two audiences matter, and confusing them is where the damage comes from: the
**browser**, which writes to the user's disk, and **shared caches** — CDNs,
proxies, gateways — which keep one copy and hand it to whoever asks next.

#### Assuming a response carrying a signed-in user's data (the default)

Only `no-store` keeps such a response out of every cache.

| Value | Severity | Rationale |
|---|---|---|
| `no-store` | OK | Nothing is stored anywhere |
| `private` | LOW | Shared caches will not store it, so it cannot reach another user — but the browser still writes it to disk, where the back button after logout, or the next person on that machine, can recover it |
| `no-cache` | MEDIUM | Forces revalidation before reuse; it does **not** prevent storage. A shared cache may keep this user's response, and nothing marks it as belonging to one user. `max-age=0` with `must-revalidate` is graded the same, being the same round trip |
| Anything else that a shared cache may store | **HIGH** | A CDN or proxy may keep the response under this URL and serve it to the next person who asks — one user's data handed to another. Covers `max-age`, `s-maxage`, `public`, and the qualified forms `private="Field"` / `no-cache="Field"`, which cover only the fields they name |
| Absent, or no token a cache understands | MEDIUM | With no instruction, caches fall back to heuristic freshness and may store it anyway. A value made only of unrecognised tokens says nothing either, so it is graded the same |

#### Assuming a response carrying nothing user-specific (`--context public`)

| Value | Severity | Rationale |
|---|---|---|
| `no-store`, `no-cache`, `private` | OK | Conservative, and harmless here |
| Only standard directives | OK | Ordinary caching of public content |
| `public` | INFO | Shared caches allowed — worth confirming that is intended |
| `no-cache="Field"`, `private="Field"` | INFO | The qualified form covers only the fields it names, so the rest of the response is served from cache; much weaker than the bare directive |
| A token that is not a standard directive | INFO | Likely a typo or a vendor extension; caches ignore it |
| Absent | INFO | Heuristic caching applies, which is unremarkable for public content |

#### Why only this header takes the flag

For nearly every other header the right value does not depend on the context —
`nosniff` is right either way, and `unsafe-inline` is wrong either way. What
changes is how much the mistake costs, not what the fix is. Caching is different:
the same value is correct in one setting and a data leak in the other, so a
single verdict would have to be wrong half the time.

`Access-Control-Allow-Origin: *` looks like it belongs here and does not.
Browsers refuse the wildcard together with credentials, so a cross-origin read of
an authenticated response is blocked whatever this flag says. What makes the
wildcard dangerous is whether the endpoint is reachable at all from outside —
a question about network position, not about authentication.

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

**Required:** yes — **Severity if missing:** LOW *(the same state a policy that
closes none of the any-origin features leaves — see below)*

| Condition | Severity | Rationale |
|---|---|---|
| A feature whose default is this origin only, widened to `*` | MEDIUM | The policy is granting access rather than restricting it: any embedded document gains a capability a browser was withholding |
| A tracking feature still reachable by an embedded document | INFO | The user's privacy toward a party the site chose to embed — often what that party was embedded to do |
| `camera`, `microphone` or `geolocation` not set to `()` | LOW | Script that achieves execution here can raise their permission prompt, and the prompt names the site rather than the code that asked |

**Two questions, asked separately.** The header answers one thing for documents
the page embeds and a different thing for script running on the page's own origin,
and a value can close one without closing the other. Grading them as one number
loses that, so they are reported as two findings.

**The first axis: what an embedded document can reach.** Every directive has a
default a browser applies when the policy does not name it, always `*` or `self`.
Only nine default to `*`, and six of those are worth reporting —
`attribution-reporting`, `browsing-topics`, `ch-ua-high-entropy-values`,
`private-state-token-issuance`, `private-state-token-redemption`,
`storage-access` — because what an embedded document gains from them is tracking
and fingerprinting surface. The remaining three, `gamepad`, `picture-in-picture`
and `deferred-fetch-minimal`, are open the same way with nothing behind them, so
they are stated in the finding but kept out of its title.

Everything else — `camera`, `payment`, `usb`, `display-capture` and the other
thirty-six — defaults to `self`. An undeclared `camera` does **not** let an
embedded third party reach the camera: a browser was never going to allow that,
and the `allow` attribute on an iframe can only narrow what the parent already
grants, never widen it.

This axis is stated and not counted as a defect. What it describes is the user's
privacy toward parties the site deliberately embedded, and for an advertising or
analytics frame, reading the user's topics and registering attributions is the
reason the frame is there — `browsing-topics=()` would break what the site
installed on purpose. It earns a look in the opposite case: a frame embedded for
something else entirely, a chat widget or a video player, that picks these
capabilities up along the way because nothing took them away. The response cannot
say which of the two it is, so the finding carries that question.

**The second axis: what an XSS on this origin can reach.** A permission prompt
names the site, never the code that asked for it. A user looking at *"example.com
wants to use your camera"* while using example.com has no way to tell a genuine
request from injected script, and grants it. So the exposure does not depend on
the origin already holding a stored grant — script that reaches execution here
can go and ask, and one click is the whole interaction.

That is true of `camera`, `microphone` and `geolocation`. It is not true of the
features whose prompt is followed by a choice: `display-capture` makes the user
pick what to share, `usb`, `serial`, `hid` and `bluetooth` make them pick a
device, `payment` opens a payment flow. There the consent is informed about *what*
and not only about *who*.

Only `()` closes this axis. `(self)` authorises this origin, and an XSS runs on
this origin — reading a declared `camera=(self)` as "handled" would be a
reassuring falsehood. The reverse holds on the first axis, where `(self)` is
enough because it excludes every other origin.

A site that genuinely uses one of the three can still close it on every response
that does not, since the header is per-response; the finding asks that rather than
assuming it.

**A widened feature is read from its allowlist**, not searched for in the raw
value: `x-payment=*` is a different feature from `payment`, and `camera=(self)`
restates the default rather than opening anything.

**Sending no header at all** leaves both axes open, which is the same position as
a policy that closes neither — so it carries the same severity, and a response
that declares an unrelated feature does not appear to have improved its standing.
The absent-header finding states both axes and names both sets.

**On publishing a list of every feature to disable.** Advice of that shape — set
all of them to `()` — is sound for whoever configures the site. It is a poor basis
for a verdict, and a fixed list goes stale in the place that matters: one widely
circulated version names `interest-cohort`, a directive for a feature its browser
removed, and covers two of the nine any-origin directives while covering
twenty-one of the forty that default to `self`. It is thorough on the axis that
needs an XSS to matter and nearly silent on the axis that needs nothing else at
all — because the any-origin APIs mostly postdate it.

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
| `attachment` (with any parameters) | OK | Download forced — prevents inline execution |
| `inline` (with any parameters) | OK | Browser renders the content inline; benign in itself, but `attachment` is safer for file downloads |
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

The value is a flag (`0` or `1`) optionally followed by directives, and only the
flag decides the verdict — a digit inside a directive such as `report=1` is not
one.

| Value | Severity | Rationale |
|---|---|---|
| `0` (with or without trailing directives) | OK | The filter is off, which is the recommended setting; `mode=block` is irrelevant once it is |
| `1` | LOW | Enables the filter — see below |
| `1; mode=block` | LOW | Enables the filter in its leakiest mode — see below |
| Any other value | INFO | Deprecated header, not doing anything risky |

**Why enabling it is worse than disabling it.** The filter compared text from the
URL against the scripts in the response and could not tell whether a matching
script was injected or belonged to the page. Two consequences:

- With `1`, an attacker could craft a URL that made the browser neutralise a
  script the page legitimately contains — an anti-CSRF or framebusting script,
  for example. The filter becomes a remote control for switching off a site's own
  defences.
- With `1; mode=block` the page is not rendered at all when the filter triggers,
  and whether it was blocked is observable from another origin. That turns "does
  this page contain script X?" into a yes/no answer readable cross-origin, and
  repeating it with different scripts reveals whether the user is signed in, is
  an administrator, and so on.

Both stay LOW because no current browser honours the header: Chrome removed the
auditor in 2019, Safari and Edge dropped theirs, and Firefox never had one.

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
