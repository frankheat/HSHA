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

Severity is what a finding is worth **if it applies to this target**. Whether it applies is a separate question, and for some checks a saved response cannot settle it: whether the page uses the camera, whether this endpoint returns a signed-in user's data, whether an allowlisted origin was echoed back rather than configured.

Those findings are written **`? LOW`** in the tables below — the same mark the report puts beside them — and they carry the check that settles them and what each outcome means. The severity states the case the response cannot rule out, so a `? CRITICAL` is not a verdict: it is what the reader will be looking at if the check comes back positive, and nothing at all if it does not.

No severity reaches the process exit status, which only reports whether the analysis could be run at all.

---

## General Checks (all headers)

These checks apply to every header before any value-specific logic runs.

| Condition | Severity | Rationale |
|---|---|---|
| Header absent + required | Per-header default | Missing required security header |
| Header absent + optional | INFO | Absent but not mandatory in current profile |
| Header absent, and absence is the right state | OK | `X-XSS-Protection` and `Expect-CT` are not to be sent at all; no CORS headers means same-origin only. Nothing is reported — see their sections |
| Header present, value is empty | Same as absent | Browsers ignore a header with no value, so the impact is identical to not sending it. Reported under its own title because an empty value usually means a misconfigured template or proxy |
| Header sent more than once, values combine | **NOTE** | Nothing is lost: the occurrences merge, or they were identical to begin with |
| Header sent more than once, one value discarded | **LOW** | A misconfiguration — see below |

An optional header that is absent is reported at INFO. Where a specific
recommendation exists for that header it is shown anyway — that is precisely
where the finding would otherwise say nothing beyond repeating its own title.
Marking such a header `required: true` in a profile switches it to the per-header
severity in the tables below.

Four headers are exempt because absence is the state to be in. Two are
deprecated and should not be sent at all. The other two are the CORS pair: with
neither of them the response is readable only same-origin, which is the secure
default — a response that needed CORS and lacks it is broken, not exposed.
Reporting any of the four as *missing* would name a deficiency on every correctly
configured response, and those checks exist for the responses that do send
them.

### Duplicate headers

When a header appears multiple times in the response, HSHA resolves the
effective value the same way browsers do, then evaluates that value:

| Strategy | Headers | Behavior |
|---|---|---|
| Join | `Content-Security-Policy`, `Cache-Control`, `Clear-Site-Data`, `Permissions-Policy`, `Pragma`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, `Referrer-Policy`, `X-Frame-Options` | Occurrences combine into a single value |
| Identical values | any other header | Collapsed to the single value |
| First wins | default (e.g. `Strict-Transport-Security`, RFC 6797 §8.1) | First occurrence is evaluated |

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

Under **first** one occurrence wins and the others are discarded. That is a misconfiguration: two components disagree — typically the
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
| `max-age=0` | Same as absent | Browsers delete the entry, so the site has no HSTS. It is the documented way to turn HSTS off, so it may be deliberate; either way the other directives are not reported, since there is no policy left for them to qualify |
| `max-age` < threshold *(default: 31536000s / 1 year)* | MEDIUM | Short values reduce protection window against SSL-stripping |
| `includeSubDomains` missing *(configurable)* | MEDIUM | A plaintext channel on any host under the domain reaches the protected site's cookies — see below |
| `preload`, declared or not *(extended profile only)* | ? LOW | Whether the domain is on the preload list is a separate fact the response cannot show — see below |

**Why a missing `includeSubDomains` does not depend on having subdomains.** The
reading it invites — *we have none, so it does not apply to us* — is the wrong
one, and it is why this is graded above a remark.

HSTS covers the host that sent it. A host that does not exist is not covered
either, and the attacker is the one who picks the name. With network position they
answer for `anything.example.com` over plain HTTP, and from that origin they set
cookies with `Domain=example.com`, which the browser then sends to the protected
site. Cookies are scoped by domain, not by origin, which is what carries the
attack across. Browsers no longer allow such an origin to overwrite an existing
`Secure` cookie, but injecting a new one — session fixation — or shadowing one on
another path still works, and the same channel serves a convincing page on a
plausible hostname.

It sits below the severity of a missing header because the protected host itself
stays protected: what is reachable is the domain around it.

Directive names are matched as names, not searched for in the value. A
misspelling such as `includeSubDomainss`, or the word appearing inside another
directive's value, counts as the directive being missing — which is what a
browser does too, since it ignores a directive name it does not recognise. Note
the asymmetry the RFC draws: an *unrecognised* directive is skipped and the rest
of the header still applies, but a *recognised* one used wrongly — repeated, or
given a value it must not have — invalidates the whole header.

**`preload` is graded either way, and neither way is settled by the response.**
It is not defined by RFC 6797: it is what a domain must send to be *accepted* onto
the browser preload lists, not what puts it there. Submission at
`hstspreload.org` is a separate step, and it can be refused or reversed.

So a header carrying `preload` proves nothing, and one without it may belong to a
domain that is listed anyway. Both are reported at the same level, because if the
domain is not on the list they leave the site in the same place: carrying the one
gap HSTS cannot close on its own — the first request to the domain, made before
the browser has ever seen the site, goes out over plain HTTP and can be stripped
by anyone on the network path.

One lookup settles both. Declining to preload is also a reasonable decision — it
is hard to undo and covers every subdomain — which is a fact to record rather than
a defect to report, and is why the finding asks rather than tells. The check runs
only when a profile opts in.

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
| `DENY` | OK | Nothing can frame the page |
| `SAMEORIGIN` | ? LOW | Another page on this origin can still frame it — see below |
| More than one value, at least one usable | NOTE | The browser refuses the frame rather than guess: framing is blocked, so this is stated and not graded — see below |
| `ALLOW-FROM ...`, or anything else | Same as absent | No browser applies either, so the page is framable — see below |

**The values are read as a set.** HTML's *check a navigation response's adherence
to `X-Frame-Options`* lowercases each comma-separated value into a set, and then:
if the set holds more than one entry **and** any of them is `deny`, `allowall` or
`sameorigin`, the frame is refused — *"any attempts at applying X-Frame-Options
which were trying to do something valid, but appear confused"*. Only when every
entry is unusable does framing go ahead. Two consequences:

- `DENY, DENY` is one entry, and blocks. Repeating the value — which is what a
  proxy appending to the header produces — changes nothing.
- `DENY, SAMEORIGIN` blocks too, and so does `SAMEORIGIN, anything`.

A contradiction is reported as a **note**, not as a weakness, and the reason is
worth stating: it can only ever be *stricter* than the values it is made of.
`ALLOWALL, bogus` blocks, where either value on its own would let the page be
framed. The outcome is the strongest one available, and it is the same in every
browser, so there is nothing here to grade. What is left is a deployment fact —
whichever component set the ignored value is working on a false assumption, and
two components writing this header may be writing others.

Repeated headers are joined with a comma before that split, so they take the same
path — including two unusable values, which leave the page framable.

**Why `SAMEORIGIN` is not graded as clean.** A browser walks *every* containing
document and refuses as soon as one is cross-origin, so it is as strong as
`frame-ancestors 'self'`. What it still permits is a page on this same origin. It
costs something where an attacker can put markup on one and not run script there —
a stored HTML injection on an origin whose CSP stops short of script execution:
they cannot read anything through the frame, but they can overlay it, which `DENY`
would have prevented outright. Whether that is worth anything depends on whether
some page here needs to frame this one, which the response cannot say.

**Why an unusable value is graded like no header at all.** A browser applies this
header for `DENY` and `SAMEORIGIN` and nothing else. `ALLOW-FROM` is the case
worth spelling out: no current browser implements it, and none of them ignore
just the directive and keep the rest — they discard the whole header. A response
carrying it is exactly as framable as one carrying nothing, with the difference
that it looks like a policy is in force.

**When the CSP gives the framing decision away.** The step above is unconditional:
a browser stops reading `X-Frame-Options` as soon as an *enforced* policy carries a
`frame-ancestors` directive, whatever that directive says. So `DENY` beside
`frame-ancestors *` protects nothing but the browsers too old to implement CSP,
and this header's own verdict, read alone, is reassurance the response has not
earned. An INFO finding is added to say so. The exposure itself stays graded on
the `Content-Security-Policy` row, once — a report-only policy does not trigger
this, since the algorithm skips policies whose disposition is not "enforce".

**Set this header even when the CSP already declares `frame-ancestors`.** The two
overlap — CSP Level 3 §6.4.2.2 states that `frame-ancestors` *overrides* the
`X-Frame-Options` header, and `'none'` and `'self'` are its equivalents of `DENY`
and `SAMEORIGIN` — but the overlap is only in browsers that implement CSP
`frame-ancestors`. Older ones, IE11 among them, implement none of it and take
`X-Frame-Options` as the only instruction they will get. So a response carrying
only the CSP directive is reported as missing this header, and that is not a
false alarm: it names the browsers left uncovered.

---

### X-Content-Type-Options

**Required:** yes — **Severity if missing:** MEDIUM

| Value | Severity | Rationale |
|---|---|---|
| `nosniff` | OK | The browser honours the declared `Content-Type` instead of guessing |
| Anything else | Same as absent | The protection is not on, which is where a response with no header already is |

**Only the first value counts.** Fetch's *determine nosniff* splits the header on
commas, strips spaces around each part, and compares **`values[0]`** — ASCII
case-insensitively — against `nosniff`. Two consequences that are easy to get
backwards:

- `nosniff, anything` **is** protected. A proxy that appends to the existing header
  rather than adding a second line produces exactly this, and reporting it as
  unprotected would be a false alarm.
- `anything, nosniff` is **not** protected. The token being present somewhere in
  the value means nothing.

A quoted string is collected with its quotes still attached, so `"nosniff"` does
not match and the protection stays off — unlike `Strict-Transport-Security`, where
RFC 6797 does allow the quoted form. The two headers differ here, and copying the
habit from one to the other silently disables this one.

Sent more than once, the occurrences are joined with a comma before that split, so
the first occurrence decides — which is what the default duplicate strategy
already evaluates.

---

### Cross-Origin-Opener-Policy

**Required:** yes — **Severity if missing:** MEDIUM

| Value | Severity | Rationale |
|---|---|---|
| `same-origin` | OK | Only a same-origin document sending it shares a browsing context group — optimal |
| `same-origin-allow-popups`, `noopener-allow-popups` | ? LOW | A window they open that sends no COOP of its own keeps a reference back to this document |
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
trusted and this is the value to use. What settles it is what this document passes
to `window.open()`. It is still graded as a weakness, because only `same-origin` closes
both directions and the reader is the one who can settle the condition in a few
seconds.

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

### Permissions-Policy

**Required:** yes — **Severity if missing:** LOW *(the same state a policy that
closes none of the any-origin features leaves — see below)*

| Condition | Severity | Rationale |
|---|---|---|
| A feature whose default is this origin only, widened to `*` | MEDIUM | The policy is granting access rather than restricting it: any embedded document gains a capability a browser was withholding |
| A tracking feature still reachable by an embedded document | ? INFO | The user's privacy toward a party the site chose to embed — often what that party was embedded to do |
| `camera`, `microphone` or `geolocation` still reachable by this origin | ? LOW | Script that achieves execution here can raise their permission prompt, and the prompt names the site rather than the code that asked |

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
say which of the two it is.

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

This axis is closed whenever the allowlist does not grant the feature to this
origin. `()` closes it entirely; naming only external origins —
`camera=("https://video.trusted.com")` — does the same for this origin while
still granting it to the named party. `(self)` authorises this origin, and an XSS
runs on this origin — reading a declared `camera=(self)` as "handled" would be a
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
| `origin`, `origin-when-cross-origin` | ? LOW | The origin, to plain-HTTP destinations as well |
| `no-referrer-when-downgrade` | **HIGH** | The full URL, to every destination reached over HTTPS |
| `unsafe-url` | **HIGH** | The full URL, to plain-HTTP destinations as well |
| No token a browser recognises | Same as absent | Nothing — no policy is applied at all |

**The header is a list, and the last valid token wins.** W3C Referrer Policy §8.1
walks every comma-separated token and keeps the last one that names a policy;
empty and unknown tokens are **skipped**, not treated as errors. The spec's own
note explains why the loop is there: so a site can write
`no-referrer, strict-origin-when-cross-origin` and have an older browser take the
first and a current one the second. A list is the recommended shape, not a
mistake, and only the token that survives the walk is graded.

Two consequences run in opposite directions. `bogus, no-referrer` is `no-referrer`
and clean. `strict-origin-when-cross-origin, unsafe-url` is **`unsafe-url`** —
naming a strong policy first protects nothing. Repeated headers are concatenated
before the walk, so they take the same path: the last *valid* token wins, which is
not always the last occurrence.

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
plain-HTTP destination at all, which the response does not say. It is still an
issue rather than a note, because the pair
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

**Required:** yes — **Severity if missing:** MEDIUM

Two audiences matter, and confusing them is where the damage comes from: the
**browser**, which writes to the user's disk, and **shared caches** — CDNs,
proxies, gateways — which keep one copy and hand it to whoever asks next.

This is the one header whose *correct* value depends on what the response
carries: `public, max-age=31536000` is right for a static asset and a data leak
on an account page. HSHA grades the case where caching costs something, and every
verdict but `no-store` turns on one question — does this response carry data
belonging to a signed-in user? On a response that carries nothing user-specific
there is nothing here, and `no-store` would only cost bandwidth, which is why it
is the one value that needs no question.

**How the user was identified changes the answer.** The verdicts below describe a
shared cache handing one user's response to another, which is what happens when
the session lives in a **cookie**: nothing in the caching rules knows about
cookies. A request authenticated with an **`Authorization` header** is different —
RFC 9111 §3.5 bars a shared cache from reusing such a response at all, *unless*
the response carries one of exactly three directives: `must-revalidate`, `public`
or `s-maxage`. On that kind of endpoint the shared-cache half of the finding falls
away and what remains is the browser's own disk, which is the `private` case — and
the three directives above become the ones to look for, `must-revalidate` most of
all, since it reads as caution and is a permission.

| Value | Severity | Rationale |
|---|---|---|
| `no-store` | OK | Nothing is stored anywhere, and right either way — the only verdict that needs no question |
| `private` | ? LOW | Shared caches will not store it, so it cannot reach another user — but the browser still writes it to disk, where the back button after logout, or the next person on that machine, can recover it |
| `no-cache` | ? MEDIUM | Forces revalidation before reuse; it does **not** prevent storage. A shared cache may keep the response, and nothing marks it as belonging to one user. `max-age=0` with `must-revalidate` is graded the same, being the same round trip |
| Anything else a shared cache may store | ? **HIGH** | A CDN or proxy may keep the response under this URL and serve it to the next person who asks — one user's data handed to another. Covers `max-age`, `s-maxage`, `public`, and the qualified forms `private="Field"` / `no-cache="Field"`, which cover only the fields they name |
| Absent, or no token a cache understands | ? MEDIUM | With no instruction, caches fall back to heuristic freshness and may store it anyway. A value made only of unrecognised tokens says nothing either, so it is graded the same |

**Why the question is asked in the finding rather than answered up front.** An
earlier version took it as a flag: the reader declared what the response carried
and the grading followed. That put the work before the report, at a point where
the reader may not yet know, and it produced a verdict that looked settled either
way. Carrying the question instead states the worse case, says plainly what
would dismiss it, and leaves the answer where the evidence is.

**`Access-Control-Allow-Origin: *` looks like it belongs in the same family and
does not.** Browsers refuse the wildcard together with credentials, so a
cross-origin read of an authenticated response is blocked regardless. What makes
the wildcard dangerous is whether the endpoint is reachable at all from outside —
a question about network position, not about authentication.

---

### Clear-Site-Data

**Required:** no — **Absent:** ? INFO *(right on almost every response — see below)*

| Condition | Severity | Rationale |
|---|---|---|
| Contains `"*"` | OK | Every type cleared |
| `"cache"`, `"cookies"` and `"storage"` all present | OK | The three a browser acts on everywhere |
| One or more of those three missing | ? LOW | Incomplete clearing — residual data outlives the session |
| No value matches a type at all | ? LOW | Nothing is cleared, while the response looks like it clears something |
| Absent | ? INFO | Nothing is cleared, and the response never said otherwise |

**One question governs all of them: does this response end something?** A logout, a
password change, an account deletion. This header has no job anywhere else —
clearing a visitor's storage on an ordinary page would itself be the defect — and
which response is which lives in the request and the application, not in the
headers. So every verdict but a complete policy carries that question, and none of
them is stated as settled.

That is also why an absent header is not treated the way the other
absence-is-correct headers are. `X-XSS-Protection` and the CORS pair should never
be sent at all; this one should be sent on exactly one kind of response, and the
tool cannot tell whether it is looking at that one. Absence ranks below a header
that is present and clears nothing: sending nothing is not a mistake, sending
something that does nothing is.

**The quotes are part of the value.** The grammar is `1#( quoted-string )`, and
§4.1 switches on each extracted value *with its quotes still attached*: `"cache"`,
not `cache`. A token that matches no branch is passed over — §3.1 requires it
("User agents MUST ignore unknown types when parsing the header") — so an
unquoted value does not fail the header, it simply contributes nothing.

That makes `Clear-Site-Data: *` a header that clears **nothing**, which is the
reason the last row exists: it looks like the strongest possible value and is the
emptiest.

**Why three values are asked for out of eight.** The specification's switch names
five types plus the wildcard, and Chromium ships two more that are not in it at
all. What separates them is not the specification but what a browser does today:

| Value | In the spec | Implemented today |
|---|---|---|
| `"cookies"` | yes | every browser, since 2018 |
| `"storage"` | yes | every browser, since 2018 |
| `"cache"` | yes | Chrome/Edge 127, Firefox 138, Safari 17 |
| `"*"` | yes | Firefox and Safari throughout; **Chrome/Edge only from 127** |
| `"clientHints"` | yes | Chrome/Edge 117 only |
| `"executionContexts"` | yes | **nowhere** — Firefox carried it 63→68, Safari 17→18.3, both withdrew it |
| `"prefetchCache"` | no | Chrome/Edge 138 |
| `"prerenderCache"` | no | Chrome/Edge 138 |

Only the first three are asked for. All eight are **recognised**, so naming any of
them is never mistaken for naming nothing — the sign-out example in the browser
documentation carries five of them, and it is clean.

`"executionContexts"` is the one worth knowing about: it is what *would* reload
the browsing contexts still open when the session ends, it is in the
specification's own sign-out example, and two browsers implemented it and took it
back out. A tab left open at logout keeps running with whatever it holds in
memory, and no value in this header changes that today.

Two dates are worth keeping in mind when a response leans on one value alone.
`"*"` did nothing on Chrome and Edge before version 127, so a site relying on the
wildcard was clearing nothing there until mid-2024. And `"cache"` carries open
caveats on Chromium — some requests are still served from the cache unless the tab
is reloaded, and setting it can hang the page for seconds — so it is the least
dependable of the three.

---

### X-DNS-Prefetch-Control

**Required:** no — **Severity if missing:** INFO *(LOW in extended profile)*

| Value | Severity | Rationale |
|---|---|---|
| `off` | OK | DNS prefetching disabled |
| Any other value | INFO *(LOW in extended)* | The browser resolves domains linked in the page before any navigation. Two things follow: the DNS resolver learns every hostname the page references — internal services, private subdomains, admin panels — whether or not the user navigates there. And an attacker with HTML injection can exfiltrate data through `<link rel=dns-prefetch>`, which resolves before CSP checks apply and so is not stopped by `script-src`, `img-src` or `connect-src` restrictions |

---

### Access-Control-Allow-Origin

**Required:** no — **Absent:** OK *(no CORS headers means same-origin only, which is the secure default)*

| Value | Severity | Rationale |
|---|---|---|
| `*` | ? **HIGH** | Any site can read the response — see below |
| `null` | **HIGH** | Forgeable by any attacker and, unlike `*`, usable with credentials — see below |
| More than one origin (`https://a.example, https://b.example`) | INFO | The header carries exactly one origin, `*` or `null`. A list never matches the requesting origin, so the CORS check fails and no site gets access, including the intended ones. Fails closed, so it is a broken configuration rather than an exposure. Usually means two components are both setting the header — typically the application and a proxy in front of it |
| `http://` origin | LOW | The allowed origin is not protected by TLS, so anyone able to tamper with traffic to it can impersonate it and read what this endpoint returns to it. A `localhost` origin here usually means a development configuration reached production |
| Specific `https://` origin | ? **HIGH** | An allowlist and a mirror of the request's `Origin` are the same bytes — see below |

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
the header, not where the endpoint lives or what the body holds. It therefore
grades the case it cannot rule out — reaching a network through a victim's
browser is a data exposure, not a configuration blemish. What settles it is
whether the endpoint is reachable from anywhere or only from certain networks; on
a genuinely public one there is nothing here.

#### A single origin is graded as the case it cannot be told apart from

One origin authorised is how CORS is meant to be used, and most responses that
carry it are correct. But a server that copies the request's `Origin` header into
the response produces exactly this header, and then the authorised origin is
whichever one asked — any site reads what the endpoint returns, which is `*` by
another route.

A saved response cannot tell the two apart, so the finding states the case it
cannot rule out and carries the replay that settles it: send the request again
with an invented `Origin`. If it comes back, the origin is reflected. If the
header keeps naming the original origin, or disappears, the allowlist is real and
there is nothing here.

With `Access-Control-Allow-Credentials: true` alongside, the same reflection is
graded again on that header and at CRITICAL, because then what any site reads is
the logged-in user's data rather than whatever is served unauthenticated. One
replay settles both.

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

**Required:** no — **Absent:** OK *(nothing to send, so nothing to grade)*

`true` means "send the cookies", which says nothing on its own — it matters who
receives them. This header is therefore graded against
`Access-Control-Allow-Origin`, and carries a single verdict:

| Access-Control-Allow-Origin | Severity | Rationale |
|---|---|---|
| `null` | **CRITICAL** | The null origin is forgeable by any page and is a concrete origin, so cookies are sent with it: an attacker's page reads this endpoint as the logged-in user |
| `*` | INFO | Browsers refuse the wildcard together with credentials, so every credentialed request is rejected. Nothing is exposed by the combination itself — it is a functional contradiction, not a weakness, and the wildcard's own effect on non-credentialed requests is graded on `Access-Control-Allow-Origin` |
| A specific origin | ? **CRITICAL** | Indistinguishable from a reflected `Origin`, which hands authenticated responses to any site — see below |
| Absent | INFO | No origin is authorised to read the response, so credentials change nothing; usually a leftover |
| Not evaluated (excluded by the profile) | INFO | Stated explicitly, because silence would read as approval |

`false` is OK regardless of the origin.

**Why a specific origin carries the weight of the reflected case.** A response
that echoes back the request's `Origin` header is byte-for-byte identical to one
that allowlists that origin, and HSHA analyses a single saved response — it never
issues requests, so it cannot tell them apart. If it is reflection, the outcome is
the `null` case reached more easily: no sandboxed iframe or `data:` URL needed,
just a page on the attacker's own domain.

Severity states what the finding is worth if it applies, so it states that. What
settles it is a replayed request carrying an invented `Origin`: if it comes back,
the server reflects; if it does not, the allowlist is real, this is correct
authenticated CORS, and there is nothing here. An earlier version
graded it INFO on the grounds that a one-off verification should not fail a build;
that reasoning went with the exit code, and it had the tool printing a note that
the reader was expected to re-grade by hand.

---

### X-XSS-Protection *(deprecated)*

**Required:** no — **Absent:** OK *(not sending it is the correct state)*

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

## Headers — Extended Profile Only

The following headers are checked only when using `profiles/extended.yaml`.

---

### Origin-Agent-Cluster

**Required:** no — **Severity if missing:** INFO

| Value | Severity | Rationale |
|---|---|---|
| `?1` | OK | Origin isolation enabled |
| `?0` | LOW | Isolation explicitly disabled |
| Any other value | INFO | Unrecognized value |

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

### Expect-CT *(deprecated)*

**Required:** no — **Absent:** OK *(not sending it is the correct state)*

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
