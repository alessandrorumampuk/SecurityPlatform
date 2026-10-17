# XSS Fingerprinting Skill

Deterministic reflected-XSS testing pipeline: probe → analyze → recommend →
verify. Instead of brute-forcing payloads, it fingerprints *which characters,
keywords, and junctions survive the target's filter* and *where the input
lands*, then composes a payload that is guaranteed — character by character —
to be deliverable, and proves it reached an executable DOM position.

> **Authorized use only.** Test only systems you own or have written
> permission to test. Probes are non-destructive by design; verification
> sends real payloads.

## The verification lattice

Filters fire on **combinations**, not atoms — `alert` passes and `()` passes
while `alert(1)` dies. So every layer is probed and gated independently:

```
L0 atoms      ' " > < / \                         (probe 1)
L1 tokens     alert () ` <script> onerror <img …  (probe 2, 46 items)
L2 junctions  alert(  tick`1`  img onerror  </script  href=javascript:
L3 payloads   the full candidate, marker-verified (--verify)
```

Downward-closure pruning: if a junction is blocked, every payload containing
it is pruned before emission — no dead candidates, no wasted requests.

## Architecture

```
   ┌─ find_surface.py (optional stage 0) ────────────────┐
   │  page -> page params, query links, GET-form fields  │
   │  -> one {xss_testing} template per parameter        │
   │  (POST forms listed as stored surface, not run)     │
   └─────────┬───────────────────────────────────────────┘
             ▼  saved: *-xss_surface.json
                  ┌────────────┐
                  │ Target URL │
                  │ {xss_testing}
                  └─────┬──────┘
                        ▼
        ┌─ send_payloads.py ──────────────────────────────┐
        │  Probe 1: char mask   testing1'x"x>x<x/x\testing2│
        │  Probe 2: kw mask     testing1x()x`xalertx…      │  (--probe2)
        │  Isolate: per-char    testing1{char}testing2 ×6  │  (--isolate)
        └─────────┬───────────────────────────────────────┘
                  ▼  saved: *-xss.html, *-xss_keywords.html
        ┌─ check_reflection.py ──┐
        │  per-item PASS/FAIL +  │   also: --keywords mode
        │  context detection +   │   records reflection positions
        │  anomaly hints         │
        └─────────┬──────────────┘
                  ▼  saved: *-xss_reflection_analysis.json
                  ▼           *-xss_keyword_analysis.json
        ┌─ recommend_payload.py ────────────────────────────┐
        │  breaker → char-gate → keyword-gate → junction-gate│
        │  → grammar → candidates (eff%, technique, case_ref)│
        │  --verify: marker injection → DOM parse → V/R      │
        └─────────┬─────────────────────────────────────────┘
                  ▼  saved: *-xss_recommendation.json
        ┌─ report ─┐
        │ logs are the single source of truth               │
        └──────────┘
```

## Files

| File | Role |
|---|---|
| `find_surface.py` | Attack-surface discovery: one `{xss_testing}` template per injectable param (page URL params, same-host query links, GET-form fields). POST forms reported as stored surface. |
| `send_payloads.py` | Sends marker probes. `--probe2` adds the 46-item keyword/junction probe; `--isolate` sends 6 single-character requests. |
| `check_reflection.py` | Parses the latest probe response: per-item PASS/FAIL, context detection, reflection positions, anomaly hints. `--keywords` analyzes the probe-2 file. |
| `recommend_payload.py` | Deterministic payload recommender: breaker computation, char gate, keyword/junction gates, composition grammar, marker verification. |
| `skill.md` | The full AI-guided workflow document (manual routing, case library usage, edge-case handling). |
| `case/` | 16 curated bypass technique files (`Payload:`/`Condition:`/`Case:`/`Output:`) — the authoritative fallback for unusual filters. |

All output goes to `Skills/log/` as timestamped files — never rely on
terminal text alone.

## Usage

### Stage 0: surface discovery (optional)

```bash
cd Cybersecurity/Skills/xss

# find every injectable param on a page -> {xss_testing} templates
python3 find_surface.py --url "http://127.0.0.1:8765/" --out surface.json
```

Output: `targets[]` (page_param / link_param / get_form → templates) +
`post_forms[]` (stored-XSS surface, enumerated but not executed — the
pipeline is GET-only). vvm's `--hunt` mode consumes this file.

### Full pipeline (recommended)

```bash
cd Cybersecurity/Skills/xss

# 1. probes (characters + keywords/junctions) — 2 requests
python3 send_payloads.py --url "http://127.0.0.1:8765/search?q={xss_testing}" --probe2

# 2. analysis — offline, zero requests
python3 check_reflection.py
python3 check_reflection.py --keywords

# 3. recommend + live marker verification
python3 recommend_payload.py --verify \
  --url "http://127.0.0.1:8765/search?q={xss_testing}"
```

### Escalation probe

```bash
python3 send_payloads.py --url "...{xss_testing}" --isolate
```

Sends each character alone (`testing1{char}testing2`) and saves
`*-xss_isolation.json`. Use **only** when the combined probe shows an
anomaly (checker prints the hint automatically):

| Anomaly | Isolation answers |
|---|---|
| No marker in response at all | No reflection surface — or WAF rejected the whole request? |
| All items FAIL | Per-item filter — or the combination tripped it? |
| Separator collapsed (split warning) | Which items survive when tested solo? |

## Detected contexts

The analyzer classifies each reflection point independently; the most
specific label wins. Per-context payload shapes:

| Context | Example reflection | Payload strategy |
|---|---|---|
| `html` | `<p>INJ</p>` | `<script>`, tag handlers, `javascript:` href, nested/case-mutated bypass, srcdoc last-resort |
| `attr` | `value="INJ"` | `">` breakout → tag handlers; `autofocus onfocus` in-context |
| `attr_handler` | `onclick="go(INJ)"` | zero-breaker `alert(1)` — already inside JS |
| `attr_url` | `href="INJ"` | `javascript:alert(1)` direct — no breakout needed; `">` fallback |
| `attr_srcdoc` | `srcdoc="INJ"` | `&lt;script&gt;…` entity-encoded inner HTML |
| `js_string` | `var q = "INJ"` | `"-alert(1)-"` in-string; `</script>` breakout |
| `js_raw` | `var q = INJ;` | `alert(1)` direct; `);fn;//` close-call |
| `js_lcomment` | `// INJ` | `\n` newline escape + call |
| `js_bcomment` | `/* INJ */` | `*/` close + call |
| `js_template` | `` `INJ` `` | `${fn}` interpolation; `` `+fn+` `` concat |
| `consuming:<tag>` | `<title>INJ` | `</tag>` close + script/img |
| `comment` | `<!-- INJ -->` | `-->` close + svg onload |

## Gates before emission

Each candidate must pass **all** applicable gates (a missing mask means
"allowed" — backward compatible):

1. **Breaker** — minimal escape string derived from context
   (`""` / `">` / `</script>` / `\n` / `*/` / `${` …).
2. **Character efficiency** — every probe char the payload needs must
   score 100 (unchanged). `50` = transformed but present, `0` = gone.
3. **Keyword mask** — primitive vocabulary: `()`,`alert`,`confirm`,`prompt`,
   `print`, `<script>`, `javascript:`, `onerror`,`onload`,`ontoggle`,
   `autofocus`,`onfocus`, `<img`,`<svg`,`<details`,`<body`,`<iframe`,
   `&lt;`, `srcdoc`.
4. **Junction mask** — combination units WAFs actually sign:
   `call_*` (`alert(1)`), `tick_*` (`` alert`1` ``), `pair_*`
   (`img onerror`), `close_*` (`</script`), `js_break_*` (`'-alert(1)-'`),
   `proto_href`, `newline`, `comment_close` (`*/`), `interp` (`${`).
5. **Case-mutation** — `ScRiPt`,`OnLoAd`,`JaVaScRiPt:` probed; when the
   lowercase form is blocked but the case-variant passes, mutated
   candidates are emitted automatically.

Survivors are composed via grammar primitives (tag × handler × function ×
terminator) and annotated with the closest `case/` file as `case_ref`.

> **Probe constraint:** keyword items must never contain the letter `x` —
> it is the `testing1x…xtesting2` split separator (`textarea` junction is
> deliberately omitted for this reason).

## Verification grades

`--verify` injects each top candidate with a unique `vvm<rand>` marker and
parses the response as real HTML:

| Grade | Evidence | Meaning |
|---|---|---|
| `V` | marker in executable position — `on*` handler value, `<script>` body, `javascript:`/`data:` URL, `srcdoc` HTML | executable DOM position — markup-level deliverability proven |
| `R` | marker reflected but inert | payload returned, not executable |
| `none` | marker absent | not reflected |

Marker embedding is shape-aware: `vvm{id}` attribute for tags,
`/*vvm{id}*/` inside JS/handler bodies, inside the `javascript:` URL
itself for `attr_url`, and inside srcdoc entities. Detection is advisory —
a mislabeled context produces grade `R` (under-claim), never false `V`.

Why marker-based instead of string-matching `alert(1)`: `&lt;script&gt;alert(1)`
contains the string verbatim but executes nothing — only a DOM parse of the
*marker element's position* avoids that false positive. The marker is inert
(unknown attributes ignored; alnum-only = zero WAF signature).

`V` does not prove runtime execution — CSP, user-interaction handlers and
client-side sanitizers can still stop it. `V` on an auto-fire vector
(`<script>`, `onload`, broken-`src` `onerror`) means it *will* run on load
in an unhardened page.

## Multi-reflection handling

One parameter can land in N positions with different filters each. Every
occurrence gets its own context label, char mask, keyword mask, and
`position`/`end` offsets in the analysis JSON (`reflections` field) — so
candidates are generated per-point and reported per reflection
(`reflections` field, `ref #n`). Positions also preserve the geometry
needed for future cross-point vector analysis.

## Log artifacts

| Producer | File | Content |
|---|---|---|
| `find_surface.py` | `*-xss_surface.json` | injectable-param templates + POST-form stored surface |
| `send_payloads.py` | `*-xss.html` | raw response + meta comments |
| `send_payloads.py --probe2` | `*-xss_keywords.html` | raw response (keyword probe) |
| `send_payloads.py --isolate` | `*-xss_isolation.json` | per-char verdicts |
| `check_reflection.py` | `*-xss_reflection_analysis.json` | char verdicts + contexts + `reflections` positions |
| `check_reflection.py --keywords` | `*-xss_keyword_analysis.json` | 46-item keyword/junction verdicts |
| `recommend_payload.py` | `*-xss_recommendation.json` | candidates, masks, V/R grades |

Latest files:
```bash
ls -t ../log/*-xss.html | head -1
ls -t ../log/*-xss_reflection_analysis.json | head -1
ls -t ../log/*-xss_recommendation.json | head -1
```

## When automation stops

- **Context the regex detector misses** (JSON, SVG, unusual tags) → manual
  HTML read (`skill.md` Step 4) + case library.
- **No candidates after all gates** → `case/` manual routing; that is the
  library's intended role, not a dead end.
- **Verify grade R** → reflected but inert — usually means the context was
  mis-detected or the markup is inert (`<template>`, comment, `noscript`).
- **Cross-point / multi-param vectors** — reflection geometry is recorded,
  but composing one payload spanning two injection points is deliberately
  left to manual analysis.

## Known limits

- Request-count cost: 2 probes + N verify requests per reflection; each is
  a signature-carrying request — keep `--verify` to top candidates.
- Context detection is regex-based and heuristic; HTML-parser detection is
  the next hardening step (shared blind spot across all stages). Errors
  fail safe — misdetection yields grade `R`, never false `V`.
- Junction coverage is 2-tuples; deeper combinations (`src x onerror`,
  mutation + encoding) and base64/`atob` transforms stay in the case
  library's domain.
- GET-only injection point (`{xss_testing}` in the URL); POST bodies and
  stored/DOM XSS are out of scope.
- `V` grade ceiling: no real-browser execution proof by design (DalFox
  makes the same trade — headless verification is non-deterministic).
