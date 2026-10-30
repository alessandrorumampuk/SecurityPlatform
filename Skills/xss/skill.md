# XSS Testing Workflow

## Why this document exists

This skill guides an AI agent through testing a user-provided URL for
Cross-Site Scripting (XSS) vulnerabilities. The workflow uses two scripts:

- `send_payloads.py` — sends a probe payload of special characters to the
  target URL and saves the raw HTTP response to the centralized log.
- `check_reflection.py` — reads the saved response, detects which characters
  were reflected back unchanged vs. encoded/filtered, identifies the
  reflection context (HTML body, attribute value, JavaScript string, etc.),
  and saves a structured analysis to the centralized log.

Based on the analysis, the AI consults the `case/` directory to select the
correct bypass technique for any characters that were blocked.

**All output is persisted to `Skills/log/`** — never rely on terminal text
alone. Every run produces a timestamped file that serves as the Single Source
of Truth for what was tested and what was found.

## Directory layout

```
Skills/xss/
├── skill.md                 ← this file
├── send_payloads.py         ← step 2: send probe payload
├── check_reflection.py      ← step 3: analyze reflection
├── recommend_payload.py     ← step 6a: deterministic payload recommendation
└── case/                    ← bypass techniques (one .md per scenario)
```

To see all available case files:
```bash
ls Skills/xss/case/
```

## Step-by-step workflow

### Step 0: Classify the user's input

The user will provide a URL. There are two cases:

**Case A — Testing URL with a placeholder:**
The URL already contains a reflection point with the `{xss_testing}` placeholder,
e.g. `https://example.com/search?q={xss_testing}`. Skip to Step 2.

**Case B — Bare website URL:**
The URL is just a website root, e.g. `https://example.com` with no visible
parameter or placeholder. The AI must first discover a reflection surface
(Step 1) before sending the probe payload.

### Step 1: Discover a reflection surface (only for Case B)

When the user gives a bare URL, the AI must find a place where user input is
reflected back into the page. Do this by:

1. **Fetch the homepage** with `curl -s -k <url>` and save the HTML.
2. **Look for input vectors** in the HTML:
   - Search forms: `<form ... method="GET">` with `<input name="q">` or
     similar. The form's `action` attribute + input `name` gives you a
     reflection URL like `https://example.com/search?q={xss_testing}`.
   - URL parameters: any link on the page that already has `?key=value`
     patterns (e.g. `?page=about`, `?id=123`, `?lang=en`).
   - Path segments: URLs like `https://example.com/page/about` where the
     last segment might be reflected.
3. **Test each candidate** by replacing the user-controllable value with the
   marker `testing1testing2` and fetching the URL. If the marker appears in
   the response, you found a reflection point.
4. **Construct the testing URL** with the `{xss_testing}` placeholder at the
   reflection point, e.g.:
   ```
   https://example.com/search?q={xss_testing}
   https://example.com/page/{xss_testing}
   https://example.com/?lang={xss_testing}
   ```
5. If no reflection point is found on the homepage, try common paths:
   `/search`, `/q`, `/query`, `/test`, `/demo`, `/api`, `/echo`. If still
   nothing, report to the user that no reflection surface was found.

Once you have a URL with `{xss_testing}`, proceed to Step 2.

### Step 2: Send the probe payload

`--url` is required — there is no default. The AI must always provide the
target URL with the `{xss_testing}` placeholder:

```bash
cd Cybersecurity/Skills/xss
python3 send_payloads.py --url "https://example.com/search?q={xss_testing}"
```

**What this does:**
- Constructs the probe payload:
  `testing1'x"x>x<x/x\testing2`
  (marker `testing1` + 6 special characters separated by `x` + marker `testing2`)
- URL-encodes it and injects it at the `{xss_testing}` position.
- Sends the request via `curl` and saves the full HTTP response (with
  metadata comments) to `Skills/log/<timestamp>-xss.html`.

The 6 characters being tested:

| # | Name          | Char | Why it matters |
|---|---------------|------|----------------|
| 1 | single_quote  | `'`  | Break out of JS strings / single-quoted attributes |
| 2 | double_quote  | `"`  | Break out of JS strings / double-quoted attributes |
| 3 | greater_than  | `>`  | Close HTML tags |
| 4 | less_than     | `<`  | Open new HTML tags |
| 5 | slash         | `/`  | Close tags, path traversal, `</script>` |
| 6 | backslash     | `\`  | Escape sequences in JS strings |

**Optional second probe (Layer B/C keywords):**
```bash
python3 send_payloads.py --url "...q={xss_testing}" --probe2
```
`--probe2` additionally sends a keyword-mask probe
(`testing1x()x`xalertxconfirmxpromptx<script>xjavascript:xonerrorx<imgx&lt;xsrcdoctesting2`)
saved as `*-xss_keywords.html`. It detects filters the 6-char probe cannot
see: blocked `()`, blocked keywords (`alert`, `javascript:`, `onerror`),
`<script>` tag stripping, and entity passthrough (`&lt;`) + `srcdoc`
availability for the last-resort srcdoc-entity technique.
The probe also appends `rand_tag` — a random 3-letter tag like `<xDh>`
regenerated on every run. If even that unknown tag is deleted, the filter
is a generic tag-stripper and any removed string can be nested inside
blocked content as a splitter (case `xss tag removed.md`).

**Escalation probe (per-character isolation):**
```bash
python3 send_payloads.py --url "...q={xss_testing}" --isolate
```
`--isolate` sends `testing1<char>testing2` one character at a time (6
requests) and saves `*-xss_isolation.json`. Use it ONLY when the combined
probe shows an anomaly: no marker reflected at all (cannot tell "no
reflection surface" from "request rejected by WAF"), all 6 FAIL (could be a
combination-triggered filter), or the `x` separator collapsed (split
warning). Isolation pinpoints which single character trips the filter.

**POST / body / header targets.** `{xss_testing}` may also live in a
request body or header instead of the URL — `send_payloads.py` and
`recommend_payload.py --verify` share the same flags:

```bash
# urlencoded POST form — body is substituted VERBATIM (curl --data /
# Burp Repeater semantics), only the URL value is percent-encoded
python3 send_payloads.py --url "https://example.com/comment" \
  --data 'name={xss_testing}&msg=x' --probe2

# browser-like form submit — percent-encode the payload inside the body
python3 send_payloads.py --url "https://example.com/comment" \
  --data 'name={xss_testing}&msg=x' --data-urlencoded --probe2

# JSON body — raw (default) keeps `"` for string-breakout testing;
# --json-escape escapes the payload as a JSON string literal
python3 send_payloads.py --url "https://example.com/api" \
  --data '{"q":"{xss_testing}"}' --content-type application/json --probe2

# header injection — value substituted verbatim
python3 send_payloads.py --url "https://example.com/" \
  -H "Referer: https://x/?r={xss_testing}"
```

Rules: `--method` defaults to POST when `--data` is present (otherwise
GET); `-H` is repeatable; verbatim body substitution means `&`/`=`/`+`
inside a payload can split a urlencoded template — that split is itself
observable fuzzing behaviour, use `--data-urlencoded` for clean
browser-equivalent semantics. POST verification checks reflection in the
POST response itself (no stored-XSS second-visit oracle). `--render` is
GET-navigation only: on a POST target it logs `[RENDER_SKIP]` and falls
back to the static path.

`find_surface.py` emits one executable `post_form` target per injectable
field — the target field carries `{xss_testing}`, all other fields
(including hidden ones like `csrf_token`) are filled with their HTML
default values, and the target is marked `body_encode: "url"` so the
orchestrators pass `--data-urlencoded` automatically. Hidden fields are
never scanned as standalone surfaces.

### Step 3: Analyze the reflection

```bash
python3 check_reflection.py              # character analysis (probe 1)
python3 check_reflection.py --keywords   # keyword analysis (probe 2)
```

This automatically reads the latest `*-xss.html` file from `Skills/log/`,
extracts the reflected payload, and for each character reports:

- **PASS** — character reflected unchanged (no filtering).
- **FAIL** — character was encoded, removed, or changed (bypass needed).

It also detects the **reflection context**:
- `html body (text content)` — reflected as visible page text.
- `attribute value (quotes encoded)` / `attribute value (quotes NOT encoded)` —
  reflected inside an HTML attribute like `value="..."`.
- `javascript string` — reflected inside a `<script>` block.
- `inside noscript/style/title/textarea tag` — reflected inside a
  consuming/special HTML tag.

The analysis is saved to `Skills/log/<timestamp>-xss_reflection_analysis.json`.
With `--keywords`, the latest `*-xss_keywords.html` is analyzed instead and
saved to `*-xss_keyword_analysis.json` (same PASS/FAIL format per keyword).

### Step 4: Read the HTML response manually

Do not rely only on the automated analysis. **Open the latest `*-xss.html`
file in `Skills/log/` and read it directly.** Look for:

- Where exactly the payload `testing1...testing2` appears in the HTML.
- Whether it appears once or multiple times (multiple reflection points =
  multiple attack surfaces).
- What surrounds it: is it inside a `<h1>`, a `value="..."` attribute, a
  `<script>` block, a `<textarea>`?
- Whether any characters were HTML-encoded (`&lt;`, `&gt;`, `&#039;`,
  `&quot;`) or URL-encoded (`%3C`, `%3E`).
- Whether the payload was truncated or rearranged.

This manual inspection is critical — the automated detector covers common
contexts but may miss unusual ones.

### Step 5: Decide if a bypass is needed

Based on Steps 3 and 4, determine the verdict:

**All 6 characters PASS (no encoding/filtering):**
The target reflects input with no sanitization. Read the case file:
```
case/xss without encoding and filtering.md
```

**Some characters FAIL (encoding/filtering detected):**
A bypass is needed. Select the correct case file based on TWO factors:
1. **Which characters are blocked** (angle brackets? quotes? parentheses?)
2. **Where the input is reflected** (HTML body? attribute? JS string? tag?)

Use the routing table below to find the right case file, then **open and
read that file** to get the actual payload and conditions.

### Step 6: Select the bypass technique

#### Routing table: context × blocked characters → case file

The table below only tells you **which case file to open**. Do NOT guess
the payload from this table — open the file and read the `Payload:`,
`Condition:`, and `Case:` lines inside it to find the exact technique that
matches your situation.

| Reflection context | Blocked chars | Case file to read |
|---|---|---|
| HTML body | Nothing blocked | `xss without encoding and filtering.md` |
| HTML body | `<` `>` blocked | `xss without greater than.md` |
| HTML body | `()` blocked | `xss without parentheses.md` |
| HTML body | `alert`/`prompt` blocked | `xss with disabled alert and prompt javascript.md` |
| HTML body | `<script>` tag removed | `xss tag removed.md` |
| HTML body | Keywords blocked | `xss with obfuscation.md` |
| HTML body | Inside `<noscript>`/`<style>`/`<title>`/`<textarea>` | `xss inside a tag.md` |
| HTML body | Inside consuming tag (`<noembed>`, `<noscript>`, etc.) | `xss with consuming tags.md` |
| Attribute value | Quotes not blocked | `xss inside an attribute value inside a tag.md` |
| Attribute value | `<` `>` not blocked | `xss inside an attribute value inside a tag without angle brackets encoded.md` |
| Attribute value | Everything blocked but HTML entities allowed | `xss with special attributes.md` |
| JS string | `<` `>` blocked, quotes not | `xss into javascript string with angle brackets encoded.md` |
| JS string | Nothing blocked | `xss into javascript string without angle brackets encoded.md` |
| Anywhere | `javascript:` protocol not blocked | `xss with javascript protocol.md` |
| Anywhere | Hidden input field | `xss with special attributes.md` |

#### How to read the case files

Each case file contains one or more entries in this format:
```
N. <title>
- Payload: <the exact payload to inject>
- Condition: <when this payload works>
- Case: <explanation of the bypass logic>
- Output: <what the resulting HTML looks like>
```

Open the case file identified by the routing table. Read every entry in it.
Match the **Condition** line against your findings from Steps 3-4. When you
find a matching condition, use the **Payload** line as your XSS payload.

#### Step 6a (optional): Automated recommendation via `recommend_payload.py`

Instead of manually walking the routing table, you can let the deterministic
recommender turn the analysis JSON into payload candidates:

```bash
python3 recommend_payload.py                # recommend only
python3 recommend_payload.py --verify \
  --url "https://example.com/search?q={xss_testing}"   # + live R/V grading
```

How it works (mirrors XSStrike/DalFox internals):

1. **Breaker computation** — for each reflection context it derives the
   minimal escape string (attribute → `quote + >`, JS string → `</script>`,
   consuming tag → `</tag>`, comment → `-->`).
2. **Character efficiency gate** — every candidate is only emitted if all
   six probe characters it requires scored 100 (unchanged). Transformed-but-
   present characters score 50 and are reported.
3. **Keyword mask gate** — if a `*-xss_keyword_analysis.json` exists (from
   `--probe2` + `check_reflection.py --keywords`), it is loaded
   automatically and gates the grammar further: blocked `()` selects
   backtick calls, blocked `alert` selects `confirm`/`prompt`, and any
   fully-removed string (`<script>`, `<img`, `onerror`, the random
   `rand_tag`, ...) becomes a splitter nested mid-target —
   `<scr<xDh>ipt>` — so the filter's own deletion reconstructs the
   blocked payload. Blocked
   `onerror`/`<img` without a usable splitter removes those tag-handler
   variants, and when `()`,
   `alert` or `<script>` are blocked while `&lt;`/`srcdoc` pass it emits the
   last-resort `<iframe srcdoc=&lt;…entity-encoded…&gt;>` payload.
4. **Composition grammar** — payloads are assembled from tag × event-handler
   × function × terminator primitives, covering filter combinations that have
   no dedicated case file. Each candidate is annotated with the closest
   `case/` file so the curated library remains the reference.
5. **Marker verification** (`--verify`) — each top payload is injected with a
   unique `vvm<rand>` marker and the response is parsed as HTML. Grade **V**
   means the marker landed in an executable position (event handler, script
   body, `javascript:`/`data:` URL); grade **R** means it reflected but is
   not executable.

Results are saved to `Skills/log/<timestamp>-xss_recommendation.json`.

The case/ library is still authoritative — use Step 6 manual routing when the
automated recommender emits no candidates or the context detector missed an
unusual reflection point (Step 4).

## Verified pipeline (most accurate order)

Each stage produces verifiable evidence before becoming the next stage's
input; every gate has an explicit fallback:

1. `send_payloads.py --url "...{xss_testing}" --probe2` — both probes
   (chars + keywords), non-destructive.
2. `check_reflection.py` + `check_reflection.py --keywords` — per-item
   PASS/FAIL + context, saved as two JSON analyses.
3. Manual HTML read (Step 4) — only mandatory when the context output is
   ambiguous or shows multiple reflections; skip when Step 3 + Step 6a agree.
4. `recommend_payload.py --verify --url "...{xss_testing}"` — breaker +
   char-gate + keyword-gate + grammar, then marker verification grades each
   candidate V (executable position confirmed) or R (reflected only).
5. Report from the log chain only: `*-xss.html`, `*-xss_keywords.html`,
   `*-xss_reflection_analysis.json`, `*-xss_keyword_analysis.json`,
   `*-xss_recommendation.json`.

### Step 7: Report findings to the user

After completing the analysis, report:

1. **Reflection surface found:** The URL/parameter where input is reflected.
2. **Characters reflected unchanged:** List which of the 6 passed.
3. **Characters blocked/encoded:** List which failed and how (encoded?
   removed? replaced?).
4. **Reflection context:** Where in the HTML the input appears.
5. **Verdict:** Is XSS possible? Which bypass technique is needed?
6. **Recommended payload:** The specific payload from the case file.
7. **Log files:** Path to the `*-xss.html` response file and
   `*-xss_reflection_analysis.json` analysis file in `Skills/log/`.

## Log file naming convention

All output goes to `Skills/log/` with timestamped filenames:

| Script | Filename pattern | Content |
|---|---|---|
| `send_payloads.py` | `<yyyymmdd-hhmmss>-xss.html` | Raw HTTP response with metadata comments (character probe) |
| `send_payloads.py --probe2` | `<yyyymmdd-hhmmss>-xss_keywords.html` | Raw HTTP response (keyword probe) |
| `send_payloads.py --isolate` | `<yyyymmdd-hhmmss>-xss_isolation.json` | Per-character isolation verdicts (escalation probe) |
| `check_reflection.py` | `<yyyymmdd-hhmmss>-xss_reflection_analysis.json` | Structured analysis: per-character verdict, context, bypass needed |
| `check_reflection.py --keywords` | `<yyyymmdd-hhmmss>-xss_keyword_analysis.json` | Structured analysis: per-keyword verdict |
| `recommend_payload.py` | `<yyyymmdd-hhmmss>-xss_recommendation.json` | Payload candidates with efficiency, technique, case reference, and optional R/V verification |

To find the latest XSS response:
```bash
ls -t Skills/log/*-xss.html | head -1
```

To find the latest analysis:
```bash
ls -t Skills/log/*-xss_reflection_analysis.json | head -1
```

## Important notes

- **Always read the HTML response manually** (Step 4). The automated
  detector covers common contexts but may miss edge cases like reflection
  inside JSON responses, SVG contexts, or unusual tag combinations.
- **Test one reflection point at a time.** If the page has multiple
  reflection points (search box + URL path + error message), test each
  separately with its own `{xss_testing}` URL.
- **The probe payload is non-destructive.** It only sends special characters
  wrapped in markers — no actual `<script>` tags. This is safe for initial
  probing. Only send actual XSS payloads after confirming reflection.
- **URL-encode the payload.** `send_payloads.py` handles URL substitution
  automatically via `urllib.parse.quote`. Body (`--data`) and header
  (`-H`) substitution is verbatim by default — opt into
  `--data-urlencoded`/`--json-escape` when the template format needs it.
  If testing manually, ensure special characters are properly encoded in
  the URL.
- **Check for multiple reflections.** The payload may appear more than once
  in the response (e.g. in both the page title and the body). Each
  reflection point may have different filtering — `check_reflection.py`
  reports each one separately as `Reflection [1]`, `Reflection [2]`, etc.
