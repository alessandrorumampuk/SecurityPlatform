# Broken Link Hijacking - Crawl & Verify Workflow

## Why this document exists

`social_media_crawler.py` finds social media links on a target website and
writes them to `log/social_media_links.json`. Four separate tools then check
whether each link's account actually exists:

- `open_facebook_playwright.py`
- `open_instagram_playwright.py`
- `open_tiktok_playwright.py`
- `open_youtube_playwright.py`

These tools work by pattern-matching page text (e.g. "Couldn't find this
account"). Social platforms constantly change their error pages, apostrophe
encoding, anti-bot challenges, and login walls - any of which can silently
break the detection logic and produce **false positives** (reporting a dead
account as existing, so a real hijack opportunity gets missed) or **false
negatives** (reporting a live account as dead, wasting analyst time).

**Never trust a batch crawl result without verifying the tools first.**

## Step-by-step workflow

### 1. Run the crawler

```bash
cd Cybersecurity/Skills/broken_link_hijacking
python3 social_media_crawler.py --url https://target-site.com
```

Output goes to `log/social_media_links.json`.

### 2. Verify the four checker tools BEFORE trusting any batch results

```bash
python3 verify_tools.py
```

This self-test, for each of the 4 platforms:
- Generates 3 random, guaranteed-nonexistent usernames (via
  `generate_random_username.py`) and confirms they're reported as **NOT
  FOUND**.
- Checks 3 known-valid, real, large/official accounts (e.g. `nike`,
  `instagram`, `@tiktok`, `@YouTube`) and confirms they're reported as
  **EXISTS**.

If any platform prints `[FAIL] FAIL`, **do not trust that platform's batch
results** - go to "Known failure modes" below and fix the tool before
proceeding.

Options:
```bash
python3 verify_tools.py --platform tiktok      # verify a single platform
python3 verify_tools.py --retries 2             # more retries for flaky platforms
```

### 3. Only after verify_tools.py reports all PASS, run the batch checks

```bash
python3 open_facebook_playwright.py    # defaults to log/social_media_links.json
python3 open_instagram_playwright.py
python3 open_tiktok_playwright.py
python3 open_youtube_playwright.py
```

## Random username generator

`generate_random_username.py` produces alphanumeric usernames that are
astronomically unlikely to collide with a real account, with an enforced
character-limit clamp (`MIN_USERNAME_LENGTH=6`, `MAX_USERNAME_LENGTH=20`,
chosen to stay under the strictest real platform limit, TikTok's 24 chars).

```bash
python3 generate_random_username.py --count 3 --length 16
```

## Known failure modes (already fixed, but watch for regressions)

| Platform | Bug found | Root cause | Fix |
|---|---|---|---|
| Facebook | False "EXISTS" for dead accounts when logged in | Logged-in error page says "This content isn't available at the moment", not the anonymous "This page isn't available" | Added both phrasings to `error_keywords` |
| TikTok | Chromium crash (SEGV) on headless runs | Bundled Playwright Chromium is unstable on heavy JS pages | Launch with `channel="chrome"` (real Google Chrome) instead of bundled Chromium |
| TikTok | False "EXISTS" for random/dead accounts | `"following"` was in `profile_markers`, but it's a generic nav tab label ("For You \| Explore \| Following") present on every page including 404s | Removed `following`/`mengikuti` from markers; kept only `followers`/`pengikut`/`likes`/`suka` |
| TikTok | Missed real "Couldn't find this account" error text | TikTok renders a typographic/curly apostrophe (U+2019), not a straight one (U+0027) | Added both apostrophe variants to `error_keywords` |
| TikTok | Ambiguous pages defaulted to "EXISTS" | Fallback branch (no error, no markers, no captcha) assumed existence | Changed fallback to "NOT FOUND / UNVERIFIABLE" - false positives are worse than false negatives for hijack detection |
| TikTok | Anti-bot CAPTCHA escalates with rapid repeated requests, causing even valid accounts to be blocked | TikTok's IP-based rate limiting | Increased inter-request delay to 4s, added automatic 1-retry with 6s backoff on CAPTCHA before giving up |

## Design principle: fail-safe, not fail-open

For broken-link-hijacking detection, a **false "EXISTS"** (missing a real
hijack opportunity) is worse than a **false "NOT FOUND"** (an analyst
manually re-checks a link that turned out to be fine). When a checker tool
can't confidently determine account existence (ambiguous page, anti-bot
block, unknown error format), it must default to **NOT FOUND /
UNVERIFIABLE**, never to EXISTS.

## Known limitation

TikTok's anti-bot system escalates CAPTCHA challenges with repeated
automated requests from the same IP in a short time window. If
`verify_tools.py --platform tiktok` fails only on **valid** accounts (not
fake ones) with `status: CAPTCHA`, wait a few minutes before retrying rather
than assuming the tool is broken - it usually resolves once request volume
from your IP drops.
