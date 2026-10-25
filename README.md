# SecurityPlatform

Visual Vulnerability Mapping — deterministic, evidence-based web vulnerability
detectors with a Flask UI. Every finding carries a `verified`/`candidate`/`drop`
verdict with concrete evidence; no LLM guesses in the detection path.

> **Authorized testing only.** Run this against systems you own or have
> explicit written permission to test. See [SECURITY.md](SECURITY.md).

## Features

| Detector | What it does |
|---|---|
| **Cross-Site Scripting (XSS)** | 12-context reflection analysis → character/keyword masks → context-aware payload generation (entity encoding, `self[...]` splits/escapes, alternate globals) → layered verification (marker, call-survival, CSP, optional browser execution via Playwright) |
| **CSRF** | Enumerates state-changing forms, filters login/signup noise, checks anti-CSRF tokens, SameSite cookies, and Origin/Referer validation |
| **Broken Link Hijacking** | `social_media_crawler.py` mines social-media links across the target (with its own crt.sh subdomain enumeration); links are reported as takeover candidates |
| **Information Disclosure** | Probes a curated sensitive-path wordlist (`.env`, `.git`, backups, debug endpoints) and classifies responses by content signature |
| **Directory Listing** | Detects exposed autoindex/listing pages (Apache, nginx, MinIO-style browsers) |
| **Subdomain Finder** | crt.sh Certificate Transparency + in-page host extraction, with optional resolution checks |

## Scan modes

- **Single Shot** — `vvm.py` drives a real browser over one target page,
  builds a page graph, runs the selected detectors, and renders an annotated
  PNG graph + findings JSON.
- **Automation** — `auto_hunt.py` enumerates `*.domain` first (persisted to
  JSON), then scans every resolving host in parallel (3 workers) with the
  selected detectors. Findings stream live to the UI.
  *Exception:* when **only** Broken Link Hijacking is selected, the crawler's
  own enumeration is used instead — no separate subdomain-finder pass.

## Quick start

```bash
pip install -r requirements.txt
playwright install chromium     # needed for Single Shot + XSS render-verify

python3 web.py                  # UI at http://127.0.0.1:8766
```

CLI equivalents:

```bash
python3 vvm.py --url https://target/ --skills xss,csrf
python3 auto_hunt.py --url https://target/ --skills xss --workers 3
```

Each skill also runs standalone — see the `skill.md`/`README.md` inside its
directory for exact flags.

## Project layout

```
SecurityPlatform/
├── web.py            # Flask UI — mode selection, live findings, annotated graph
├── vvm.py            # Single-Shot orchestrator: browser map → skills → PNG/JSON
├── auto_hunt.py      # Automation orchestrator: enumerate → parallel per-host scans
├── requirements.txt
├── Skills/
│   ├── skill.md              # agent entry point & per-skill index
│   ├── log_utils.py          # timestamped log/ filename convention (SSOT)
│   ├── env_loader.py         # shared .env loader
│   ├── .env.example          # copy to .env
│   ├── xss/                  # find_surface → check_reflection →
│   │                         #   recommend_payload → send_payloads (+ js_verify)
│   ├── csrf/                 # enumerate_forms → check_csrf
│   ├── broken_link_hijacking/# social_media_crawler (+ unused platform checkers)
│   ├── info_disclosure/      # probe_paths → check_leak → trigger_errors
│   ├── directory_listing/    # directory_listing.py
│   ├── subdomain_finder/     # find_subdomains.py
│   └── broken_access_control/idor/   # case docs (detector planned)
└── log/              # all results: yyyymmdd-hhmmss-{detector}.{json,txt,...}
                      # (gitignored)
```

## Finding model

```json
{
  "vuln": "Broken Link Hijacking",
  "status": "candidate | verified | drop",
  "path": ["el:12", "page:https://host/"],
  "evidence": "https://instagram.com/x -- instagram link found",
  "host": "sub.target.tld"
}
```

- **verified** — detector produced positive evidence (e.g. payload executed,
  token absent + confirmed by replay).
- **candidate** — indicator found but exploitability not confirmed.
- **drop** — checked and ruled out (kept for auditability).

## Testing

```bash
python3 Skills/xss/test_js_verify.py    # standalone runner, 31 fixture tests
```

## License / disclaimer

For educational and authorized security testing only. The authors are not
responsible for misuse.
