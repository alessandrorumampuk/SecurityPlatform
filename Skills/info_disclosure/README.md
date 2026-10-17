# Information Disclosure — deterministic detection

URL-probe + response-signature pipeline for sensitive-data exposure.
The most deterministic vuln class: the oracle is a binary pattern match,
not DOM position — no composition problem, no AI needed for detection.

```
                    ┌──────────────┐
   base URL ──────► │ probe_paths  │  ~80 curated paths (.env .git
                    └──────┬───────┘   actuator phpinfo backups…)
                           │ status + 4KB sample + sha256
                           ▼
                    ┌──────────────┐
                    │  check_leak  │  L2 signature → L3 format →
                    └──────┬───────┘  entropy + placeholder gate
                           │ CONFIRMED / SUSPECT / INFO
                           ▼
                  infoleak_findings.json  (redacted evidence)

   URL?id=1 ──────► ┌───────────────┐
                    │ trigger_errors│  baseline → mutate param
                    └──────┬────────┘  ('  9999999999  -1  %00 …)
                           │ new signatures vs baseline
                           ▼
                  infoleak_errors.json   (Class-A error pages)
```

## Files

| File | Role |
|---|---|
| `probe_paths.py` | Class-B wordlist probe; writes `*-infoleak_probe.json` |
| `check_leak.py` | Signature + credential-grammar + entropy grader → `*-infoleak_findings.json` |
| `trigger_errors.py` | Class-A param-mutation error trigger → `*-infoleak_errors.json` |
| `skill.md` | Workflow, signature vocabulary, grades, gaps |
| `../log/` | Central log dir (shared `log_utils`) |

## Why deterministic works here

1. **Binary oracle** — `ref: refs/heads/` in `/.git/HEAD` IS the vuln;
   no interpretation layer between evidence and verdict.
2. **Credentials have grammars** — `AKIA[0-9A-Z]{16}`, `ghp_[36]`,
   `base64:…`, PEM blocks, conn-strings are regex-validatable.
3. **Placeholders are enumerable** — `changeme|example|xxx|TODO` +
   entropy < 3.4 kills the classic false positive.
4. **Diff-not-assume** — error pages confirmed only by signatures that
   were absent at baseline (same principle as the BLH calibration gate).

## Known limits

- GET-only path probing; custom Hosts/auth headers not parameterized yet
- ~90% coverage of *popular* secret formats; custom tokens = entropy-only
- Severity tiers are fixed (critical > high > medium > low), not contextual
- Content-based only — a `.env` that returns 200 with HTML (SPA fallback)
  is correctly NOT flagged; a true `.env` behind `Allow` rules is missed
