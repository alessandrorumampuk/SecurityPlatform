# Skill: Information Disclosure Detection

Deterministic detection of sensitive-data exposure — no AI needed for the
detection layer. Two complementary classes:

- **Class B (always-on):** paths that leak without a trigger — `.env`,
  `.git/`, `actuator/env`, `phpinfo`, backups, status pages.
- **Class A (error-triggered):** debug/error pages surfaced by malformed
  input — `'` SQL escape, int64 overflow, type coercion, null byte.

## Commands

### Class B — always-on leaks
```bash
# 1) probe the curated path wordlist (~80 paths)
python3 probe_paths.py --url https://target.example
#    → log/…-infoleak_probe.json  (status + sample evidence per path)

# 2) grade findings: signature → secret-format → entropy/placeholder
python3 check_leak.py
#    → log/…-infoleak_findings.json  (CONFIRMED / SUSPECT / INFO)
```

### Class A — error-page disclosure
```bash
# baseline → mutate each query param → diff for new error signatures
python3 trigger_errors.py --url 'http://target/page?id=1&name=x'
#    → log/…-infoleak_errors.json
```

## The validation lattice

```
L1  PATH      wordlist probe → status 2xx / 401·403
L2  SIGNATURE body match: APP_KEY=, ref: refs/heads/, SQLSTATE,
              phpinfo, Whoops, actuator propertySources, PEM, conn-strings
L3  FORMAT    matched value fits a credential grammar:
              AKIA…, ghp_…, gho_…, AIza…, sk-…, xox*-, base64:…, JWT
L3b ENTROPY   shannon ≥ 3.4 AND not in placeholder blocklist
              (DB_PASSWORD=changeme is NOT a finding)
```

Oracle principle (same as BLH verify / XSS marker): **diff, don't assume**
— `trigger_errors.py` only confirms signatures absent from the baseline.

## Grades

| Grade | Meaning |
|---|---|
| CONFIRMED | critical signature, or structural leak (git HEAD, phpinfo, env), or format-validated secret — evidence kept |
| SUSPECT | medium signature (traceback/path leak) without secret validation — manual review |
| INFO | low-severity (status page, API schema) — context only |

Secrets are **redacted** in logs (`AKIAxx…`) — evidence without re-leaking.

## Severity tiers (what actually leaks)

- **Tier 1 — credentials/user-data:** `.env`, `.git`, `actuator/env`+`heapdump`,
  Telescope, Symfony profiler, conn-strings → equivalent to the Whoops case
- **Tier 2 — code/config/RCE surface:** YSOD source snippets, Werkzeug
  console, `.php.bak` source
- **Tier 3 — internal map:** `display_errors` paths, stack traces, SQL
  schema, phpinfo → enabler, not the crown jewels

## Honest gaps (where judgment may still help)

- Novel/custom secret formats with no grammar (entropy-only suspicion)
- Canary/honeypot credentials — indistinguishable until used (don't use)
- `.env` content rendered inside documentation pages — path-context check
- Severity ranking of internal IPs/hostnames

## Operational notes

- `probe_paths.py` sends `allow_redirects=False` and stores only a 4KB
  sample + sha256 — evidence without hoarding bodies.
- 401/403 responses are logged (`▲`) — the file exists but is protected;
  worth a manual bypass look, not auto-flagged.
- `trigger_errors.py` mutates query params only; extend to POST bodies /
  path segments if needed.
- Rate: `--delay` default 0.3 s; ~80 paths ≈ 25 s per host.
- Run against **authorized targets only** — public `.env`/`.git` on
  someone else's host is a finding to report, not to download.
