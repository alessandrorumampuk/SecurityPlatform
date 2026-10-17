# Skill: CSRF Detection

Deterministic — oracle is a replay-diff, no AI needed.

```
enumerate_forms.py  →  forms + cookies + token fields
check_csrf.py       →  replay battery per form → CONFIRMED/DEFENDED/SUSPECT
```

## Commands

```bash
# 1) enumerate state-changing forms (+ SameSite cookie info)
python3 enumerate_forms.py --url http://target/page --cookie "session=abc"
#    → log/…-csrf_forms.json

# 2) replay oracle
python3 check_csrf.py --cookie "session=abc"
#    → log/…-csrf_findings.json
```

## The replay battery (per state-changing form)

| Mutation | Question answered |
|---|---|
| baseline | does a legit submit succeed at all? |
| no_origin | accepted without Origin/Referer? |
| foreign_origin | accepted with `Origin: https://csrf-vvm.invalid`? |
| forged_token | token present but validated? (presence ≠ validation) |
| no_token | token required at all? |
| no_session | is ambient auth even needed? |

CONFIRMED = baseline succeeds AND a should-have-been-rejected mutation
succeeds. DEFENDED = server rejects mutated submits with 4xx.
SUSPECT = baseline itself fails (can't replay — inconclusive).

A SameSite=Strict session cookie is noted as a browser mitigation in
evidence — the server-side verdict still stands.

## WARNING — the oracle writes

Replays PERFORM the state change — that is what makes the verdict
objective. Run against owned/authorized targets; pick low-impact forms.
`--no-submit` enumerates without touching anything.

## Grades

| Grade | Meaning |
|---|---|
| CONFIRMED | forgeable: origin/token checks absent or not validated |
| DEFENDED | server rejects mutated submissions |
| SUSPECT | inconclusive (baseline failed / endpoint unreachable) |

## Honest gaps

- HTML forms only (GET/POST). Fetch/XHR/SPA flows not enumerated —
  parsing JS bundles is coverage work, not verdict work.
- Severity is not judged: a CSRF-able "change theme" and a CSRF-able
  "change email" are both CONFIRMED — impact rating is a human layer.
- Field values are generic (`vvmtest`); forms with server-side field
  validation may baseline-fail → SUSPECT.
