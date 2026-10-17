# CSRF — deterministic replay-oracle detection

Answers one measurable question: *does the server accept a state-changing
request without proof it came from our origin?*

```
page URL ──► enumerate_forms.py ──► forms + cookies + token fields
                                       │
                                       ▼
                              check_csrf.py replay battery
                              baseline / no_origin / foreign_origin /
                              forged_token / no_token / no_session
                                       │
                                       ▼
                        CONFIRMED · DEFENDED · SUSPECT  (+evidence)
```

## Files

| File | Role |
|---|---|
| `enumerate_forms.py` | form surface + token detection + cookie attrs → `*-csrf_forms.json` |
| `check_csrf.py` | 6-way replay oracle → `*-csrf_findings.json` |
| `skill.md` | battery, grades, safety warning |

## Why deterministic suffices

CSRF's verdict is a binary: *was the mutated-but-equivalent request
accepted?* Status codes are the oracle — no interpretation layer.
Same lattice as the other skills: enumerate → mutate → compare → grade.

⚠️ Replays write state — authorized/owned targets only.
