# Cybersecurity Skills — Vulnerability Testing Framework

## Purpose

This is the **entry point** for any AI agent performing security testing
in this repository.

When the user asks to test a target for vulnerabilities:

1. Read this document first.
2. Find the `skill.md` for the vulnerability class to test.
3. **Read that `skill.md` entirely** before running any tool or sending
   any payload.
4. Follow the workflow described in that `skill.md`.

**Never run a tool without first reading the `skill.md` for that
vulnerability class.** Each one contains its own workflow, tool usage,
detection logic, bypass technique selection, and reporting format.

## Directory structure

```
Skills/
├── skill.md              ← this file (entry point)
├── log_utils.py          ← shared logging utility
├── env_loader.py         ← shared .env loader
├── .env                  ← shared environment variables
├── log/                  ← ALL results from ALL tools
├── report_format/        ← vulnerability report templates
└── {vulnerability_directory}/
    └── skill.md
```

To find all available vulnerability classes and their skill documents:
```bash
find Skills/ -name "skill.md" -o -name "SKILL.md" | sort
```

## Log directory — Single Source of Truth

**Every tool saves its output to `Skills/log/`.** No result should exist
only in terminal output. Terminal text is for progress monitoring — the
log file is the authoritative record.

After running any tool, always read the log file it produced before
reporting to the user. Never report findings based only on terminal
output.

```bash
ls -t Skills/log/ | head -20    # see latest results
```

## Report format

When reporting a vulnerability finding to the target organization, use
the templates and examples in `Skills/report_format/`:

```bash
ls Skills/report_format/
```

- **Template** — fill in the placeholders (`{JENIS_KERENTANAN}`,
  `{WEBSITE_ADDRESS/DOMAIN}`, `{DAMPAK}`, `{PAYLOAD}`, `{URL}`, `{BUKTI}`)
  and attach screenshots manually as proof.
- **Example reports** — read the existing example reports (Indonesian and
  English) as reference for tone, structure, and level of detail.

## Rules

1. **Read the vulnerability's `skill.md` before testing.** Never skip
   this step.

2. **All results go to `Skills/log/`.** If a tool does not save to the
   centralized log, it is not trustworthy.

3. **Read the log files after running tools.** Do not report based on
   terminal text alone.

4. **Follow each `skill.md`'s workflow and reporting format.** Do not
   improvise — each vulnerability class has specific steps, payloads,
   and reporting requirements documented in its own `skill.md`.

5. **Skip classes without a `skill.md`.** If a vulnerability directory
   exists but has no `skill.md`, it is not yet implemented. Note this in
   the report and move on.
