# Security Policy

## Scope

SecurityPlatform is a vulnerability-scanning toolkit intended for systems you
own, lab environments, or targets covered by a written authorization
(bug-bounty scope, pentest engagement, CTF). Scanning systems without
permission may be illegal in your jurisdiction.

## Reporting a vulnerability in this project

If you find a security issue **in SecurityPlatform itself** (e.g. unsafe
handling of scan output, command injection through target URLs), please do not
open a public issue with exploit details. Instead, report it privately to the
repository owner via GitHub's "Report a vulnerability" feature (Security →
Advisories) or by direct contact.

## Operational notes

- Skills send real attack traffic (XSS payloads, sensitive-path probes).
  Expect WAF/IPS alerts and rate limiting on the target side.
- Playwright-based components render target pages locally — treat them as
  untrusted content (do not browse other sites in the same browser profile).
- `Skills/.env` may contain default target URLs. Do not put secrets or
  credentials in it; it is committed to the repository by design.
- Everything under `log/` is local scan output and is gitignored — review it
  before sharing, it may contain target internals.
