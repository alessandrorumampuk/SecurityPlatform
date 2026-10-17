#!/usr/bin/env python3
"""Classify probe results from probe_paths.py as real leaks — deterministic.

Three-layer validation, no AI:

    L2  SIGNATURE   does the response body contain a disclosure signature?
                    (APP_KEY=, ref: refs/heads/, phpinfo, SQLSTATE, ...)
    L3  FORMAT      does a matched secret match a known credential grammar?
                    (AKIA…, ghp_…, sk-…, base64:…, PEM block, conn-string)
    L3b ENTROPY     is the matched value high-entropy and NOT a placeholder?
                    (DB_PASSWORD=changeme is NOT a leak)

Grade per finding:
    CONFIRMED  signature hit AND (format-validated secret OR env-var pair
               OR structural signature like git HEAD / phpinfo table)
    SUSPECT    signature hit but value looks like a placeholder/example
    INFO       low-severity exposure (status page, robots-like, stack
               trace without secrets) — evidence kept for review

Secrets are REDACTED in the output log (first 6 chars only) — evidence
without re-leaking the credential into another file.

Usage:
    python3 check_leak.py                    # latest infoleak_probe JSON
    python3 check_leak.py --file path.json
"""

import argparse
import json
import math
import os
import re
import sys
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import latest_log_path, new_log_path

# ── L2: disclosure signatures (regex → human label) ─────────────────────
SIGNATURES = [
    (r"APP_KEY\s*=", "env: APP_KEY", "critical"),
    (r"DB_(HOST|PORT|DATABASE|USERNAME|PASSWORD)\s*=", "env: DB_*", "critical"),
    (r"(AWS_|MINIO_|S3_)[A-Z_]*(KEY|SECRET)\s*=", "env: cloud creds", "critical"),
    (r"(MAIL|PUSHER|REDIS)_(PASSWORD|SECRET|KEY)\s*=", "env: service creds", "critical"),
    (r"ref:\s*refs/heads/", "git HEAD", "critical"),
    (r"repositoryformatversion", "git config", "high"),
    (r"<title>phpinfo\(\)</title>|phpinfo\(\)</h1>", "phpinfo page", "high"),
    (r"propertySources|systemEnvironment", "Spring actuator env", "high"),
    (r"SQLSTATE\[\w+\]", "SQL error (SQLSTATE)", "high"),
    (r"Illuminate\\\\|Whoops\\\\|PrettyPageHandler", "Laravel debug", "high"),
    (r"Traceback \(most recent call last\)", "Python traceback", "medium"),
    (r"NullPointerException|\.java:\d+\)", "Java stack trace", "medium"),
    (r"Django Version|django\.conf", "Django debug page", "high"),
    (r"-----BEGIN [\w ]*PRIVATE KEY", "private key PEM", "critical"),
    (r"mongodb(\+srv)?://", "MongoDB conn string", "critical"),
    (r"(postgres|mysql|redis)://[^\s<\"']+:[^\s<\"'@]+@", "DB conn string w/ creds", "critical"),
    (r"Apache Server Status|Active connections:\s*\d+", "server status page", "low"),
    (r"swagger|openapi", "API schema", "low"),
]

# ── L3: known credential grammars ───────────────────────────────────────
SECRET_FORMATS = {
    "aws_access_key":  r"AKIA[0-9A-Z]{16}",
    "google_api_key":  r"AIza[0-9A-Za-z\-_]{35}",
    "github_pat":      r"ghp_[0-9a-zA-Z]{36}",
    "github_oauth":    r"gho_[0-9a-zA-Z]{36}",
    "slack_token":     r"xox[baprs]-[0-9A-Za-z-]{10,}",
    "openai_key":      r"sk-[A-Za-z0-9_-]{20,}",
    "laravel_app_key": r"APP_KEY\s*=\s*base64:[A-Za-z0-9+/]{40,}={0,2}",
    "jwt":             r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}",
    "generic_secret":  r"(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY)\s*=\s*['\"]?([A-Za-z0-9+/=_.\-]{12,})",
}

PLACEHOLDERS = re.compile(
    r"^(changeme|change_me|example|sample|your[_-].*|x{3,}|\*+|t(d|o)do|"
    r"password|secret|test|demo|null|none|undefined|localhost|127\.0\.0\.1|"
    r"base64:|root|admin|default|placeholder|<.*>)$", re.I)

ENTROPY_MIN = 3.4          # shannon bits/char — placeholders sit far below
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def shannon(s: str) -> float:
    """Shannon entropy of a string (bits/char)."""
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def mask(v: str) -> str:
    """Redact a secret for the log: keep prefix, hide the rest."""
    return v[:6] + "…" if len(v) > 6 else "…"


def analyze(rec: dict) -> Optional[dict]:
    """Grade one probe record. Returns a finding dict or None."""
    if not (200 <= rec.get("status", 0) < 300):
        return None
    body = rec.get("sample", "")
    hits, secrets = [], []
    max_sev = "low"

    # L2 signatures
    for pat, label, sev in SIGNATURES:
        if re.search(pat, body):
            hits.append(label)
            if SEV_ORDER[sev] > SEV_ORDER[max_sev]:
                max_sev = sev

    # L3 credential grammars + entropy + placeholder gate
    format_hits = []
    for name, pat in SECRET_FORMATS.items():
        for m in re.finditer(pat, body):
            val = m.group(1) if name == "generic_secret" else m.group(0)
            if PLACEHOLDERS.match(val):
                continue
            if len(val) >= 12 and shannon(val) < ENTROPY_MIN:
                continue
            format_hits.append(f"format:{name}")
            secrets.append(mask(val))
            break  # one per format is enough evidence

    if not hits and not format_hits:
        return None

    # exposed env-style file with NO credential-shaped values inside:
    # the file IS leaked (CONFIRMED) but severity drops — it's an empty
    # or placeholder-only exposure, not a live credential dump
    if max_sev == "critical" and not format_hits \
            and all(h.startswith("env:") for h in hits):
        max_sev = "medium"

    if format_hits or max_sev in ("critical", "high"):
        grade = "CONFIRMED" if (format_hits or max_sev == "critical") else "CONFIRMED"
        # structural signatures (git/phpinfo/actuator) are self-proving
        if not format_hits and max_sev != "critical":
            grade = "CONFIRMED" if max_sev == "high" else grade
    else:
        grade = "SUSPECT" if max_sev == "medium" else "INFO"

    return {
        "path": rec["path"],
        "status": rec["status"],
        "grade": grade,
        "severity": max_sev,
        "evidence": hits + format_hits,
        "secrets_redacted": secrets[:8],
        "sha256": rec.get("sha256"),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Grade probe results for leaks")
    ap.add_argument("--file", help="probe JSON (default: latest infoleak_probe)")
    ap.add_argument("--out", help="Output findings JSON (default: log dir)")
    args = ap.parse_args()

    src = args.file or latest_log_path("infoleak_probe", "json")
    data = json.load(open(src))
    print(f"📂 {os.path.basename(src)} — {data.get('target')} "
          f"({len(data.get('results', []))} records)")

    findings = [f for f in (analyze(r) for r in data.get("results", [])) if f]
    findings.sort(key=lambda f: -SEV_ORDER[f["severity"]])

    for f in findings:
        print(f"  {f['grade']:9} {f['severity']:8} {f['path']:42} "
              f"{' · '.join(f['evidence'][:3])}")

    out = args.out or new_log_path("infoleak_findings", "json")
    payload = {
        "generated_by": "check_leak.py",
        "source": os.path.basename(src),
        "target": data.get("target"),
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "confirmed": sum(1 for f in findings if f["grade"] == "CONFIRMED"),
        "suspect": sum(1 for f in findings if f["grade"] == "SUSPECT"),
        "findings": findings,
    }
    with open(out, "w") as fh:
        json.dump(payload, fh, indent=2)
    print(f"\n💾 {out}")
    print(f"   {payload['confirmed']} CONFIRMED · {payload['suspect']} SUSPECT "
          f"· {sum(1 for f in findings if f['grade'] == 'INFO')} INFO")


if __name__ == "__main__":
    main()
