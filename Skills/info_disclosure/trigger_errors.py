#!/usr/bin/env python3
"""Trigger error-page disclosure via parameter mutation (CLASS-A detector).

Baseline → mutate each query parameter with error-triggering values →
signature-match the response for framework/SQL/stack output.

Mutations target the most reliable triggers (per field data):
    '           SQL quote escape      → SQLSTATE / SQL syntax errors
    9999999999  int64 overflow        → type/coercion errors
    -1          negative boundary     → validation/unhandled paths
    %00         null byte             → parser errors
    test'       string-in-int         → invalid input syntax (Postgres)
    []          array-in-scalar       → TypeError / binding errors
    ../         path traversal probe  → file errors

A response is CONFIRMED only when an error signature appears that was
NOT present in the baseline — same oracle principle as the BLH verify
gate and the XSS marker: diff, don't assume.

Usage:
    python3 trigger_errors.py --url 'http://target/page?id=1&name=x'
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import new_log_path

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")

MUTATIONS = ["'", '"', "9999999999", "-1", "%00", "test'", "[]", "../"]

ERROR_SIGNATURES = [
    (r"SQLSTATE\[\w+\]", "sqlstate"),
    (r"SQL syntax|syntax error.*SQL|unclosed quotation", "sql_syntax"),
    (r"invalid input syntax for type \w+", "pg_type_coercion"),
    (r"ORA-\d{4,}", "oracle_error"),
    (r"mysql_|mysqli_|pg_query|sqlite3?::", "db_function"),
    (r"Illuminate\\\\|Whoops\\\\|PrettyPageHandler", "laravel_whoops"),
    (r"Traceback \(most recent call last\)", "python_traceback"),
    (r"(?:Warning|Fatal error|Notice|Deprecated):\s+.+?in\s+/[\w./-]+", "php_error"),
    (r"NullPointerException|\.java:\d+\)", "java_stack"),
    (r"Server Error in '/' Application|ASP\.NET", "aspnet_ysod"),
    (r"Django Version|django\.core|ObjectDoesNotExist", "django_debug"),
    (r"(?:at\s+)?/[\w./-]+\.(?:php|py|rb|java|cs|js):\d+", "internal_path"),
    (r"APP_KEY|DB_PASSWORD|SECRET_KEY\s*=", "env_secret"),
]


def fetch(session: requests.Session, url: str, timeout: int) -> dict:
    try:
        r = session.get(url, timeout=timeout, allow_redirects=False, verify=False)
        return {"status": r.status_code, "body": r.text or "", "len": len(r.content)}
    except Exception as e:
        return {"status": 0, "body": "", "len": 0, "error": str(e)[:120]}


def signatures_in(body: str) -> set:
    return {name for pat, name in ERROR_SIGNATURES if re.search(pat, body)}


def main() -> None:
    ap = argparse.ArgumentParser(description="Trigger error-page disclosure")
    ap.add_argument("--url", required=True,
                    help="URL with query params, e.g. http://t/page?id=1")
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--out", help="Output JSON (default: log dir)")
    args = ap.parse_args()

    requests.packages.urllib3.disable_warnings()  # noqa
    parsed = urlparse(args.url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        print("❌ URL has no query parameters to mutate")
        sys.exit(1)

    session = requests.Session()
    session.headers["User-Agent"] = UA

    base = fetch(session, args.url, args.timeout)
    base_sigs = signatures_in(base["body"])
    print(f"baseline: {base['status']} len={base['len']} sigs={sorted(base_sigs) or '—'}")

    findings = []
    for param in params:
        for mut in MUTATIONS:
            q = dict(params)
            q[param] = mut
            url = urlunparse(parsed._replace(query=urlencode(q, doseq=True)))
            r = fetch(session, url, args.timeout)
            new_sigs = signatures_in(r["body"]) - base_sigs
            grade = "CONFIRMED" if new_sigs else ("SUSPECT"
                    if r["status"] >= 500 and base["status"] < 500 else "none")
            if grade != "none":
                # evidence excerpt: first 160 chars around the signature
                ev = ""
                for pat, name in ERROR_SIGNATURES:
                    m = re.search(pat, r["body"])
                    if m and name in new_sigs:
                        ev = r["body"][max(0, m.start() - 60):m.end() + 80]
                        break
                findings.append({
                    "param": param, "mutation": mut, "status": r["status"],
                    "grade": grade, "new_signatures": sorted(new_sigs),
                    "excerpt": re.sub(r"\s+", " ", ev)[:220],
                })
                print(f"  ◉ {param}={mut!r} → {r['status']} {sorted(new_sigs)}")
            time.sleep(args.delay)

    out = args.out or new_log_path("infoleak_errors", "json")
    payload = {
        "generated_by": "trigger_errors.py",
        "target": args.url,
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "baseline_status": base["status"],
        "baseline_signatures": sorted(base_sigs),
        "confirmed": sum(1 for f in findings if f["grade"] == "CONFIRMED"),
        "findings": findings,
    }
    with open(out, "w") as fh:
        json.dump(payload, fh, indent=2)
    print(f"\n💾 {out}  ·  {payload['confirmed']} CONFIRMED error disclosures")


if __name__ == "__main__":
    main()
