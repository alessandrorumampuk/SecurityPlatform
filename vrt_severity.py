#!/usr/bin/env python3
"""vrt_severity.py -- Bugcrowd VRT severity grading for skill findings.

vvm.py / auto_hunt.py fold every skill's JSON output into flat findings:

    {"vuln": ..., "status": "verified"|"candidate",
     "tool": "xss"|"csrf"|"dirlist"|"info_disclosure"|..., "evidence": ...}

This module maps each flat finding onto a Bugcrowd Vulnerability Rating
Taxonomy (VRT) row -- deterministic rule lookup, no AI, consistent with
the rest of the platform:

    tool  +  oracle grade (status)  +  signals inside the evidence string
        ->  VRT (category / name / variant)  +  P1-P5 / Varies / Info  +  basis

Two honesty rules, same epistemics as the skills themselves:

    - only oracle-VERIFIED findings earn a fixed P row; unverified
      candidates are VARIES -- never inflate a guess into a severity
    - severity follows the VRT "varies-with-impact" rows: a confirmed
      issue whose real rating depends on the data it exposes (dirlist
      sensitive files, action-specific CSRF) stays VARIES

Standalone use (grades an existing findings JSON; writes to log/):

    python3 vrt_severity.py --file <auto|graph>.json
    python3 vrt_severity.py --file findings.json --out graded.json
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, "Skills"))
from log_utils import new_log_path  # noqa: E402

# Sort order for the UI: P1 first, then Varies, then informational.
SEV_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5,
            "VARIES": 6, "INFO": 7}

# -- evidence-string parsers -------------------------------------------------
# vvm flattens skill fields into the evidence text, e.g.
#   infoleak : "GET {u}{p} -> 200 [CONFIRMED/critical] env: DB_* · format:..."
#   errors   : "id='9999' -> HTTP 500 [CONFIRMED] sqlstate,pg_type_coercion"
#   xss      : "[V] <svg ...> -- marker in executable position"
_BRACKET_PAIR = re.compile(r"\[([A-Z]+)/([a-z]+)\]")
_BRACKET_ONE = re.compile(r"\[([A-Z]+)\]")


def _bracket_grade_sev(ev):
    m = _BRACKET_PAIR.search(ev or "")
    return (m.group(1), m.group(2)) if m else (None, None)


def _lead_grade(ev):
    m = _BRACKET_ONE.search((ev or "")[:8])
    return m.group(1) if m else None


def _has(ev, *subs):
    return any(s in (ev or "") for s in subs)


def _row(sev, cat, name, variant, basis):
    return {"severity": sev,
            "vrt": {"category": cat, "name": name, "variant": variant},
            "basis": basis}


# -- per-tool graders --------------------------------------------------------

def _grade_xss(status, ev):
    g = _lead_grade(ev)
    if status == "verified" or g == "V":
        return _row("P3", "Cross-Site Scripting (XSS)", "Reflected",
                    "Non-Self",
                    "marker-in-DOM grade V -- payload reached an executable "
                    "position. Stored persistence would elevate to P2.")
    return _row("VARIES", "Cross-Site Scripting (XSS)", "Reflected",
                "Unverified",
                f"reflection grade {g or '?'} -- inert until verified; "
                "self-XSS drops to P5")


def _grade_csrf(status, ev):
    if status != "verified":
        return _row("VARIES", "Cross-Site Request Forgery (CSRF)",
                    "Action-Specific", "Inconclusive replay",
                    "replay oracle inconclusive (baseline failed) -- "
                    "retest with a valid session")
    if "no session needed" in ev:
        return _row("VARIES", "Cross-Site Request Forgery (CSRF)",
                    "Action-Specific", "Unauthenticated Action",
                    "mutation accepted without a session -- review as "
                    "missing authorization, not just CSRF")
    return _row("VARIES", "Cross-Site Request Forgery (CSRF)",
                "Action-Specific", "Authenticated Action",
                "forgeable mutation accepted; application-wide impact "
                "elevates to P2")


# check_leak evidence labels, grouped by the VRT row they map to.
_LEAK_P1 = ("env: APP_KEY", "env: DB_*", "env: cloud creds",
            "env: service creds", "private key PEM", "conn string",
            "git HEAD", "format:")
_LEAK_P3 = ("Spring actuator env", "git config", "Django debug",
            "Laravel debug")
_LEAK_P4 = ("phpinfo page", "SQL error")
_LEAK_P5 = ("Python traceback", "Java stack", "server status",
            "API schema")

# trigger_errors signature names -> VRT error-disclosure rows.
_ERR_P4 = ("sqlstate", "sql_syntax", "pg_type_coercion", "oracle_error",
           "db_function", "aspnet_ysod", "django_debug")
_ERR_P5 = ("python_traceback", "php_error", "java_stack")


def _grade_infoleak(status, ev):
    grade, sev = _bracket_grade_sev(ev)
    if grade and grade != "CONFIRMED":
        return _row("VARIES", "Sensitive Data Exposure",
                    "Disclosure of Secrets", "Unverified signature",
                    f"probe signature inconclusive [{grade}] -- "
                    "manual review of the exposed content")
    if _has(ev, *_LEAK_P1) or sev == "critical":
        return _row("P1", "Sensitive Data Exposure",
                    "Disclosure of Secrets", "For Publicly Accessible Asset",
                    "live credential / key / VCS material exposed")
    if _has(ev, *_LEAK_P3):
        return _row("P3", "Sensitive Data Exposure",
                    "Disclosure of Secrets", "For Internal Asset",
                    "framework internals / config disclosure")
    if _has(ev, *_LEAK_P4) or sev == "high":
        return _row("P4", "Sensitive Data Exposure",
                    "Visible Detailed Error/Debug Page",
                    "Detailed Server Configuration",
                    "framework/debug page leaks server internals")
    if _has(ev, "Python traceback", "Java stack") or sev == "medium":
        return _row("P5", "Sensitive Data Exposure",
                    "Visible Detailed Error/Debug Page",
                    "Descriptive Stack Trace",
                    "stack trace / framework error disclosure")
    if _has(ev, "server status", "API schema") or sev == "low":
        return _row("P5", "Server Security Misconfiguration",
                    "Fingerprinting/Banner Disclosure", "",
                    "status page / schema disclosure")
    return _row("VARIES", "Sensitive Data Exposure",
                "Disclosure of Secrets", "Unverified",
                "signature hit without a known label -- manual review")


def _grade_trigger_errors(status, ev):
    grade, _sev = _bracket_grade_sev(ev)
    if _has(ev, "env_secret"):
        return _row("P1", "Sensitive Data Exposure",
                    "Disclosure of Secrets", "For Publicly Accessible Asset",
                    "error page leaked env-style secrets")
    if _has(ev, *_ERR_P4):
        return _row("P4", "Sensitive Data Exposure",
                    "Visible Detailed Error/Debug Page",
                    "Detailed Server Configuration",
                    "error page leaks DB/framework internals")
    if _has(ev, *_ERR_P5):
        return _row("P5", "Sensitive Data Exposure",
                    "Visible Detailed Error/Debug Page",
                    "Descriptive Stack Trace",
                    "error page leaks stack trace")
    if _has(ev, "internal_path"):
        return _row("P5", "Sensitive Data Exposure",
                    "Visible Detailed Error/Debug Page",
                    "Full Path Disclosure",
                    "error page leaks filesystem paths")
    if grade == "SUSPECT" or status != "verified":
        return _row("VARIES", "Sensitive Data Exposure",
                    "Visible Detailed Error/Debug Page",
                    "Inconclusive",
                    "5xx without a disclosure signature -- investigate "
                    "manually")
    return _row("VARIES", "Sensitive Data Exposure",
                "Visible Detailed Error/Debug Page", "Unreviewed",
                "error signature without a mapped row -- manual review")


def _grade_dirlist(status, ev):
    if status == "verified":
        return _row("VARIES", "Server Security Misconfiguration",
                    "Directory Listing Enabled", "Sensitive Data Exposure",
                    "open listing with sensitive-named files -- rating "
                    "scales with actual file contents")
    return _row("P5", "Server Security Misconfiguration",
                "Directory Listing Enabled", "Non-Sensitive Data Exposure",
                "open autoindex listing, no sensitive filenames flagged")


def _grade_blh(status, ev):
    if status == "verified":
        return _row("P4", "Server-Side Injection", "Content Spoofing",
                    "Impersonation via Broken Link Hijacking",
                    "dead social link verified re-registrable")
    return _row("VARIES", "Server-Side Injection", "Content Spoofing",
                "Impersonation via Broken Link Hijacking",
                "social link mined but re-registration not yet verified")


def _grade_subdomain(status, ev):
    if _has(ev, "axfr", "zone transfer"):
        return _row("P4", "Server Security Misconfiguration",
                    "Misconfigured DNS", "Zone Transfer",
                    "AXFR succeeded -- full zone dump")
    return _row("INFO", "Server Security Misconfiguration",
                "Misconfigured DNS", "Enumeration",
                "attack-surface enumeration, not a vulnerability")


def _grade_idor(status, ev):
    if status != "verified":
        return _row("VARIES", "Broken Access Control (BAC)",
                    "Insecure Direct Object References (IDOR)",
                    "Unverified", "candidate object reference -- "
                    "needs cross-identity replay proof")
    if _has(ev, "modify", "write", "update", "delete"):
        return _row("P2", "Broken Access Control (BAC)",
                    "Insecure Direct Object References (IDOR)",
                    "Modify Sensitive Information"
                    "(Iterable Object Identifiers)",
                    "cross-identity write verified")
    if _has(ev, "guid", "uuid"):
        return _row("P4", "Broken Access Control (BAC)",
                    "Insecure Direct Object References (IDOR)",
                    "Modify/View Sensitive Information"
                    "(Complex Object Identifiers GUID/UUID)",
                    "cross-identity access via complex identifier")
    return _row("P3", "Broken Access Control (BAC)",
                "Insecure Direct Object References (IDOR)",
                "View Sensitive Information"
                "(Iterable Object Identifiers)",
                "cross-identity read verified")


_GRADERS = {
    "xss": _grade_xss,
    "csrf": _grade_csrf,
    "info_disclosure": _grade_infoleak,
    "info_disclosure/trigger_errors": _grade_trigger_errors,
    "dirlist": _grade_dirlist,
    "directory_listing": _grade_dirlist,
    "broken_link_hijacking": _grade_blh,
    "blh": _grade_blh,
    "subdomain_finder": _grade_subdomain,
    "idor": _grade_idor,
}


def grade_finding(f):
    """One flat finding -> same dict + severity/vrt/basis.

    Dispatch is on the originating skill (`tool`); grading only reads
    the oracle verdict (`status`) plus signals already embedded in the
    evidence string -- never invents evidence of its own."""
    tool = (f.get("tool") or "").lower()
    g = _GRADERS.get(tool)
    if g is None:
        # fall back to the vuln name for tools recorded under a label
        for key, fn in _GRADERS.items():
            if key in tool or (f.get("vuln") or "").lower().startswith(
                    key.split("_")[0]):
                g = fn
                break
    row = (g or (lambda s, e: _row(
        "VARIES", "Uncategorized", (f.get("vuln") or "Unknown"),
        "Unmapped", "no VRT rule for this tool -- manual triage")))(
        f.get("status") or "", f.get("evidence") or "")
    out = dict(f)
    out.update(row)
    return out


def grade_findings(findings):
    """Grade a finding list and sort verified-first, then by severity."""
    graded = [grade_finding(f) for f in findings]
    graded.sort(key=lambda f: (f.get("status") != "verified",
                               SEV_RANK.get(f.get("severity"), 9)))
    return graded


# -- standalone CLI ----------------------------------------------------------

def _load_findings(path):
    data = json.load(open(path))
    if isinstance(data, list):
        return data
    return data.get("findings") or data.get("results") or []


def main():
    ap = argparse.ArgumentParser(
        description="Grade findings JSON against the Bugcrowd VRT")
    ap.add_argument("--file", required=True,
                    help="auto_hunt/vvm findings JSON")
    ap.add_argument("--out", help="Output JSON (default: log dir)")
    args = ap.parse_args()

    graded = grade_findings(_load_findings(args.file))
    counts = {}
    for f in graded:
        v = f.get("vrt") or {}
        tag = v.get("name", "?")
        if v.get("variant"):
            tag += f" / {v['variant']}"
        print(f"  {f['severity']:6} {f.get('status', '?'):9} "
              f"{f.get('vuln', '?'):28} {tag}")
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    out = args.out or new_log_path("vrt_grading", "json")
    with open(out, "w") as fh:
        json.dump({"generated_by": "vrt_severity.py",
                   "source": os.path.basename(args.file),
                   "graded_at": datetime.now().isoformat(timespec="seconds"),
                   "taxonomy": "Bugcrowd VRT",
                   "counts": counts, "findings": graded}, fh, indent=2)
    print(f"\n💾 {out}")
    print("   " + " · ".join(f"{s}×{n}" for s, n in sorted(
        counts.items(), key=lambda kv: SEV_RANK.get(kv[0], 9))))


if __name__ == "__main__":
    main()
