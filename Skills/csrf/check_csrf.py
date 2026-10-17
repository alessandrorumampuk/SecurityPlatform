#!/usr/bin/env python3
"""CSRF replay oracle — deterministic, no AI.

For every state-changing form found by enumerate_forms.py, replay the
submission six ways and compare against the baseline:

    baseline       legit Origin + Referer, real token  -> must succeed
    no_origin      strip Origin/Referer entirely
    foreign_origin Origin: https://csrf-vvm.invalid
    forged_token   token fields -> "forged"            (presence != validation)
    no_token       token fields removed entirely
    no_session     baseline replayed WITHOUT cookies

Oracle logic:
    CONFIRMED  -- a mutation the server should have rejected succeeded:
                  foreign origin accepted, or forged/missing token accepted
                  (when a token exists). State change is forgeable.
    DEFENDED   -- mutations rejected with 4xx (server validates origin/token)
    SUSPECT    -- baseline itself failed; replay inconclusive

WARNING: the replays PERFORM the state change (that is the oracle).
Only run against endpoints you own or are explicitly authorized to test;
prefer low-impact forms. Use --no-submit to enumerate only.

Usage:
    python3 check_csrf.py --cookie "session=abc"      # latest forms JSON
    python3 check_csrf.py --file forms.json --cookie "session=abc"
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import latest_log_path, new_log_path

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")

TOKEN_RE = re.compile(r"csrf|token|authenticity|xsrf|nonce|verify|__request",
                      re.I)
EVIL_ORIGIN = "https://csrf-vvm.invalid"


def submit(url, method, fields, cookie="", origin=None, referer=None,
           timeout=15):
    """Send the form once; return (status, length, url_final)."""
    headers = {"User-Agent": UA}
    if cookie:
        headers["Cookie"] = cookie
    if origin is not None:
        headers["Origin"] = origin
    if referer is not None:
        headers["Referer"] = referer
    try:
        if method == "get":
            sep = "&" if "?" in url else "?"
            req = urllib.request.Request(
                url + sep + urllib.parse.urlencode(fields),
                headers=headers, method="GET")
        else:
            req = urllib.request.Request(
                url, data=urllib.parse.urlencode(fields).encode(),
                headers=headers, method=method.upper())
        r = urllib.request.urlopen(req, timeout=timeout)
        code, final, ln = r.status, r.url, len(r.read())
        return code, ln, final
    except urllib.error.HTTPError as e:
        return e.code, len(e.read()), url
    except Exception as e:
        return 0, 0, str(e)[:60]


def build_fields(form, forged=False, drop_tokens=False):
    fields = {}
    for i in form.get("inputs", []):
        name = i.get("name")
        if not name:
            continue
        t = (i.get("type") or "text").lower()
        if t in ("submit", "button", "image", "file", "password"):
            fields[name] = "vvmtest1" if t == "password" else fields.get(name)
            continue
        is_tok = bool(TOKEN_RE.search(name))
        if is_tok and drop_tokens:
            continue
        if t == "hidden":
            fields[name] = "forged" if (is_tok and forged) else \
                           (i.get("value") or "vvmtest")
        elif t in ("checkbox", "radio"):
            if i.get("checked"):
                fields[name] = i.get("value", "on")
        else:
            fields[name] = i.get("value") or "vvmtest"
    return {k: v for k, v in fields.items() if v is not None}


def ok(code):
    return 200 <= code < 400


def grade(form, results):
    """results: {mutation_name: (code,...)}"""
    base_ok = ok(results["baseline"][0])
    if not base_ok:
        return "SUSPECT", "baseline submission failed -- replay inconclusive"

    tokens = form.get("token_fields") or []
    defended, reasons = False, []

    for mut in ("no_origin", "foreign_origin"):
        if not ok(results[mut][0]):
            defended = True
            reasons.append(f"{mut} rejected ({results[mut][0]})")
    if tokens:
        for mut in ("forged_token", "no_token"):
            if not ok(results[mut][0]):
                defended = True
                reasons.append(f"{mut} rejected ({results[mut][0]})")
    if defended:
        return "DEFENDED", "; ".join(reasons)

    acc = [m for m in ("no_origin", "foreign_origin")
           if ok(results[m][0])]
    if tokens:
        acc += [m for m in ("forged_token", "no_token")
                if ok(results[m][0])]
    noauth = ok(results["no_session"][0])
    note = " (no session needed -- anonymous state change)" if noauth else ""
    return "CONFIRMED", (f"accepted mutations: {', '.join(acc) or 'baseline only'}"
                         + ("; token present but not validated"
                            if tokens else "; no token field")
                         + note)


def main():
    ap = argparse.ArgumentParser(description="CSRF replay oracle")
    ap.add_argument("--file", help="forms JSON (default: latest csrf_forms)")
    ap.add_argument("--cookie", default="", help='"name=val; name2=val2"')
    ap.add_argument("--delay", type=float, default=0.2)
    ap.add_argument("--no-submit", action="store_true",
                    help="enumerate/grade structure only; perform no replays")
    ap.add_argument("--out", help="Output JSON (default: log dir)")
    args = ap.parse_args()

    src = args.file or latest_log_path("csrf_forms", "json")
    data = json.load(open(src))
    url, forms = data["url"], data.get("forms", [])
    origin = urllib.parse.urlsplit(url)
    origin = f"{origin.scheme}://{origin.netloc}"
    print(f"📂 {os.path.basename(src)} — {len(forms)} forms on {url}")

    targets = [f for f in forms if f.get("state_changing")]
    findings = []
    for f in targets:
        print(f"\n  form {f['method'].upper()} {f['action'][:70]}")
        if args.no_submit:
            findings.append({"action": f["action"], "method": f["method"],
                             "grade": "SKIPPED",
                             "evidence": "--no-submit (enumeration only)"})
            continue
        results = {}
        results["baseline"] = submit(f["action"], f["method"],
                                     build_fields(f), args.cookie,
                                     origin=origin, referer=url)
        for name, kw in [
            ("no_origin", dict(cookie=args.cookie)),
            ("foreign_origin", dict(cookie=args.cookie, origin=EVIL_ORIGIN)),
            ("forged_token", dict(cookie=args.cookie, origin=origin,
                                  referer=url)),
            ("no_token", dict(cookie=args.cookie, origin=origin,
                              referer=url)),
            ("no_session", dict(origin=origin, referer=url)),
        ]:
            flds = build_fields(f, forged=(name == "forged_token"),
                                drop_tokens=(name == "no_token"))
            results[name] = submit(f["action"], f["method"], flds, **kw)
            time.sleep(args.delay)

        g, ev = grade(f, results)
        print(f"    -> {g}: {ev}")
        findings.append({
            "action": f["action"], "method": f["method"],
            "token_fields": f.get("token_fields", []),
            "grade": g, "evidence": ev,
            "responses": {k: v[0] for k, v in results.items()},
        })

    # Browser-level mitigation note from enumerate cookies
    strict = [c["name"] for c in data.get("cookies", [])
              if str(c.get("samesite", "")).lower() == "strict"]
    if strict and findings:
        for f in findings:
            if f["grade"] == "CONFIRMED":
                f["evidence"] += (f" | NOTE: SameSite=Strict cookie(s) "
                                  f"{strict} mitigate top-level POSTs in "
                                  f"modern browsers")

    out = args.out or new_log_path("csrf_findings", "json")
    payload = {"generated_by": "check_csrf.py", "source": os.path.basename(src),
               "url": url, "checked_at": datetime.now().isoformat(timespec="seconds"),
               "confirmed": sum(1 for f in findings
                                if f["grade"] == "CONFIRMED"),
               "findings": findings}
    with open(out, "w") as fh:
        json.dump(payload, fh, indent=2)
    print(f"\n💾 {out}")
    print(f"   {payload['confirmed']} CONFIRMED · "
          f"{sum(1 for f in findings if f['grade'] == 'DEFENDED')} DEFENDED · "
          f"{sum(1 for f in findings if f['grade'] == 'SUSPECT')} SUSPECT")


if __name__ == "__main__":
    main()
