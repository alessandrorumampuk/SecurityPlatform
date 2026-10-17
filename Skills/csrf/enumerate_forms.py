#!/usr/bin/env python3
"""Enumerate state-changing forms on a page (CSRF surface, deterministic).

GETs the page once with the stdlib parser (no JS) and extracts:
    - every <form>: action (resolved), method, inputs (name/type/value)
    - which forms carry an anti-CSRF-looking hidden input
    - response Set-Cookie attributes (SameSite / Secure / HttpOnly)

Forms are the CSRF surface: a state-changing POST without a token is
forgeable cross-site unless the server checks Origin/Referer. GET forms
are kept too -- a state-changing GET is CSRF-able even under
SameSite=Lax.

Result feeds check_csrf.py, which replays the mutations.

Usage:
    python3 enumerate_forms.py --url http://target/page [--cookie "k=v"]
"""

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime
from html.parser import HTMLParser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import new_log_path

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")

TOKEN_RE = __import__("re").compile(
    r"csrf|token|authenticity|xsrf|nonce|verify|__request", __import__("re").I)

STATELESS_METHODS = ("get", "head", "options")


class FormParser(HTMLParser):
    """Collect <form> structure plus input/select/textarea fields."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._form = {"action": a.get("action", ""),
                          "method": (a.get("method") or "get").lower(),
                          "inputs": []}
            self.forms.append(self._form)
        elif self._form is not None and tag in ("input", "textarea", "select"):
            self._form["inputs"].append({
                "name": a.get("name", ""),
                "type": (a.get("type") or "text").lower(),
                "value": a.get("value", ""),
                "checked": "checked" in a,
            })

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def fetch(url: str, cookie: str = "") -> tuple:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        r = urllib.request.urlopen(req, timeout=15)
        return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def cookies_from(headers: dict) -> list:
    """Parse Set-Cookie lines -> [{name, samesite, secure, httponly}]."""
    raw = headers.get("Set-Cookie", "")
    lines = raw if isinstance(raw, list) else [raw]
    out = []
    for line in lines:
        if not line:
            continue
        parts = [p.strip() for p in line.split(";")]
        name = parts[0].split("=", 1)[0]
        attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1]
                 if "=" in p else True) for p in parts[1:]}
        out.append({"name": name,
                    "samesite": attrs.get("samesite"),
                    "secure": "secure" in attrs,
                    "httponly": "httponly" in attrs})
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Enumerate forms for CSRF surface")
    ap.add_argument("--url", required=True)
    ap.add_argument("--cookie", default="", help='"name=val; name2=val2"')
    ap.add_argument("--out", help="Output JSON (default: log dir)")
    args = ap.parse_args()

    status, headers, html = fetch(args.url, args.cookie)
    p = FormParser()
    p.feed(html)

    forms = []
    for f in p.forms:
        action = urllib.parse.urljoin(args.url, f["action"] or args.url)
        token_fields = [i["name"] for i in f["inputs"]
                        if i.get("name") and TOKEN_RE.search(i["name"])]
        forms.append({
            "action": action,
            "method": f["method"],
            "state_changing": f["method"] not in STATELESS_METHODS,
            "inputs": f["inputs"],
            "token_fields": token_fields,
        })
        mark = "◉" if f["method"] not in STATELESS_METHODS else "·"
        print(f"  {mark} {f['method'].upper():6} {action[:70]} "
              f"({'token:' + ','.join(token_fields) if token_fields else 'no token'})")

    cookies = cookies_from(headers)
    payload = {
        "generated_by": "enumerate_forms.py",
        "url": args.url,
        "status": status,
        "enumerated_at": datetime.now().isoformat(timespec="seconds"),
        "cookies": cookies,
        "forms": forms,
    }
    out = args.out or new_log_path("csrf_forms", "json")
    with open(out, "w") as fh:
        json.dump(payload, fh, indent=2)
    print(f"\n💾 {out}")
    print(f"   {len(forms)} forms "
          f"({sum(1 for f in forms if f['state_changing'])} state-changing), "
          f"{len(cookies)} cookies")


if __name__ == "__main__":
    main()
