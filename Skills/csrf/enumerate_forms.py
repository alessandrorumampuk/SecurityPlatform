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
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime
from html.parser import HTMLParser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import new_log_path

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")

TOKEN_RE = re.compile(
    r"csrf|token|authenticity|xsrf|nonce|verify|__request", re.I)

# Login/registration forms are excluded from replay targets: login CSRF
# has no meaningful impact (it only logs the victim into the attacker's
# account) and registration CSRF creates no state under the victim's
# identity.
LOGIN_RE = re.compile(r"login|log-?in|sign-?in|masuk|auth", re.I)
REGISTER_RE = re.compile(
    r"register|sign-?up|daftar|create.?account|registrasi", re.I)

# Query params that strongly suggest a state-changing GET endpoint --
# a GET that mutates is CSRF-able even under SameSite=Lax cookies.
ACTION_PARAM_RE = re.compile(
    r"^(action|do|cmd|op|task|exec|act|func|method|mode|verb|"
    r"delete|del|remove|drop|edit|update|modify|add|create|insert|"
    r"set|change|save|store|approve|confirm|activate|deactivate|"
    r"disable|enable|unsubscribe|ban|promote|demote|grant|revoke|"
    r"reset|publish|unpublish|hide|move|copy|duplicate|transfer|"
    r"pay|invoice|cancel|reject|accept|verify|impersonate|switch|"
    r"hapus|ubah|tambah|simpan|kirim|setuju|tolak|batal|aktif|nonaktif)$",
    re.I)

STATELESS_METHODS = ("get", "head", "options")


class FormParser(HTMLParser):
    """Collect <form> structure plus input/select/textarea fields."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.links = []          # raw <a href> values, for GET action scan
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._form = {"action": a.get("action", ""),
                          "method": (a.get("method") or "get").lower(),
                          "id": a.get("id", ""), "name": a.get("name", ""),
                          "inputs": []}
            self.forms.append(self._form)
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
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


def form_kind(form: dict) -> str:
    """Classify a form as login / register / other from its action,
    id/name attributes, and password-field count."""
    hay = " ".join([form.get("action") or "",
                    form.get("id") or "",
                    form.get("name") or ""])
    npass = sum(1 for i in form["inputs"]
                if (i.get("type") or "") == "password")
    if REGISTER_RE.search(hay) or npass >= 2:
        return "register"
    if npass == 1 or LOGIN_RE.search(hay):
        return "login"
    return "other"


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
        kind = form_kind(f)
        forms.append({
            "action": action,
            "method": f["method"],
            "kind": kind,
            "state_changing": f["method"] not in STATELESS_METHODS,
            "inputs": f["inputs"],
            "token_fields": token_fields,
        })
        mark = "◉" if f["method"] not in STATELESS_METHODS else "·"
        print(f"  {mark} {f['method'].upper():6} {action[:70]} "
              f"({'token:' + ','.join(token_fields) if token_fields else 'no token'}"
              f"{'; ' + kind if kind != 'other' else ''})")

    # State-changing GET surface: same-host links carrying action-ish
    # params (?action=delete&id=) stay CSRF-able under SameSite=Lax.
    host = urllib.parse.urlsplit(args.url).hostname or ""
    get_links = []
    for href in p.links:
        u = urllib.parse.urljoin(args.url, href)
        sp = urllib.parse.urlsplit(u)
        if sp.hostname != host or not sp.query:
            continue
        keys = [seg.split("=", 1)[0].lower()
                for seg in sp.query.split("&")]
        if any(ACTION_PARAM_RE.match(k) for k in keys):
            get_links.append(u.split("#", 1)[0])
    for l in sorted(set(get_links)):
        print(f"  ? GET  {l[:80]}")

    # CSWSH surface (CWE-1385): ws(s) endpoints only stay safe if the
    # server validates Origin in the upgrade handshake.
    websockets = sorted(set(
        re.findall(r"""wss?://[^\s"'<>\\()]+""", html)))
    for w in websockets:
        print(f"  ⚡ WS   {w}")

    cookies = cookies_from(headers)
    payload = {
        "generated_by": "enumerate_forms.py",
        "url": args.url,
        "status": status,
        "enumerated_at": datetime.now().isoformat(timespec="seconds"),
        "cookies": cookies,
        "forms": forms,
        "get_links": sorted(set(get_links)),
        "websockets": websockets,
    }
    out = args.out or new_log_path("csrf_forms", "json")
    with open(out, "w") as fh:
        json.dump(payload, fh, indent=2)
    print(f"\n💾 {out}")
    print(f"   {len(forms)} forms "
          f"({sum(1 for f in forms if f['state_changing'])} state-changing, "
          f"{sum(1 for f in forms if f.get('kind') in ('login', 'register'))} "
          f"login/register), {len(set(get_links))} GET action link(s), "
          f"{len(websockets)} websocket endpoint(s), {len(cookies)} cookies")


if __name__ == "__main__":
    main()
