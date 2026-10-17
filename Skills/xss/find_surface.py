#!/usr/bin/env python3
"""
find_surface.py -- XSS attack-surface discovery.

Finds every injectable parameter on a page, before any payload is sent:

    1. query params on the page URL itself
    2. <a href> links carrying query params (same host)
    3. <form method=get> fields  -> become URL params when submitted
    4. <form method=post> fields -> stored-XSS surface (listed, not
       turned into URL templates; needs the stored checker)
    5. DOM-source params hidden inside scripts — params.get("name"),
       location.search, location.hash never appear in HTML, so the
       script source itself is grepped for them

Each entry becomes one {xss_testing} template per parameter so
send_payloads.py can substitute it directly.

Usage:
    python3 find_surface.py --url http://target/page --out surface.json

Output JSON:
    {"url": ..., "targets": [{"type": "page_param"|"link_param"|"get_form",
                              "template": "...?q={xss_testing}",
                              "param": "q"}],
     "post_forms": [{"action": ..., "fields": [...]}]}

Local lab / authorized targets only.
"""
import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from html.parser import HTMLParser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import new_log_path

PLACEHOLDER = "{xss_testing}"
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")


class SurfaceParser(HTMLParser):
    """Collect same-host links with query params and all forms."""

    def __init__(self, host):
        super().__init__(convert_charrefs=True)
        self.host = host
        self.links = []          # absolute hrefs with a query
        self.forms = []          # {action, method, fields:[names]}
        self.scripts = []        # inline script bodies
        self.script_srcs = []    # same-host external script URLs
        self._form = None        # form currently being parsed
        self._in_script = False
        self._script_buf = []

    def _absolute(self, base, href):
        try:
            u = urllib.parse.urljoin(base, href)
        except Exception:
            return None
        if urllib.parse.urlsplit(u).scheme not in ("http", "https"):
            return None
        return u

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "script":
            self._in_script = True
            self._script_buf = []
            src = d.get("src")
            if src:
                u = self._absolute(self._base, src)
                if u and urllib.parse.urlsplit(u).hostname == self.host:
                    self.script_srcs.append(u)
        elif tag == "a" and d.get("href"):
            u = self._absolute(self._base, d["href"])
            if u and urllib.parse.urlsplit(u).hostname == self.host \
                    and urllib.parse.urlsplit(u).query:
                self.links.append(u)
        elif tag == "form":
            self._form = {"action": d.get("action", ""),
                          "method": (d.get("method") or "get").lower(),
                          "fields": []}
        elif self._form is not None and tag in ("input", "textarea",
                                                "select"):
            name = d.get("name")
            ftype = (d.get("type") or "text").lower()
            if name and ftype not in ("hidden", "submit", "button",
                                      "image", "reset"):
                self._form["fields"].append(name)

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "script" and self._in_script:
            self.scripts.append("".join(self._script_buf))
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)


def param_templates(url, host):
    """One {xss_testing} template per query param of a same-host URL."""
    u = urllib.parse.urlsplit(url)
    if (u.hostname or "") != host or not u.query:
        return []
    segs = u.query.split("&")
    out = []
    for i, seg in enumerate(segs):
        key = seg.split("=", 1)[0]
        if not key:
            continue
        q = "&".join(s if j != i else f"{key}={PLACEHOLDER}"
                     for j, s in enumerate(segs))
        out.append((urllib.parse.urlunsplit(u._replace(query=q)), key))
    return out


# DOM sources: location.search/location.hash/URLSearchParams feed sinks like
# document.write/innerHTML without the param ever appearing in the HTML.
#   .get("name")/.has("name")/.getAll("name") -> exact param name known
#   bare location.search/document.URL reads  -> generic ?q= template
#   location.hash reads                      -> #fragment template
#   location.pathname reads                  -> payload as path segment
_DOM_PARAM_RE = re.compile(r"""\.(?:get|getAll|has)\(\s*["']([\w-]+)["']""")
_DOM_SEARCH_RE = re.compile(
    r"location\.search\b|location\.href\b|document\.(?:URL|documentURI)\b")
_DOM_HASH_RE = re.compile(r"location\.hash\b")
_DOM_PATH_RE = re.compile(r"location\.pathname\b")


def dom_source_params(script_texts):
    """Return (param_names, reads_search, reads_hash, reads_path)."""
    names, search, hash_, path = set(), False, False, False
    for src in script_texts:
        names.update(_DOM_PARAM_RE.findall(src))
        if _DOM_SEARCH_RE.search(src):
            search = True
        if _DOM_HASH_RE.search(src):
            hash_ = True
        if _DOM_PATH_RE.search(src):
            path = True
    return names, search, hash_, path


def find_surface(url, timeout=15):
    """Fetch the page and return (targets, post_forms)."""
    host = urllib.parse.urlsplit(url).hostname or ""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read().decode("utf-8", errors="replace")
        base = r.url

    p = SurfaceParser(host)
    p._base = base
    p.feed(body)

    targets, seen = [], set()

    def push(tpl, param, typ):
        if tpl not in seen:
            seen.add(tpl)
            targets.append({"type": typ, "template": tpl, "param": param})

    # 1. page URL params
    for tpl, key in param_templates(url, host):
        push(tpl, key, "page_param")

    # 2. same-host links with query params
    for href in p.links:
        for tpl, key in param_templates(href, host):
            push(tpl, key, "link_param")

    # 3. GET form fields -> URL params
    post_forms = []
    for f in p.forms:
        action = f["action"] or base
        u = urllib.parse.urljoin(base, action)
        if urllib.parse.urlsplit(u).hostname != host:
            continue
        if f["method"] == "get":
            for name in f["fields"]:
                tpl = u.split("?")[0] + f"?{name}={PLACEHOLDER}"
                push(tpl, name, "get_form")
        else:
            post_forms.append({"action": u, "fields": f["fields"]})

    # 4. DOM-source params inside scripts — invisible in markup:
    #    params.get("name") -> ?name= template; bare location.search read
    #    -> generic ?q= ; location.hash read -> #fragment template.
    script_texts = list(p.scripts)
    for src_url in p.script_srcs[:6]:
        try:
            sreq = urllib.request.Request(src_url, headers={"User-Agent": UA})
            with urllib.request.urlopen(sreq, timeout=8) as r:
                script_texts.append(r.read().decode("utf-8", errors="replace"))
        except Exception:
            pass
    u_base = urllib.parse.urlsplit(base)
    base_nf = urllib.parse.urlunsplit(u_base._replace(fragment=""))
    joiner = "&" if u_base.query else "?"
    dom_names, dom_search, dom_hash, dom_path = dom_source_params(script_texts)
    for name in sorted(dom_names):
        push(f"{base_nf}{joiner}{name}={PLACEHOLDER}", name, "dom_param")
    if dom_search:
        push(f"{base_nf}{joiner}q={PLACEHOLDER}", "q", "dom_search")
    if dom_hash:
        push(f"{base_nf}#{PLACEHOLDER}", "hash", "dom_hash")
    if dom_path:
        push(f"{base_nf.rstrip('/')}/{PLACEHOLDER}", "path", "dom_path")

    return targets, post_forms


def main():
    ap = argparse.ArgumentParser(
        description="Discover XSS attack surface (injectable parameters)")
    ap.add_argument("--url", required=True, help="Page URL to inspect")
    ap.add_argument("--out", help="Write results JSON to this path "
                                  "(also logged under Skills/log)")
    ap.add_argument("--max", type=int, default=0,
                    help="Cap number of targets (0 = no cap)")
    args = ap.parse_args()

    targets, post_forms = find_surface(args.url)
    if args.max:
        targets = targets[:args.max]

    result = {"url": args.url,
              "targets": targets,
              "post_forms": post_forms,
              "target_count": len(targets)}

    payload = json.dumps(result, indent=2)
    log_path = new_log_path("xss_surface", "json")
    with open(log_path, "w", encoding="utf-8") as fh:
        fh.write(payload)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(payload)

    print(f"XSS surface: {len(targets)} injectable param(s), "
          f"{len(post_forms)} POST form(s) (stored surface)")
    for t in targets:
        print(f"  [{t['type']:11}] {t['param']:20} {t['template'][:80]}")
    for f in post_forms:
        print(f"  [{'post_form':11}] {','.join(f['fields']) or '-':20} "
              f"POST {f['action'][:80]}")
    print(f"saved -> {args.out or log_path}")


if __name__ == "__main__":
    main()
