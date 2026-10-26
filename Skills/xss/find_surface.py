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
import secrets
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
        self.embedded = []       # query URLs in non-anchor attrs (iframe,
                                 # data-*, formaction, meta refresh, ...)
        self.forms = []          # {action, method, fields:[names]}
        self.scripts = []        # inline script bodies
        self.script_srcs = []    # same-host external script URLs
        self._form = None        # form currently being parsed
        self._in_script = False
        self._script_buf = []

    def _collect_embedded(self, raw):
        u = self._absolute(self._base, raw)
        if u and urllib.parse.urlsplit(u).hostname == self.host \
                and urllib.parse.urlsplit(u).query:
            self.embedded.append(u)

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

        # query-bearing URLs hide outside <a href> too: embedded frames,
        # per-button formaction overrides, meta refresh targets, and
        # SPA-style data-* URL stashes all hit real endpoints.
        if tag == "meta" and \
                "refresh" in (d.get("http-equiv") or "").lower():
            m = re.search(r"url\s*=\s*([^;]+)", d.get("content") or "",
                          re.I)
            if m:
                self._collect_embedded(m.group(1).strip(" '\""))
        elif tag in ("iframe", "frame", "embed", "object", "video",
                     "audio", "source", "track", "area", "base"):
            for k in ("src", "data", "href", "poster"):
                if d.get(k):
                    self._collect_embedded(d[k])
        for k, v in d.items():
            if not v:
                continue
            if k == "formaction" or (k.startswith("data-") and any(
                    t in k for t in ("url", "href", "src", "link",
                                     "api", "ajax", "endpoint"))):
                self._collect_embedded(v)

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

# JSONP-style callback params reflect the value back inside a JS call —
# a script src carrying one is its own reflected-XSS channel.
_CALLBACK_RE = re.compile(
    r"^(callback|cb|jsonp|jsonpcallback|json_callback|jsonpcb|call|"
    r"func|method|cbfn|onload)$", re.I)

# Non-URL DOM sources + sinks: annotates the dom_* templates. postMessage
# reads are attacker-controllable but cannot be expressed as a URL
# template, so they are reported as a note rather than a target.
_POSTMSG_RE = re.compile(
    r"""addEventListener\(\s*["']message["']|\.onmessage\s*=""")
_SINKS = {
    "innerHTML": re.compile(r"\.innerHTML\s*="),
    "outerHTML": re.compile(r"\.outerHTML\s*="),
    "document.write": re.compile(r"document\.write(?:ln)?\s*\("),
    "eval()": re.compile(r"\beval\s*\("),
    "new Function()": re.compile(r"new\s+Function\s*\("),
    "setTimeout(string)": re.compile(r"""setTimeout\s*\(\s*["']"""),
    "insertAdjacentHTML": re.compile(r"insertAdjacentHTML\s*\("),
    ".html()": re.compile(r"\.html\s*\("),
}


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


def dom_extras(script_texts):
    """Return (postmessage_source_seen, sorted_sink_names)."""
    postmsg = any(_POSTMSG_RE.search(s) for s in script_texts)
    sinks = sorted(n for n, rx in _SINKS.items()
                   if any(rx.search(s) for s in script_texts))
    return postmsg, sinks


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

    # 2b. query params on non-anchor elements/attrs (iframes, data-*,
    #     formaction, meta refresh, ...)
    for href in p.embedded:
        for tpl, key in param_templates(href, host):
            push(tpl, key, "embedded_param")

    # 2c. same-host <script src> params — JSONP callbacks reflect into a
    #     JS context without ever appearing in markup.
    for src in p.script_srcs:
        for tpl, key in param_templates(src, host):
            push(tpl, key,
                 "jsonp_param" if _CALLBACK_RE.match(key)
                 else "script_param")

    # 3. GET form fields -> URL params; the action URL's own params are
    #    reflected surface too regardless of method.
    post_forms = []
    for f in p.forms:
        action = f["action"] or base
        u = urllib.parse.urljoin(base, action)
        if urllib.parse.urlsplit(u).hostname != host:
            continue
        for tpl, key in param_templates(u, host):
            push(tpl, key, "form_action")
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
    postmsg, sinks = dom_extras(script_texts)
    for name in sorted(dom_names):
        push(f"{base_nf}{joiner}{name}={PLACEHOLDER}", name, "dom_param")
    if dom_search:
        push(f"{base_nf}{joiner}q={PLACEHOLDER}", "q", "dom_search")
    if dom_hash:
        push(f"{base_nf}#{PLACEHOLDER}", "hash", "dom_hash")
    if dom_path:
        push(f"{base_nf.rstrip('/')}/{PLACEHOLDER}", "path", "dom_path")

    return targets, post_forms, {"postmessage": postmsg, "sinks": sinks}


# Curated high-signal parameter names for bucketed hidden-parameter mining
COMMON_PARAMS = [
    "q", "s", "search", "query", "keyword", "keywords", "id", "page",
    "url", "redirect", "next", "return", "returnUrl", "callback", "cb",
    "jsonp", "name", "user", "username", "msg", "message", "error", "err",
    "title", "text", "body", "content", "html", "data", "input", "val",
    "value", "view", "template", "tpl", "file", "path", "folder", "dir",
    "lang", "locale", "type", "cat", "category", "sort", "order", "filter",
    "ref", "source", "src", "dest", "target", "action", "cmd", "debug",
    "test", "echo", "tag", "term", "token", "code", "email", "key", "item",
    "out", "format", "style", "theme", "color", "label", "comment", "note",
]


def mine_hidden_params(url, existing_params=None, bucket_size=36, timeout=10):
    """Bucketed query-parameter miner (Dalfox/Param-Miner pattern):
    packs `bucket_size` candidate names into a single GET request with a
    unique canary per name (O(N/B) requests instead of O(N)), and collapses
    buckets where >3 canaries echo together (whole-query-string reflection
    like canonical links) into a single representative parameter."""
    existing = set(existing_params or ())
    u_base = urllib.parse.urlsplit(url)
    base_nf = urllib.parse.urlunsplit(u_base._replace(fragment=""))
    joiner = "&" if u_base.query else "?"
    cands = [p for p in COMMON_PARAMS if p not in existing]
    discovered = []
    for i in range(0, len(cands), bucket_size):
        chunk = cands[i:i + bucket_size]
        canaries = [(p, f"vvmc{secrets.token_hex(3)}{idx:02d}")
                    for idx, p in enumerate(chunk)]
        qs = "&".join(f"{p}={c}" for p, c in canaries)
        probe_url = f"{base_nf}{joiner}{qs}"
        try:
            req = urllib.request.Request(probe_url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", errors="replace")
        except Exception:
            continue
        hits = [p for p, c in canaries if c in body]
        if len(hits) > 3:
            # Whole query string echoed (e.g. canonical link); keep 1 representative
            hits = hits[:1]
        for p in hits:
            discovered.append({
                "type": "mined_param",
                "template": f"{base_nf}{joiner}{p}={PLACEHOLDER}",
                "param": p,
            })
    return discovered


def main():
    ap = argparse.ArgumentParser(
        description="Discover XSS attack surface (injectable parameters)")
    ap.add_argument("--url", required=True, help="Page URL to inspect")
    ap.add_argument("--out", help="Write results JSON to this path "
                                  "(also logged under Skills/log)")
    ap.add_argument("--max", type=int, default=0,
                    help="Cap number of targets (0 = no cap)")
    ap.add_argument("--mine", action="store_true",
                    help="Bucket-probe common hidden query parameters "
                         "(also runs automatically when 0 visible params "
                         "are found on the page)")
    args = ap.parse_args()

    targets, post_forms, extras = find_surface(args.url)
    if args.mine or not targets:
        known = {t["param"] for t in targets}
        mined = mine_hidden_params(args.url, existing_params=known)
        seen_tpls = {t["template"] for t in targets}
        for mt in mined:
            if mt["template"] not in seen_tpls:
                seen_tpls.add(mt["template"])
                targets.append(mt)
    if args.max:
        targets = targets[:args.max]

    result = {"url": args.url,
              "targets": targets,
              "post_forms": post_forms,
              "dom_extras": extras,
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
    if extras["postmessage"]:
        print("  note: 'message' event listener found — postMessage "
              "DOM-XSS surface (needs a crafted postMessage, not a URL)")
    if extras["sinks"]:
        print(f"  note: DOM sinks present: {', '.join(extras['sinks'])}")
    print(f"saved -> {args.out or log_path}")


if __name__ == "__main__":
    main()
