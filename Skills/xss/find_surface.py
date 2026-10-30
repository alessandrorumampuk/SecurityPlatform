#!/usr/bin/env python3
"""
find_surface.py — XSS attack-surface discovery.

Finds every injectable parameter on a page before any payload is sent:
  1. Query params on the page URL itself
  2. <a href> links carrying query params (same host)
  3. Embedded element URLs (iframes, meta refresh, formaction, data-* attrs)
  4. Same-host <script src> params (JSONP callbacks & script query params)
  5. <form method=get> fields -> become URL params when submitted
  6. <form method=post> fields -> stored-XSS surface
  7. DOM-source params inside scripts (URLSearchParams, location.search/hash/pathname)
  8. Optional bucketed hidden-parameter mining (--mine)

Local lab / authorized targets only.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from typing import Any, Iterable
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.constants import (  # noqa: E402
    CALLBACK_RE as _CALLBACK_RE,
    COMMON_PARAMS,
    DEFAULT_UA as UA,
    DOM_HASH_RE as _DOM_HASH_RE,
    DOM_PARAM_RE as _DOM_PARAM_RE,
    DOM_PATH_RE as _DOM_PATH_RE,
    DOM_SEARCH_RE as _DOM_SEARCH_RE,
    PLACEHOLDER,
    POSTMSG_RE as _POSTMSG_RE,
    SURFACE_SINKS as _SINKS,
)
from core.context import (  # noqa: E402
    SurfaceParser,
    dom_extras,
    dom_source_params,
    param_templates,
)
from core.transport import fetch_url_with_base, send_curl  # noqa: E402
from log_utils import new_log_path  # noqa: E402


def find_surface(
    url: str, timeout: int = 15
) -> tuple[list[dict[str, str]], list[dict[str, Any]], dict[str, Any]]:
    """Fetch `url` and return `(targets, post_forms, dom_extras_dict)`."""
    host = urllib.parse.urlsplit(url).hostname or ""
    body, base = fetch_url_with_base(url, timeout=timeout)

    parser = SurfaceParser(host)
    parser._base = base
    parser.feed(body)

    targets: list[dict[str, str]] = []
    seen: set[str] = set()

    def push(tpl: str, param: str, typ: str) -> None:
        if tpl not in seen:
            seen.add(tpl)
            targets.append({"type": typ, "template": tpl, "param": param})

    # 1. Page URL params
    for tpl, key in param_templates(url, host):
        push(tpl, key, "page_param")

    # 2. Same-host anchor links with query params
    for href in parser.links:
        for tpl, key in param_templates(href, host):
            push(tpl, key, "link_param")

    # 2b. Query params on non-anchor elements/attrs
    for href in parser.embedded:
        for tpl, key in param_templates(href, host):
            push(tpl, key, "embedded_param")

    # 2c. Same-host <script src> params (JSONP callbacks vs script params)
    for src in parser.script_srcs:
        for tpl, key in param_templates(src, host):
            push(
                tpl,
                key,
                "jsonp_param" if _CALLBACK_RE.match(key) else "script_param",
            )

    # 3. GET form fields -> URL params; POST forms -> executable body surface
    post_forms: list[dict[str, Any]] = []
    post_seen: set[tuple[str, str]] = set()
    for f in parser.forms:
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
            defaults = f.get("all_fields") or {}
            post_forms.append({"action": u, "fields": f["fields"]})
            for name in f["fields"]:
                # One body template per injectable field: the target field
                # holds {xss_testing}, siblings keep their collected value
                # (csrf/hidden fields) or a benign filler.
                parts = [f"{name}={PLACEHOLDER}"] + [
                    f"{n}={urllib.parse.quote(v or 'x', safe='')}"
                    for n, v in defaults.items()
                    if n != name
                ]
                data = "&".join(parts)
                if (u, name) in post_seen:
                    continue
                post_seen.add((u, name))
                targets.append(
                    {
                        "type": "post_form",
                        "template": u,
                        "param": name,
                        "method": "POST",
                        "data": data,
                        "content_type": "application/x-www-form-urlencoded",
                        # A real browser form submission percent-encodes
                        # every value — without it, `&`/`=` inside the probe
                        # would corrupt the urlencoded body structure.
                        "body_encode": "url",
                    }
                )

    # 4. DOM-source params inside inline and same-host external scripts
    script_texts = list(parser.scripts)
    for src_url in parser.script_srcs[:6]:
        try:
            ext_body, _ = fetch_url_with_base(src_url, timeout=8)
            script_texts.append(ext_body)
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


def mine_hidden_params(
    url: str,
    existing_params: Iterable[str] | None = None,
    bucket_size: int = 36,
    timeout: int = 10,
) -> list[dict[str, str]]:
    """Bucketed query-parameter miner (Dalfox/Param-Miner pattern)."""
    existing = set(existing_params or ())
    u_base = urllib.parse.urlsplit(url)
    base_nf = urllib.parse.urlunsplit(u_base._replace(fragment=""))
    joiner = "&" if u_base.query else "?"
    cands = [p for p in COMMON_PARAMS if p not in existing]
    discovered: list[dict[str, str]] = []

    for i in range(0, len(cands), bucket_size):
        chunk = cands[i : i + bucket_size]
        canaries = [
            (p, f"vvmc{secrets.token_hex(3)}{idx:02d}")
            for idx, p in enumerate(chunk)
        ]
        qs = "&".join(f"{p}={c}" for p, c in canaries)
        probe_url = f"{base_nf}{joiner}{qs}"
        try:
            body = send_curl(probe_url, timeout=timeout)
        except Exception:
            continue
        hits = [p for p, c in canaries if c in body]
        if len(hits) > 3:
            hits = hits[:1]
        for p in hits:
            discovered.append(
                {
                    "type": "mined_param",
                    "template": f"{base_nf}{joiner}{p}={PLACEHOLDER}",
                    "param": p,
                }
            )
    return discovered


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Discover XSS attack surface (injectable parameters)"
    )
    ap.add_argument("--url", required=True, help="Page URL to inspect")
    ap.add_argument(
        "--out",
        help="Write results JSON to this path (also logged under Skills/log)",
    )
    ap.add_argument(
        "--max",
        type=int,
        default=0,
        help="Cap number of targets (0 = no cap)",
    )
    ap.add_argument(
        "--mine",
        action="store_true",
        help="Bucket-probe common hidden query parameters "
        "(also runs automatically when 0 visible params are found on the page)",
    )
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
        targets = targets[: args.max]

    result = {
        "url": args.url,
        "targets": targets,
        "post_forms": post_forms,
        "dom_extras": extras,
        "target_count": len(targets),
    }

    payload = json.dumps(result, indent=2)
    log_path = new_log_path("xss_surface", "json")
    with open(log_path, "w", encoding="utf-8") as fh:
        fh.write(payload)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(payload)

    print(
        f"XSS surface: {len(targets)} injectable param(s), "
        f"{len(post_forms)} POST form(s) (stored surface)"
    )
    for t in targets:
        print(f"  [{t['type']:11}] {t['param']:20} {t['template'][:80]}")
    for f in post_forms:
        print(
            f"  [{'post_form':11}] {','.join(f['fields']) or '-':20} "
            f"POST {f['action'][:80]}"
        )
    if extras["postmessage"]:
        print(
            "  note: 'message' event listener found — postMessage "
            "DOM-XSS surface (needs a crafted postMessage, not a URL)"
        )
    if extras["sinks"]:
        print(f"  note: DOM sinks present: {', '.join(extras['sinks'])}")
    print(f"saved -> {args.out or log_path}")


if __name__ == "__main__":
    main()
