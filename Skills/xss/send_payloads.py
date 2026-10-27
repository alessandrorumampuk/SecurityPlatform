#!/usr/bin/env python3
"""
send_payloads.py — Layer A (characters) & Layer B/C (keywords/junctions) probe sender.

Features:
  - Indexed non-colliding boundary tokens (`make_boundaries`)
  - Automatic request-level block bisection (`_bisect`) with 429/503 backoff
  - Partial-reflection truncation recovery & `NUMERIC_PROBE_MARKER` letter-stripper detection
  - Optional headless Chromium DOM sink & execution capture (`--render`)
  - Single-character escalation probe (`--isolate`)
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime
import json
import os
import re
import secrets
import sys
import time
from typing import Any, Sequence
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.boundary import (  # noqa: E402
    build_probe_string as _probe_string,
    extract_indexed_items as _extract_indexed,
    keyword_items,
    make_boundaries,
    random_tag_name,
)
from core.constants import (  # noqa: E402
    CHARACTERS,
    DEFAULT_UA as UA,
    KEYWORDS,
    MARKER_END,
    MARKER_START,
    NUMERIC_PROBE_MARKER,
    PLACEHOLDER,
    RENDER_HOOK_JS,
    SEPARATOR,
)
from core.transport import (  # noqa: E402
    _send_once,
    fetch_rendered,
    get_http_session as _get_session,
    send_curl,
    send_curl_meta,
)
from log_utils import new_log_path  # noqa: E402

_MARKER_SPAN_RE = re.compile(
    re.escape(MARKER_START) + r"(.*?)" + re.escape(MARKER_END), re.DOTALL
)
_SHORT_MARKER_SPAN_RE = re.compile(
    re.escape(MARKER_START) + r"(.{0,200}?)" + re.escape(MARKER_END), re.DOTALL
)


def _bisect(
    target_url: str,
    items: Sequence[tuple[str, str]],
    out: list[dict[str, Any]],
    budget: list[int],
) -> None:
    """Recursively bisect `items` to attribute which specific token(s)
    triggered a WAF request-level block (deny page)."""
    if not items:
        return
    if budget[0] <= 0:
        out += [
            {"name": n, "expected": v, "got": None, "verdict": "unresolved"}
            for n, v in items
        ]
        return
    s, seps = _probe_string(items)
    url = target_url.replace(PLACEHOLDER, urllib.parse.quote(s, safe=""))
    body, status = send_curl_meta(url)
    for attempt in range(3):
        if status not in ("429", "503"):
            break
        delay = min(4.0, 0.3 * (2 ** attempt)) + (
            secrets.randbelow(200) / 1000.0
        )
        time.sleep(delay)
        body, status = send_curl_meta(url)
    budget[0] -= 1
    m = _MARKER_SPAN_RE.search(body)
    if m:
        parts = _extract_indexed(m.group(1), seps, len(items))
        for (n, v), got in zip(items, parts):
            out.append(
                {
                    "name": n,
                    "expected": v,
                    "got": got,
                    "verdict": (
                        "passed"
                        if got == v
                        else "indeterminate"
                        if got is None
                        else "transformed"
                    ),
                }
            )
        return
    if status in ("429", "503"):
        out += [
            {
                "name": n,
                "expected": v,
                "got": None,
                "verdict": "unresolved",
                "status": status,
            }
            for n, v in items
        ]
        return
    if len(items) == 1:
        out.append(
            {
                "name": items[0][0],
                "expected": items[0][1],
                "got": None,
                "verdict": "blocked",
                "status": status,
            }
        )
        return
    mid = len(items) // 2
    _bisect(target_url, items[:mid], out, budget)
    _bisect(target_url, items[mid:], out, budget)


def send_probe(
    target_url: str,
    items: Sequence[tuple[str, str]],
    vuln_name: str,
    kind: str,
    render: bool = False,
) -> None:
    """Send a bounded multi-item probe and persist the response HTML +
    optional block/truncation attribution JSON."""
    input_str, seps = _probe_string(items)
    print(f"{kind}: {input_str}")
    encoded = urllib.parse.quote(input_str, safe="")
    url = target_url.replace(PLACEHOLDER, encoded)
    print(f"URL:   {url}")
    rmeta: dict[str, Any] = {"sinks": [], "fired": []}
    http_status = "200"

    if render:
        try:
            response, rmeta = fetch_rendered(url)
        except Exception as e:
            print(f"[RENDER_ERROR] {e}")
            print(
                "hint: pip install playwright && playwright install chromium"
            )
            return
        print(
            f"Rendered DOM: {len(response)} chars | "
            f"sinks: {sorted({n for n, _ in rmeta['sinks']}) or 'none'} | "
            f"fired: {rmeta['fired'] or 'none'}"
        )
    else:
        response, http_status = send_curl_meta(url)
        print(f"Response length: {len(response)} (HTTP {http_status})")

    html_file = new_log_path(vuln_name, "html")
    with open(html_file, "w", encoding="utf-8") as f:
        f.write("<!-- generated_by: send_payloads.py -->\n")
        f.write(f"<!-- generated_at: {datetime.now().isoformat()} -->\n")
        f.write(f"<!-- probe_mode: {'render' if render else 'curl'} -->\n")
        f.write(f"<!-- input_sent: {input_str} -->\n")
        f.write("<!-- separator: indexed -->\n")
        f.write(f"<!-- seps_json: {json.dumps(seps)} -->\n")
        f.write(f"<!-- items_json: {json.dumps(list(items))} -->\n")
        f.write(
            f"<!-- {kind.lower()}_names: {', '.join(n for n, _ in items)} -->\n"
        )
        f.write(f"<!-- url: {url} -->\n")
        f.write(f"<!-- response_length: {len(response)} -->\n")
        if render:
            sinks_b64 = base64.b64encode(
                json.dumps(rmeta["sinks"]).encode()
            ).decode()
            f.write(f"<!-- sinks_b64: {sinks_b64} -->\n")
            f.write(f"<!-- fired_json: {json.dumps(rmeta['fired'])} -->\n")
        f.write(response)
    print(f"Saved: {html_file}\n")

    full_match = _MARKER_SPAN_RE.search(response)
    if not render and not full_match:
        pre_verdicts: list[dict[str, Any]] = []
        tail_items = list(items)
        max_len: int | None = None
        p_start = response.find(MARKER_START + seps[0]) if seps else -1
        if p_start >= 0:
            seg = response[p_start + len(MARKER_START) :]
            bpos = [seg.find(b) for b in seps]
            k = 0
            for i in range(len(items)):
                if bpos[i] >= 0 and bpos[i + 1] > bpos[i]:
                    got = seg[bpos[i] + len(seps[i]) : bpos[i + 1]]
                    n, v = items[i]
                    pre_verdicts.append(
                        {
                            "name": n,
                            "expected": v,
                            "got": got,
                            "verdict": "passed" if got == v else "transformed",
                        }
                    )
                    k = i + 1
                else:
                    break
            if k > 0:
                tail_items = list(items[k:])
                max_len = len(MARKER_START) + bpos[k] + len(seps[k])
                print(
                    f"[ANOMALY] Partial reflection (MARKER_END missing) — "
                    f"recovered {k}/{len(items)} leading item(s) "
                    f"(~{max_len} chars before cut)."
                )
        if not pre_verdicts:
            print(
                "[ANOMALY] No complete markers in response — possible "
                "request-level block (deny page) or truncation. Checking "
                "baseline reflection…"
            )
        base = MARKER_START + secrets.token_hex(4) + MARKER_END
        burl = target_url.replace(
            PLACEHOLDER, urllib.parse.quote(base, safe="")
        )
        bbody, bstatus = send_curl_meta(burl)
        base_ok = bool(_MARKER_SPAN_RE.search(bbody))
        attrib: dict[str, Any] = {
            "generated_by": "send_payloads.py",
            "generated_at": datetime.now().isoformat(),
            "url": target_url,
            "kind": kind,
            "http_status": http_status,
            "baseline_status": bstatus,
            "baseline_reflects": base_ok,
            "baseline_marker": base,
            "baseline_body": bbody,
            "max_len": max_len,
        }
        if base_ok or pre_verdicts:
            verdicts = list(pre_verdicts)
            if tail_items:
                print(
                    f"          bisecting {len(tail_items)} remaining item(s)…"
                )
                max_b = 2 * len(tail_items) + 16
                budget = [max_b]
                _bisect(target_url, tail_items, verdicts, budget)
                used_reqs = max_b - budget[0]
            else:
                used_reqs = 0
            blocked = [
                v["name"] for v in verdicts if v["verdict"] == "blocked"
            ]
            attrib["verdicts"] = verdicts
            print(
                f"          blocked: {blocked or 'none'} "
                f"({used_reqs} probe requests)"
            )
        else:
            attrib["verdicts"] = []
            nurl = target_url.replace(PLACEHOLDER, NUMERIC_PROBE_MARKER)
            nbody, nstatus = send_curl_meta(nurl)
            num_ok = (
                NUMERIC_PROBE_MARKER in nbody
                and NUMERIC_PROBE_MARKER not in bbody
            )
            attrib["numeric_reflects"] = num_ok
            attrib["numeric_status"] = nstatus
            if num_ok:
                attrib["baseline_body"] = nbody
                attrib["baseline_marker"] = NUMERIC_PROBE_MARKER
                print(
                    f"          numeric probe ({NUMERIC_PROBE_MARKER}) "
                    "REFLECTS -> letter-stripping filter detected!"
                )
            else:
                print(
                    "          baseline does NOT reflect -> dead surface / "
                    "blanket block; per-item attribution impossible"
                )
        apath = html_file.replace(".html", "_attribution.json")
        with open(apath, "w", encoding="utf-8") as f:
            json.dump(attrib, f, indent=2, ensure_ascii=False)
        print(f"Saved: {apath}\n")


def _reflects_verbatim(target_url: str, frag: str) -> bool:
    """One-request shape pre-probe: returns `True` if `frag` is reflected
    verbatim in every occurrence bounded by the markers."""
    probe = MARKER_START + frag + MARKER_END
    url = target_url.replace(PLACEHOLDER, urllib.parse.quote(probe, safe=""))
    segs = _SHORT_MARKER_SPAN_RE.findall(send_curl(url))
    return bool(segs) and all(s == frag for s in segs)


def parens_ok(target_url: str) -> bool:
    return _reflects_verbatim(target_url, "(1)")


def tick_ok(target_url: str) -> bool:
    return _reflects_verbatim(target_url, "`1`")


def _tick_call_variants(
    items: Sequence[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Swap `()` -> `` `1` `` inside `gen_*` shape probes when parens are dead."""
    out: list[tuple[str, str]] = []
    for name, value in items:
        if name.startswith("gen_") and name != "gen_call" and "(" in value:
            value = value.replace("(1)", "`1`").replace("()", "`1`")
        out.append((name, value))
    return out


def _bare_call_variants(
    items: Sequence[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Strip call syntax from `gen_*` shape probes when both `()` and `` ` `` are dead."""
    out: list[tuple[str, str]] = []
    for name, value in items:
        if name.startswith("gen_") and name not in ("gen_call", "gen_tick"):
            for dead in ("(1)", "()", "`1`"):
                value = value.replace(dead, "")
        out.append((name, value))
    return out


def isolate_probe(target_url: str) -> None:
    """Escalation probe: send each character alone (`testing1<c>testing2`)."""
    print("Isolation mode: one request per character")
    results: list[dict[str, Any]] = []
    for name, char in CHARACTERS:
        probe = MARKER_START + char + MARKER_END
        url = target_url.replace(
            PLACEHOLDER, urllib.parse.quote(probe, safe="")
        )
        response = send_curl(url)
        reflected_ok = probe in response
        m = _SHORT_MARKER_SPAN_RE.search(response)
        got = m.group(1) if m else None
        if reflected_ok:
            verdict, status = "unchanged", 100
        elif got is not None:
            verdict, status = "transformed", 50
        else:
            verdict, status = "rejected", 0
        results.append(
            {
                "character_name": name,
                "character": char,
                "reflected": got,
                "verdict": verdict,
                "score": status,
            }
        )
        print(f"  {name:<15} {char!r:<6} -> {verdict} (got: {got!r})")

    out_file = new_log_path("xss_isolation", "json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "generated_by": "send_payloads.py --isolate",
                "generated_at": datetime.now().isoformat(),
                "url": target_url,
                "results": results,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    print(f"Saved: {out_file}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send XSS test payloads to a target URL"
    )
    parser.add_argument(
        "--url",
        required=True,
        help=(
            f"Target URL with {PLACEHOLDER} placeholder "
            f'(example: --url="https://example.com/search?q={PLACEHOLDER}")'
        ),
    )
    parser.add_argument(
        "--probe2",
        action="store_true",
        help="also send the Layer B/C keyword-mask probe (saved as *-xss_keywords.html)",
    )
    parser.add_argument(
        "--isolate",
        action="store_true",
        help="escalation probe: send each character alone testing1<c>testing2 "
        "(saved as *-xss_isolation.json)",
    )
    parser.add_argument(
        "--render",
        action="store_true",
        help="fetch via headless chromium instead of curl to capture DOM sinks",
    )
    args = parser.parse_args()

    target_url = args.url
    if PLACEHOLDER not in target_url:
        print(f"Error: URL must contain {PLACEHOLDER} placeholder")
        print(f'Example: --url="https://example.com/search?q={PLACEHOLDER}"')
        return

    if args.isolate:
        isolate_probe(target_url)
        return

    kw_items = keyword_items() if args.probe2 else []
    if kw_items and not parens_ok(target_url):
        if tick_ok(target_url):
            print("[*] parens encoded/removed -> gen_* probes use `1` call form")
            kw_items = _tick_call_variants(kw_items)
        else:
            print(
                "[*] parens AND backtick dead -> gen_* shape probes drop the call (feature-only)"
            )
            kw_items = _bare_call_variants(kw_items)

    print("=" * 80)
    print("Send Payloads")
    print(f"Target: {target_url}")
    print(f"Date: {datetime.now().isoformat()}")
    print(f"Characters: {', '.join(name for name, _ in CHARACTERS)}")
    if args.probe2:
        print(f"Keywords:  {', '.join(name for name, _ in kw_items)}")
    print("=" * 80)
    print()

    send_probe(
        target_url, CHARACTERS, "xss", "Characters", render=args.render
    )
    if args.probe2:
        send_probe(
            target_url,
            kw_items,
            "xss_keywords",
            "Keywords",
            render=args.render,
        )


if __name__ == "__main__":
    main()
