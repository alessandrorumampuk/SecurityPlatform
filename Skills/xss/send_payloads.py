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
    expand_spec,
    fetch_rendered,
    send_curl,
    send_curl_meta,
    send_spec,
)
from core.types import RequestSpec, normalize_method  # noqa: E402
from log_utils import new_log_path  # noqa: E402

_MARKER_SPAN_RE = re.compile(
    re.escape(MARKER_START) + r"(.*?)" + re.escape(MARKER_END), re.DOTALL
)
_SHORT_MARKER_SPAN_RE = re.compile(
    re.escape(MARKER_START) + r"(.{0,200}?)" + re.escape(MARKER_END), re.DOTALL
)


def _bisect(
    spec: RequestSpec,
    items: Sequence[tuple[str, str]],
    out: list[dict[str, Any]],
    budget: list[int],
    body_encode: str = "raw",
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
    body, status = send_spec(spec, s, body_encode=body_encode)
    for attempt in range(3):
        if status not in ("429", "503"):
            break
        delay = min(4.0, 0.3 * (2 ** attempt)) + (
            secrets.randbelow(200) / 1000.0
        )
        time.sleep(delay)
        body, status = send_spec(spec, s, body_encode=body_encode)
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
    _bisect(spec, items[:mid], out, budget, body_encode)
    _bisect(spec, items[mid:], out, budget, body_encode)


def send_probe(
    spec: RequestSpec,
    items: Sequence[tuple[str, str]],
    vuln_name: str,
    kind: str,
    render: bool = False,
    body_encode: str = "raw",
) -> None:
    """Send a bounded multi-item probe and persist the response HTML +
    optional block/truncation attribution JSON."""
    input_str, seps = _probe_string(items)
    print(f"{kind}: {input_str}")
    url, data, headers = expand_spec(spec, input_str, body_encode=body_encode)
    print(f"{spec.method}: {url}")
    if data is not None:
        print(f"Body:  {data}")
    rmeta: dict[str, Any] = {"sinks": [], "fired": []}
    http_status = "200"

    if render and (spec.method.upper() != "GET" or data is not None):
        print(
            "[RENDER_SKIP] headless render only supports GET navigation — "
            "POST/body probes use the static fetch path"
        )
        render = False

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
        response, http_status = send_curl_meta(
            url, method=spec.method, data=data, headers=headers
        )
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
        f.write(f"<!-- http_method: {spec.method} -->\n")
        if spec.data is not None:
            f.write(f"<!-- data_template: {spec.data} -->\n")
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
        bbody, bstatus = send_spec(spec, base, body_encode=body_encode)
        base_ok = bool(_MARKER_SPAN_RE.search(bbody))
        attrib: dict[str, Any] = {
            "generated_by": "send_payloads.py",
            "generated_at": datetime.now().isoformat(),
            "url": spec.url,
            "method": spec.method,
            "data_template": spec.data,
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
                _bisect(spec, tail_items, verdicts, budget, body_encode)
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
            nbody, nstatus = send_spec(
                spec, NUMERIC_PROBE_MARKER, body_encode=body_encode
            )
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


def _reflects_verbatim(
    spec: RequestSpec, frag: str, body_encode: str = "raw"
) -> bool:
    """One-request shape pre-probe: returns `True` if `frag` is reflected
    verbatim in every occurrence bounded by the markers."""
    probe = MARKER_START + frag + MARKER_END
    url, data, headers = expand_spec(spec, probe, body_encode=body_encode)
    segs = _SHORT_MARKER_SPAN_RE.findall(
        send_curl(url, method=spec.method, data=data, headers=headers)
    )
    return bool(segs) and all(s == frag for s in segs)


def parens_ok(spec: RequestSpec, body_encode: str = "raw") -> bool:
    return _reflects_verbatim(spec, "(1)", body_encode)


def tick_ok(spec: RequestSpec, body_encode: str = "raw") -> bool:
    return _reflects_verbatim(spec, "`1`", body_encode)


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


def isolate_probe(spec: RequestSpec, body_encode: str = "raw") -> None:
    """Escalation probe: send each character alone (`testing1<c>testing2`)."""
    print("Isolation mode: one request per character")
    results: list[dict[str, Any]] = []
    for name, char in CHARACTERS:
        probe = MARKER_START + char + MARKER_END
        url, data, headers = expand_spec(spec, probe, body_encode=body_encode)
        response = send_curl(
            url, method=spec.method, data=data, headers=headers
        )
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
                "url": spec.url,
                "method": spec.method,
                "data_template": spec.data,
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
    parser.add_argument(
        "--method",
        help="HTTP method — any verb: GET/POST/PUT/PATCH/DELETE/OPTIONS/"
        "QUERY (default: GET, or POST when --data is present)",
    )
    parser.add_argument(
        "--data",
        help=(
            f"Request body template containing {PLACEHOLDER} "
            "(implies POST; --content-type selects the body format)"
        ),
    )
    parser.add_argument(
        "--content-type",
        help=(
            "Content-Type for --data (default: "
            "application/x-www-form-urlencoded)"
        ),
    )
    parser.add_argument(
        "--data-urlencoded",
        action="store_true",
        help="percent-encode the payload when substituting inside --data "
        "(default: verbatim, curl --data semantics)",
    )
    parser.add_argument(
        "--json-escape",
        action="store_true",
        help="escape the payload as a JSON string literal when substituting "
        "inside --data (default: raw — JSON-string breakout is testable)",
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="Name: Value",
        help=f"custom request header (repeatable; value may contain "
        f"{PLACEHOLDER})",
    )
    args = parser.parse_args()

    custom_headers: dict[str, str] = {}
    for h in args.header:
        k, sep, v = h.partition(":")
        if not sep or not k.strip():
            print(f"Error: malformed -H header {h!r} (expected 'Name: Value')")
            return
        custom_headers[k.strip()] = v.strip()

    content_type = args.content_type or "application/x-www-form-urlencoded"
    try:
        method = normalize_method(args.method, has_body=args.data is not None)
    except ValueError as e:
        print(f"Error: {e}")
        return
    if method == "HEAD":
        print(
            "[!] HEAD responses carry no body — reflection cannot be "
            "observed; probe results will be empty"
        )
    spec = RequestSpec(
        method=method,
        url=args.url,
        data=args.data,
        content_type=content_type,
        headers=custom_headers,
    )
    body_encode = (
        "json"
        if args.json_escape and "json" in content_type.lower()
        else "url"
        if args.data_urlencoded
        else "raw"
    )

    if not (
        PLACEHOLDER in spec.url
        or (spec.data is not None and PLACEHOLDER in spec.data)
        or any(PLACEHOLDER in v for v in spec.headers.values())
    ):
        print(f"Error: {PLACEHOLDER} must appear in --url, --data, or a -H header")
        print(f'Example: --url="https://example.com/search?q={PLACEHOLDER}"')
        print(
            f'         --url="https://example.com/comment" '
            f'--data="name={PLACEHOLDER}&msg=x"'
        )
        return

    if args.isolate:
        isolate_probe(spec, body_encode=body_encode)
        return

    kw_items = keyword_items() if args.probe2 else []
    if kw_items and not parens_ok(spec, body_encode):
        if tick_ok(spec, body_encode):
            print("[*] parens encoded/removed -> gen_* probes use `1` call form")
            kw_items = _tick_call_variants(kw_items)
        else:
            print(
                "[*] parens AND backtick dead -> gen_* shape probes drop the call (feature-only)"
            )
            kw_items = _bare_call_variants(kw_items)

    print("=" * 80)
    print("Send Payloads")
    print(f"Target: {spec.method} {spec.url}")
    if spec.data is not None:
        print(f"Body template: {spec.data} ({spec.content_type})")
    if spec.headers:
        print(
            "Headers: "
            + ", ".join(f"{k}={v[:40]}" for k, v in spec.headers.items())
        )
    print(f"Date: {datetime.now().isoformat()}")
    print(f"Characters: {', '.join(name for name, _ in CHARACTERS)}")
    if args.probe2:
        print(f"Keywords:  {', '.join(name for name, _ in kw_items)}")
    print("=" * 80)
    print()

    send_probe(
        spec,
        CHARACTERS,
        "xss",
        "Characters",
        render=args.render,
        body_encode=body_encode,
    )
    if args.probe2:
        send_probe(
            spec,
            kw_items,
            "xss_keywords",
            "Keywords",
            render=args.render,
            body_encode=body_encode,
        )


if __name__ == "__main__":
    main()
