#!/usr/bin/env python3
"""
check_reflection.py — Reflection & filter analyzer for Layer A (chars) and Layer B/C (keywords).

Reads the latest `*-xss.html` or `*-xss_keywords.html` response log, extracts
reflected items via indexed boundaries, determines HTML/JS reflection contexts
and structural JS closers, recovers bisect/partial-truncation/letter-stripper
attributions, and writes `*-xss_reflection_analysis.json` / `*-xss_keyword_analysis.json`.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime
import json
import os
import re
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.boundary import (  # noqa: E402
    extract_indexed_items as extract_items,
    extract_reflected_all,
    items_from_meta,
    parse_html_meta as parse_meta,
    split_by_separator,
    strip_html_comments,
)
from core.constants import (  # noqa: E402
    CHARACTERS,
    DOM_JS_SINKS as _DOM_JS_SINKS,
    DOM_SINK_CTX,
    DOM_SINK_HINT_RE as _DOM_SINK_RE,
    DOM_SRC_HINT_RE as _DOM_SRC_RE,
    DOM_URL_SINKS as _DOM_URL_SINKS,
    MARKER_END,
    MARKER_START,
    SEPARATOR,
)
from core.context import (  # noqa: E402
    _parse_open_tag_before,
    compute_js_breakout,
    detect_reflection_context,
    inspect_reflection_point,
)
from log_utils import latest_log_path, new_log_path  # noqa: E402

_MARKER_SPAN_RE = re.compile(
    re.escape(MARKER_START) + r"(.*?)" + re.escape(MARKER_END), re.DOTALL
)


def _decode_sinks(meta: dict[str, str]) -> list[list[str]]:
    if not meta.get("sinks_b64"):
        return []
    try:
        return json.loads(
            base64.b64decode(meta["sinks_b64"]).decode("utf-8", "replace")
        )
    except Exception:
        return []


def _load_attribution(
    html_file: str,
    response_body: str,
    indexed: bool,
    seps: list[str] | None,
    items: list[tuple[str, str]],
) -> tuple[list[dict[str, Any]], dict[str, Any], int | None]:
    """Load `*_attribution.json` (from bisect/numeric probe) or recover
    partial prefix reflections directly from `response_body`."""
    verdicts: list[dict[str, Any]] = []
    adata: dict[str, Any] = {}
    max_len: int | None = None
    attrib = (
        html_file.replace(".html", "_attribution.json")
        if isinstance(html_file, str)
        else None
    )
    if attrib and os.path.exists(attrib):
        try:
            with open(attrib, encoding="utf-8") as fh:
                adata = json.load(fh)
            verdicts = adata.get("verdicts") or []
            max_len = adata.get("max_len")
        except Exception:
            verdicts = []
    if (
        not verdicts
        and indexed
        and seps
        and (MARKER_START + seps[0]) in response_body
    ):
        p_start = response_body.find(MARKER_START + seps[0])
        seg = response_body[p_start + len(MARKER_START) :]
        bpos = [seg.find(b) for b in seps]
        for i, (n, v) in enumerate(items):
            if bpos[i] >= 0 and bpos[i + 1] > bpos[i]:
                got = seg[bpos[i] + len(seps[i]) : bpos[i + 1]]
                verdicts.append(
                    {
                        "name": n,
                        "expected": v,
                        "got": got,
                        "verdict": "passed" if got == v else "transformed",
                    }
                )
                max_len = len(MARKER_START) + bpos[i + 1] + len(seps[i + 1])
            else:
                verdicts.append(
                    {
                        "name": n,
                        "expected": v,
                        "got": None,
                        "verdict": "unresolved",
                    }
                )
        adata = {
            "baseline_body": response_body,
            "baseline_marker": MARKER_START + seps[0],
        }
    return verdicts, adata, max_len


def _print_summary_and_analysis(results: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print()
    print(
        f"{'#':<4} {'Character':<20} {'Expected':<12} {'Got back':<20} {'Bypass':<8}"
    )
    print("-" * 68)
    for r in results:
        print(
            f"{r['character_index']:<4} {r['character_name']:<20} "
            f"{str(r['expected']):<12} {str(r['got_back']):<20.20} "
            f"{'YES' if r['needs_bypass'] else 'NO':<8}"
        )
    print()

    print("=" * 80)
    print("AI ANALYSIS")
    print("=" * 80)
    print()

    passed = [r for r in results if r["passed"]]
    failed = [r for r in results if not r["passed"]]

    if passed:
        print(f"[PASS] {len(passed)} character(s) reflected unchanged:")
        for r in passed:
            print(
                f"  [OK] {r['character_name']} ('{r['character']}') -> "
                f"'{r['expected']}' == '{r['got_back']}'"
            )
        print()

    if failed:
        print(
            f"[FAIL] {len(failed)} character(s) changed/encoded/removed (bypass needed):"
        )
        for r in failed:
            print(
                f"  [!] {r['character_name']} ('{r['character']}') -> "
                f"'{r['expected']}' != '{r['got_back']}'"
            )
        print()
        print("  These characters need a bypass technique (see skill.md).")
        if len(passed) == 0:
            print(
                "  [ANOMALY] All items failed — could be a combination-triggered"
            )
            print("            filter rather than per-character blocking.")
            print(
                '            -> Escalate: send_payloads.py --isolate --url "..."'
            )
    else:
        print(
            "[OK] All characters passed through unchanged. No filter/encoding detected."
        )
        print("     Standard XSS payloads should work without bypass.")

    return passed, failed


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Check which probe items were reflected unchanged"
    )
    ap.add_argument(
        "--keywords",
        action="store_true",
        help="analyze the Layer B/C keyword probe (*-xss_keywords.html) "
        "instead of the character probe (*-xss.html)",
    )
    args = ap.parse_args()

    if args.keywords:
        log_name, out_name, label, kind = (
            "xss_keywords",
            "xss_keyword_analysis",
            "keywords",
            "keywords",
        )
    else:
        log_name, out_name, label, kind = (
            "xss",
            "xss_reflection_analysis",
            "chars",
            "characters",
        )

    print("=" * 80)
    print("Check Reflection")
    print(f"Date: {datetime.now().isoformat()}")
    print("Logic: input 'testing1 b0 item1 b1 item2 ... bN testing2'")
    print("       each item between its indexed boundaries == expected -> PASS")
    print("       item != expected -> FAIL (needs bypass)")
    print("       boundary lost -> item INDETERMINATE (merged with neighbour)")
    print(f"Mode: {label}")
    print("=" * 80)
    print()

    html_file = latest_log_path(log_name, "html")
    if not html_file or not os.path.exists(html_file):
        print(
            f"No {log_name} response log found in Skills/log/. Run send_payloads.py first."
        )
        return

    print(f"📄 Reading response from: {html_file}")
    with open(html_file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    meta = parse_meta(content)
    input_str = meta.get("input_sent", "")
    probe_mode = meta.get("probe_mode", "curl")

    sinks = _decode_sinks(meta)
    if sinks:
        print(
            f"DOM sinks observed: {', '.join(sorted({n for n, _ in sinks}))}"
        )

    items = items_from_meta(meta, kind)
    print(
        f"Items: {len(items)} "
        f"({'items_json from log' if meta.get('items_json') else 'static list fallback'})"
    )

    seps: list[str] | None = None
    try:
        seps = json.loads(meta.get("seps_json", "null"))
    except (ValueError, TypeError):
        seps = None
    indexed = bool(seps) and len(seps) == len(items) + 1
    print(
        f"Boundaries: {'indexed (' + str(len(seps)) + ')' if indexed and seps else 'legacy x'}"
    )

    response_body = strip_html_comments(content)
    dom_hint = bool(
        _DOM_SRC_RE.search(response_body)
        and _DOM_SINK_RE.search(response_body)
    )
    if dom_hint:
        print(
            "DOM plumbing detected: page scripts read a location.* source "
            "and call a DOM sink"
        )

    reflected_matches, refl_positions = extract_reflected_all(response_body)

    sink_names: list[str | None] = [None] * len(reflected_matches)
    sink_args: list[str | None] = [None] * len(reflected_matches)
    for sname, sarg in sinks:
        for m in _MARKER_SPAN_RE.finditer(sarg):
            reflected_matches.append(m.group(1))
            refl_positions.append(
                {
                    "index": len(reflected_matches),
                    "start": -1,
                    "end": -1,
                    "sink": sname,
                }
            )
            sink_names.append(sname)
            sink_args.append(sarg)

    results: list[dict[str, Any]] = []
    attribution_quote: str | None = None
    max_len: int | None = None

    if not reflected_matches:
        print("[NOT FOUND] No reflection detected in response.")
        verdicts, adata, max_len = _load_attribution(
            html_file, response_body, indexed, seps, items
        )
        if not verdicts:
            if adata.get("numeric_reflects"):
                nbody = adata.get("baseline_body") or ""
                nmark = adata.get("baseline_marker") or "90197752"
                nctx, nq, _ncloser = inspect_reflection_point(nbody, nmark)
                print(
                    f"         [LETTER-STRIPPER] Numeric probe ({nmark}) "
                    "reflected while alphabetic markers were stripped!"
                )
                print(f"         Surface context (from numeric probe): {nctx}")
                out_file = new_log_path(out_name, "json")
                with open(out_file, "w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "generated_by": "check_reflection.py",
                            "generated_at": datetime.now().isoformat(),
                            "mode": label,
                            "probe_mode": probe_mode,
                            "dom_hint": dom_hint,
                            "dom_sinks": sinks or None,
                            "source_html": html_file,
                            "input_sent": input_str,
                            "total_reflections": 0,
                            "reflections": [],
                            "total_items_tested": 0,
                            "passed_count": 0,
                            "failed_count": 0,
                            "all_passed": False,
                            "results": [],
                            "letter_stripper": True,
                            "numeric_context": nctx,
                            "attribution_quote": nq,
                            "max_len": max_len,
                        },
                        f,
                        indent=2,
                        ensure_ascii=False,
                    )
                print(f"\n💾 Analysis saved to: {out_file}")
                return
            print(
                "         Ambiguous: no reflection surface, filter/WAF "
                "rejected the request, or reflection is client-side only (DOM)."
            )
            print(
                '         -> Escalate: send_payloads.py --render --url "..." (DOM sinks)'
            )
            print(
                '            then send_payloads.py --isolate --url "..." (per-char)'
            )
            return

        print("         Request-level block confirmed (baseline reflects")
        print("         but the combined probe was denied). Bisect results:")
        bctx = ["request-level block (bisected)"]
        bcloser = ""
        bbody, bmark = adata.get("baseline_body"), adata.get("baseline_marker")
        if bbody and bmark:
            bctx, bq, bcloser = inspect_reflection_point(bbody, bmark)
            bctx = bctx or ["request-level block (bisected)"]
            attribution_quote = bq
            print(
                f"         Surface context (from baseline): {bctx}"
                f"{' quote=' + repr(bq) if bq is not None else ''}"
            )
        for i, v in enumerate(verdicts, 1):
            verd = v.get("verdict")
            results.append(
                {
                    "reflection_index": 0,
                    "position": -1,
                    "character_index": i,
                    "character_name": v.get("name"),
                    "character": v.get("expected"),
                    "expected": v.get("expected"),
                    "got_back": (
                        v.get("got")
                        if verd != "blocked"
                        else f"request blocked — HTTP {v.get('status', '?')}"
                    ),
                    "passed": (
                        True
                        if verd == "passed"
                        else None
                        if verd in ("indeterminate", "unresolved")
                        else False
                    ),
                    "needs_bypass": verd != "passed",
                    "contexts": bctx,
                    "quote": attribution_quote,
                    "js_breakout": bcloser,
                }
            )

    for refl_idx, reflected in enumerate(reflected_matches, start=1):
        sink_name = sink_names[refl_idx - 1]
        rpos = refl_positions[refl_idx - 1].get("start")
        print(f"--- Reflection [{refl_idx}] ---")
        print(f"    Full reflected: {MARKER_START}{reflected}{MARKER_END}")

        rquote: str | None = None
        rcloser = ""
        if sink_name is not None:
            if sink_name in _DOM_JS_SINKS:
                inner = "javascript raw"
            elif sink_name in _DOM_URL_SINKS:
                inner = "attribute url value"
            else:
                ictxs, rquote, rcloser = inspect_reflection_point(
                    sink_args[refl_idx - 1] or "",
                    MARKER_START + reflected + MARKER_END,
                )
                inner = ictxs[0]
            contexts = [f"dom sink: {sink_name} ({inner})"]
        else:
            contexts, rquote, rcloser = inspect_reflection_point(
                response_body,
                MARKER_START + reflected + MARKER_END,
                pos=rpos if rpos is not None and rpos >= 0 else None,
            )
        print(f"    Context:    {', '.join(contexts)}")
        print()

        if indexed and seps:
            parts = extract_items(reflected, seps, len(items))
        else:
            parts = split_by_separator(reflected, len(items))

        if parts is None:
            print(
                f"    [WARNING] Reflected content split by '{SEPARATOR}' gave an unexpected part count."
            )
            print(f"    Reflected: {reflected}")
            print("    -> Anomaly: filter mangled the separator. Escalate with")
            print('       send_payloads.py --isolate --url "..."')
            print()
            continue

        for i, (name, expected_char) in enumerate(items):
            got = parts[i]
            if got is None:
                print(f"    [{i + 1}] {name} ('{expected_char}')")
                print(f"        Expected:  {expected_char}")
                print("        Got back:  <merged — boundary lost>")
                print(
                    "        Verdict:   INDETERMINATE - merged with neighbour item"
                )
                print()
                results.append(
                    {
                        "reflection_index": refl_idx,
                        "position": refl_positions[refl_idx - 1]["start"],
                        "character_index": i + 1,
                        "character_name": name,
                        "character": expected_char,
                        "expected": expected_char,
                        "got_back": None,
                        "passed": None,
                        "needs_bypass": None,
                        "verdict": "indeterminate",
                        "contexts": contexts,
                        "quote": rquote,
                        "js_breakout": rcloser,
                    }
                )
                continue

            passed_item = got == expected_char or (
                name in ("double_url_lt", "fullwidth_lt") and got == "<"
            )
            print(f"    [{i + 1}] {name} ('{expected_char}')")
            print(f"        Expected:  {expected_char}")
            print(f"        Got back:  {got}")
            print(
                f"        Verdict:   {'PASS - reflected unchanged' if passed_item else 'FAIL - changed/encoded/removed'}"
            )
            print(f"        Bypass:    {'NO' if passed_item else 'YES'}")
            print()

            results.append(
                {
                    "reflection_index": refl_idx,
                    "position": refl_positions[refl_idx - 1]["start"],
                    "character_index": i + 1,
                    "character_name": name,
                    "character": expected_char,
                    "expected": expected_char,
                    "got_back": got,
                    "passed": passed_item,
                    "needs_bypass": not passed_item,
                    "contexts": contexts,
                    "quote": rquote,
                    "js_breakout": rcloser,
                }
            )

    if not results:
        return

    passed, failed = _print_summary_and_analysis(results)

    out_file = new_log_path(out_name, "json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "generated_by": "check_reflection.py",
                "generated_at": datetime.now().isoformat(),
                "mode": label,
                "probe_mode": probe_mode,
                "dom_hint": dom_hint,
                "dom_sinks": sinks or None,
                "source_html": html_file,
                "input_sent": input_str,
                "total_reflections": len(reflected_matches),
                "reflections": refl_positions,
                "total_items_tested": len(results),
                "passed_count": len(passed),
                "failed_count": len(failed),
                "all_passed": len(failed) == 0,
                "results": results,
                "attribution_quote": attribution_quote,
                "max_len": max_len,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    print(f"\n💾 Analysis saved to: {out_file}")


if __name__ == "__main__":
    main()
