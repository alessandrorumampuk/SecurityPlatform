#!/usr/bin/env python3
"""
recommend_payload.py — Deterministic XSS payload recommendation & R/V verification.

Reads the latest `*-xss_reflection_analysis.json` (and optional
`*-xss_keyword_analysis.json`) and synthesizes context-specific XSS candidates:
  1. Breaker computation (XSStrike htmlParser model)
  2. Character efficiency gating (XSStrike checker model)
  3. Composition grammar & junction/obfuscation bypasses (XSStrike genGen + JSFuck)
  4. Marker-based DOM & JS span verification (Dalfox R/V model + Playwright escalation)
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
import re
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.composer import compose  # noqa: E402
from core.constants import (  # noqa: E402
    CASE_REF,
    CONSUMING_TAGS,
    CONTEXT_MAP,
    DEFAULT_UA as _UA,
    GEN_EV,
    INERT_SCRIPT_SINKS,
    PLACEHOLDER,
    PROBE_CHARS,
    TAG_HANDLERS,
)
from core.context import (  # noqa: E402
    breakers,
    detect_quote,
    normalize_contexts,
)
from core.jsfuck import jsfuck_encode  # noqa: E402
from core.obfuscators import (  # noqa: E402
    _throw_ops,
    avail_funcs,
    bracket_funcs,
    char_scores,
    encoded_funcs,
    entity_fname,
    entity_variants,
    escaped_quotes,
    indirect_call_funcs,
    jsfuck_funcs,
    junction_ok,
    min_eff,
    noparens_funcs,
    required_ok,
    split_str,
    u6_fname,
    u6_funcs,
    u_fname,
    u_funcs,
    usable,
)
from core.transport import get_http_session as _get_verify_session  # noqa: E402
from core.types import RequestSpec, normalize_method  # noqa: E402
from core.verifier import (  # noqa: E402
    MarkerDomCheck,
    _core_payload,
    _locate_anchor,
    _parse_response,
    candidate_tier as tier,
    classify_response,
    run_verification_waves,
    verify_payload,
)
from log_utils import latest_log_path, new_log_path  # noqa: E402

_DOM_SINK_EXTRACT_RE = re.compile(r"dom sink:\s*([\w:.-]+)")


def _load_keyword_masks(
    kw_file: str | None,
) -> tuple[dict[int, dict[str, bool]], dict[int, dict[str, tuple[str, str]]]]:
    kw_by_refl: dict[int, dict[str, bool]] = {}
    kwv_by_refl: dict[int, dict[str, tuple[str, str]]] = {}
    if kw_file and os.path.exists(kw_file):
        with open(kw_file, encoding="utf-8") as fh:
            kwdata = json.load(fh)
        for r in kwdata.get("results", []):
            rid = r["reflection_index"]
            name = r["character_name"]
            kw_by_refl.setdefault(rid, {})[name] = r["passed"]
            kwv_by_refl.setdefault(rid, {})[name] = (
                r.get("expected", ""),
                r.get("got_back", ""),
            )
        print(f"Keyword mask:     {kw_file}\n")
    else:
        print(
            "Keyword mask:     none found (run send_payloads.py --probe2 + "
            "check_reflection.py --keywords to enable Layer B/C gating)\n"
        )
    return kw_by_refl, kwv_by_refl


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Recommend XSS payloads from reflection analysis"
    )
    ap.add_argument(
        "--analysis",
        help="path to *-xss_reflection_analysis.json (default: latest in Skills/log/)",
    )
    ap.add_argument(
        "--url",
        help="target URL with {xss_testing} placeholder (required for --verify)",
    )
    ap.add_argument(
        "--keywords",
        help="path to *-xss_keyword_analysis.json (default: latest in Skills/log/, if any)",
    )
    ap.add_argument(
        "--verify",
        action="store_true",
        help="inject top payloads with a marker and grade R/V",
    )
    ap.add_argument(
        "--render",
        action="store_true",
        help="verify via rendered DOM (headless chromium)",
    )
    ap.add_argument(
        "--top",
        type=int,
        default=3,
        help="max payload candidates per reflection (default 3)",
    )
    ap.add_argument(
        "--method",
        help="HTTP method for --verify — any verb: GET/POST/PUT/PATCH/"
        "DELETE/OPTIONS/QUERY (default: GET, or POST when --data is "
        "present)",
    )
    ap.add_argument(
        "--data",
        help=f"request body template containing {PLACEHOLDER} (for --verify "
        "on POST/body surfaces)",
    )
    ap.add_argument(
        "--content-type",
        help="Content-Type for --data (default: "
        "application/x-www-form-urlencoded)",
    )
    ap.add_argument(
        "--data-urlencoded",
        action="store_true",
        help="percent-encode the payload inside --data during --verify "
        "(default: verbatim)",
    )
    ap.add_argument(
        "--json-escape",
        action="store_true",
        help="escape the payload as a JSON string literal inside --data "
        "(default: raw)",
    )
    ap.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="Name: Value",
        help=f"custom request header (repeatable; value may contain "
        f"{PLACEHOLDER})",
    )
    args = ap.parse_args()

    print("=" * 80)
    print(
        "Recommend Payload  (breaker -> char-gate -> grammar -> marker verify)"
    )
    print(f"Date: {datetime.now().isoformat()}")
    print("=" * 80)

    analysis_file = args.analysis or latest_log_path(
        "xss_reflection_analysis", "json"
    )
    if not analysis_file or not os.path.exists(analysis_file):
        print("No reflection analysis found. Run check_reflection.py first.")
        return
    print(f"Reading analysis: {analysis_file}\n")

    with open(analysis_file, encoding="utf-8") as fh:
        analysis = json.load(fh)
    results = analysis.get("results", [])
    source_html = analysis.get("source_html", "")
    letter_stripper = bool(analysis.get("letter_stripper"))
    refl_ids = sorted({r["reflection_index"] for r in results})
    if not refl_ids and letter_stripper:
        refl_ids = [0]

    kw_file = args.keywords or latest_log_path("xss_keyword_analysis", "json")
    kw_by_refl, kwv_by_refl = _load_keyword_masks(kw_file)

    report: dict[str, Any] = {
        "generated_by": "recommend_payload.py",
        "generated_at": datetime.now().isoformat(),
        "source_analysis": analysis_file,
        "source_keyword_analysis": kw_file if kw_by_refl else None,
        "reflections": [],
    }

    for rid in refl_ids:
        if letter_stripper and not results:
            raw_ctxs = analysis.get("numeric_context") or ["javascript raw"]
            ctxs = [k for c in raw_ctxs for k in normalize_contexts([c])]
            ctx = ctxs[0]
            inert = False
            scores = {ch: 100 for ch in PROBE_CHARS}
            esc_q: set[str] = set()
            kw = kw_by_refl.get(0, {})
            kwv = kwv_by_refl.get(0, {})
            quote_ch = analysis.get("attribution_quote") or ""
            js_brk = ""
        else:
            raw_ctxs = [
                c
                for r in results
                if r["reflection_index"] == rid
                for c in r["contexts"]
            ]
            ctxs = [k for c in raw_ctxs for k in normalize_contexts([c])]
            ctx = ctxs[0]
            m_sink = next(
                (m for c in raw_ctxs if (m := _DOM_SINK_EXTRACT_RE.search(c))),
                None,
            )
            inert = (
                bool(m_sink)
                and m_sink.group(1).lower() in INERT_SCRIPT_SINKS
            )
            scores = char_scores(results, rid)
            esc_q = escaped_quotes(results, rid)
            kw = (
                kw_by_refl.get(rid)
                or kw_by_refl.get(0)
                or (kw_by_refl.get(1, {}) if rid == 0 else {})
            )
            kwv = (
                kwv_by_refl.get(rid)
                or kwv_by_refl.get(0)
                or (kwv_by_refl.get(1, {}) if rid == 0 else {})
            )
            r_rows = [r for r in results if r["reflection_index"] == rid]
            per_q = next(
                (
                    r["quote"]
                    for r in r_rows
                    if "quote" in r and r["quote"] is not None
                ),
                None,
            )
            js_brk = next(
                (
                    r.get("js_breakout") or ""
                    for r in r_rows
                    if r.get("js_breakout")
                ),
                "",
            )
            quote_ch = (
                per_q
                if per_q is not None
                else detect_quote(source_html, "testing1")
            )
            if rid == 0 and analysis.get("attribution_quote") is not None:
                quote_ch = analysis["attribution_quote"]

        max_len = analysis.get("max_len")
        cand = compose(
            ctx,
            quote_ch,
            scores,
            kw,
            kwv,
            inert=inert,
            escaped_q=esc_q,
            js_breakout=js_brk,
            deny=(rid == 0 and not letter_stripper),
            letter_stripper=letter_stripper,
        )
        if max_len:
            fit = [c for c in cand if len(c["payload"]) <= max_len]
            if fit:
                cand = fit
        cand.sort(key=lambda c: (-c["efficiency"], tier(c)))
        cand = cand[: args.top]

        print(
            f"--- Reflection [{rid}]  context={ctx}  quote='{quote_ch or 'unquoted'}'"
        )
        print(
            "    char efficiency: "
            + " ".join(f"{c}={s}" for c, s in scores.items())
        )
        if kw:
            print(
                "    keyword mask:    "
                + " ".join(
                    f"{k}={'OK' if v else 'BLOCKED'}" for k, v in kw.items()
                )
            )
        if not cand:
            print(
                "    [NO CANDIDATE] no payload passes the char gate -> "
                "consult case/ manually or extend grammar"
            )
        for i, c in enumerate(cand):
            print(f"    [{i + 1}] eff={c['efficiency']}%  {c['payload']}")
            print(
                f"        technique: {c['technique']}  |  case: {c['case_ref']}"
            )

        entry: dict[str, Any] = {
            "reflection_index": rid,
            "context": ctx,
            "quote": quote_ch,
            "scores": scores,
            "keyword_mask": kw,
            "candidates": cand,
        }

        if args.verify and cand:
            custom_headers: dict[str, str] = {}
            for h in args.header:
                k, sep, v = h.partition(":")
                if sep and k.strip():
                    custom_headers[k.strip()] = v.strip()
            content_type = (
                args.content_type or "application/x-www-form-urlencoded"
            )
            try:
                req_method = normalize_method(
                    args.method, has_body=args.data is not None
                )
            except ValueError as e:
                print(f"    [!] {e}")
                req_method = "GET"
            if req_method == "HEAD":
                print(
                    "    [!] HEAD responses carry no body — verify grades "
                    "will be meaningless"
                )
            spec = RequestSpec(
                method=req_method,
                url=args.url or "",
                data=args.data,
                content_type=content_type,
                headers=custom_headers,
            )
            has_ph = (
                PLACEHOLDER in spec.url
                or (spec.data is not None and PLACEHOLDER in spec.data)
                or any(PLACEHOLDER in v for v in spec.headers.values())
            )
            if not has_ph:
                print(
                    "    [!] --verify needs {xss_testing} in --url, --data, "
                    "or a -H header"
                )
            else:
                body_encode = (
                    "json"
                    if args.json_escape and "json" in content_type.lower()
                    else "url"
                    if args.data_urlencoded
                    else "raw"
                )
                render = args.render or analysis.get("probe_mode") == "render"
                print(
                    f"    verifying top payloads{render and ' (rendered DOM)' or ''}..."
                )
                verified = run_verification_waves(
                    spec=spec,
                    body_encode=body_encode,
                    initial_candidates=cand,
                    ctx=ctx,
                    quote_ch=quote_ch,
                    scores=scores,
                    kw=kw,
                    kwv=kwv,
                    inert=inert,
                    esc_q=esc_q,
                    js_brk=js_brk,
                    rid=rid,
                    max_len=max_len,
                    top_n=args.top,
                    render=render,
                    dom_hint=bool(analysis.get("dom_hint")),
                    letter_stripper=letter_stripper,
                )
                entry["verification"] = verified
                for v in verified:
                    print(f"        [{v['confidence']}] {v['payload']}")
                    print(f"            {v['evidence']}")
        print()
        report["reflections"].append(entry)

    out_file = new_log_path("xss_recommendation", "json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"💾 Recommendation saved to: {out_file}")


if __name__ == "__main__":
    main()
