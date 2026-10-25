#!/usr/bin/env python3
import re
import os
import sys
import json
import argparse
import base64
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from log_utils import latest_log_path, new_log_path

MARKER_START = "testing1"
MARKER_END = "testing2"
SEPARATOR = "x"

CHARACTERS = [
    ("single_quote", "'"),
    ("double_quote", '"'),
    ("greater_than", ">"),
    ("less_than", "<"),
    ("slash", "/"),
    ("backslash", "\\"),
]


def parse_meta(content):
    meta = {}
    for line in content.split("\n"):
        match = re.match(r"<!-- (\w+): (.+?) -->", line)
        if match:
            meta[match.group(1)] = match.group(2)
    return meta


def strip_html_comments(content):
    return re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL)


# Parenthetical maps each DOM sink to the parse context its argument lands
# in, so CONTEXT_MAP in recommend_payload.py normalizes it for free:
#   "dom sink: document.write (html body)"      -> html
#   "dom sink: eval (javascript raw)"           -> js_raw
DOM_SINK_CTX = {
    "document.write": "dom sink: document.write (html body)",
    "document.writeln": "dom sink: document.writeln (html body)",
    "innerHTML": "dom sink: innerHTML (html body)",
    "eval": "dom sink: eval (javascript raw)",
    "setTimeout(string)": "dom sink: setTimeout(string) (javascript raw)",
}

# DOM plumbing hint: page scripts read a location.*/document.* source AND
# call a DOM sink -> worth a render probe even when a server reflection
# exists (the sink path never reaches the raw response body). List follows
# the canonical source/sink sets (PortSwigger / OWASP DOM-XSS cheat sheets).
_DOM_SRC_RE = re.compile(
    r"location\.(?:search|hash|href|pathname|host(?:name)?|port|protocol)\b"
    r"|document\.(?:URL|URLUnencoded|documentURI|baseURI|referrer|cookie)\b"
    r"|window\.name\b|localStorage|sessionStorage"
    r"|event\.data\b|onmessage\b|addEventListener\s*\(\s*['\"]message")
_DOM_SINK_RE = re.compile(
    r"document\.(?:write|writeln|open)\b|\.(?:inner|outer)HTML\b"
    r"|insertAdjacentHTML\b|createContextualFragment\b|\.srcdoc\b"
    r"|\beval\s*\(|new\s+Function\b|set(?:Timeout|Interval)\s*\(\s*['\"]"
    r"|location\.(?:assign|replace)\s*\(|\bwindow\.open\s*\(|\.location\s*="
    r"|setAttribute\s*\(\s*['\"]on\w+"
    r"|\$\.(?:parseHTML|globalEval)\s*\("
    r"|\.(?:html|append|prepend|after|before|replaceWith|replaceAll"
    r"|insertAfter|insertBefore|wrap(?:Inner|All)?)\s*\(")
# sinks whose argument is executed as JavaScript, not parsed as markup
_DOM_JS_SINKS = ("eval", "setTimeout(string)", "setInterval(string)",
                 "Function")
# navigation sinks: the argument is a URL — javascript: scheme executes
_DOM_URL_SINKS = ("location.assign", "location.replace", "window.open",
                  "location")


def items_from_meta(meta, kind):
    """Recover the (name, value) probe items exactly as sent, from the saved
    items_json metadata. Required because probe2 appends a per-run random
    tag (rand_tag) that cannot be regenerated later. Falls back to the
    static list for logs written before items_json existed."""
    raw = meta.get("items_json")
    if raw:
        try:
            return [(str(n), str(v)) for n, v in json.loads(raw)]
        except (ValueError, TypeError):
            pass
    if kind == "keywords":
        from send_payloads import KEYWORDS
        return list(KEYWORDS)
    return list(CHARACTERS)


def extract_reflected_all(response):
    pattern = re.escape(MARKER_START) + r"(.*?)" + re.escape(MARKER_END)
    matches = list(re.finditer(pattern, response, re.DOTALL))
    reflected = [m.group(1) for m in matches]
    positions = [{"index": i + 1, "start": m.start(), "end": m.end()}
                 for i, m in enumerate(matches)]
    return reflected, positions


def split_by_separator(reflected, expected_count=None):
    """Legacy extractor for logs written before indexed boundaries
    existed (single 'x' separator — one colliding item voids the whole
    reflection)."""
    parts = reflected.split(SEPARATOR)
    if len(parts) != (expected_count or len(CHARACTERS)):
        return None
    return parts


def extract_items(reflected, seps, n):
    """Indexed-boundary item extraction. seps[i] sits before item i,
    seps[i+1] right after it (N+1 bounds total, incl. the two edge
    bounds). Returns a list of N extracted strings; an item is None
    ('indeterminate') when either of its boundaries is missing or the
    boundary order collapsed — a filter eating one boundary merges
    only its two neighbours instead of voiding the whole reflection."""
    bpos = [reflected.find(b) for b in seps]
    parts = []
    for i in range(n):
        if bpos[i] < 0 or bpos[i + 1] < 0:
            parts.append(None)
            continue
        lo = bpos[i] + len(seps[i])
        hi = bpos[i + 1]
        parts.append(reflected[lo:hi] if hi >= lo else None)
    return parts


def detect_reflection_context(content, reflected_full):
    """Detect where in the HTML the input is reflected."""
    contexts = []
    body = strip_html_comments(content)
    esc = re.escape(reflected_full)

    # attribute sub-contexts, most specific first
    if re.search(r'on\w+\s*=\s*"[^"]*' + esc, body, re.DOTALL | re.IGNORECASE) or \
            re.search(r"on\w+\s*=\s*'[^']*" + esc, body, re.DOTALL | re.IGNORECASE):
        contexts.append("attribute event-handler value")
    elif re.search(r'srcdoc\s*=\s*"[^"]*' + esc, body, re.DOTALL | re.IGNORECASE) or \
            re.search(r"srcdoc\s*=\s*'[^']*" + esc, body, re.DOTALL | re.IGNORECASE):
        contexts.append("attribute srcdoc value")
    elif re.search(r'(?:href|src|action|formaction|data)\s*=\s*"[^"]*' + esc,
                   body, re.DOTALL | re.IGNORECASE) or \
            re.search(r"(?:href|src|action|formaction|data)\s*=\s*'[^']*" + esc,
                      body, re.DOTALL | re.IGNORECASE):
        contexts.append("attribute url value")

    # script-internal contexts, specific before generic
    for sm in re.finditer(r'<script[^>]*>(.*?)(?:</script>|$)', body,
                          re.IGNORECASE | re.DOTALL):
        seg = sm.group(1)
        if not re.search(esc, seg):
            continue
        if re.search(r'/\*[^*]*' + esc, seg):
            contexts.append("javascript block comment")
        elif re.search(r'(?<![:\'"`])//[^\n]*' + esc, seg):
            contexts.append("javascript line comment")
        elif re.search(r'`[^`]*' + esc, seg):
            contexts.append("javascript template literal")
        elif re.search(r'[\'"][^\'"\n]*' + esc, seg):
            contexts.append("javascript string")
        else:
            contexts.append("javascript raw")
        break

    # Check for attribute value context: value="...reflected..." or value='...reflected...'
    attr_patterns = [
        r'value="[^"]*' + re.escape(reflected_full) + r'[^"]*"',
        r"value='[^']*" + re.escape(reflected_full) + r"[^']*'",
        r'href="[^"]*' + re.escape(reflected_full) + r'[^"]*"',
        r"href='[^']*" + re.escape(reflected_full) + r"[^']*'",
        r'src="[^"]*' + re.escape(reflected_full) + r'[^"]*"',
        r"src='[^']*" + re.escape(reflected_full) + r"[^']*'",
    ]
    for pat in attr_patterns:
        if re.search(pat, body, re.DOTALL):
            # Check if quotes are encoded in this reflection
            has_encoded_quotes = "&#039;" in reflected_full or "&quot;" in reflected_full
            has_raw_quotes = "'" in reflected_full or '"' in reflected_full
            if has_encoded_quotes and not has_raw_quotes:
                contexts.append("attribute value (quotes encoded)")
            else:
                contexts.append("attribute value (quotes NOT encoded)")
            break

    # Check for JavaScript string context: var x='...reflected...' or var x="...reflected..."
    js_patterns = [
        r"var\s+\w+\s*=\s*'[^']*" + re.escape(reflected_full) + r"[^']*'",
        r'var\s+\w+\s*=\s*"[^"]*' + re.escape(reflected_full) + r'[^"]*"',
        r"<script[^>]*>[^<]*" + re.escape(reflected_full),
    ]
    for pat in js_patterns:
        if re.search(pat, body, re.DOTALL | re.IGNORECASE):
            contexts.append("javascript string")
            break

    # Check for HTML tag context: <noscript>...reflected...</noscript>, <style>, <title>, <textarea>
    tag_patterns = [
        (r"<noscript[^>]*>[^<]*" + re.escape(reflected_full), "noscript tag"),
        (r"<style[^>]*>[^<]*" + re.escape(reflected_full), "style tag"),
        (r"<title[^>]*>[^<]*" + re.escape(reflected_full), "title tag"),
        (r"<textarea[^>]*>[^<]*" + re.escape(reflected_full), "textarea tag"),
    ]
    for pat, tag_name in tag_patterns:
        if re.search(pat, body, re.DOTALL | re.IGNORECASE):
            contexts.append(f"inside {tag_name}")
            break

    # Check for HTML body context (reflected as visible text)
    # If not in any of the above, it's likely in HTML body
    if not contexts:
        contexts.append("html body (text content)")

    return contexts


def main():
    ap = argparse.ArgumentParser(description="Check which probe items were reflected unchanged")
    ap.add_argument("--keywords", action="store_true",
                    help="analyze the Layer B/C keyword probe (*-xss_keywords.html) "
                         "instead of the character probe (*-xss.html)")
    args = ap.parse_args()

    if args.keywords:
        log_name, out_name, label, kind = \
            "xss_keywords", "xss_keyword_analysis", "keywords", "keywords"
    else:
        log_name, out_name, label, kind = \
            "xss", "xss_reflection_analysis", "chars", "characters"

    print("=" * 80)
    print("Check Reflection")
    print(f"Date: {datetime.now().isoformat()}")
    print(f"Logic: input 'testing1 b0 item1 b1 item2 ... bN testing2'")
    print(f"       each item between its indexed boundaries == expected -> PASS")
    print(f"       item != expected -> FAIL (needs bypass)")
    print(f"       boundary lost -> item INDETERMINATE (merged with neighbour)")
    print(f"Mode: {label}")
    print("=" * 80)
    print()

    html_file = latest_log_path(log_name, "html")

    if not html_file or not os.path.exists(html_file):
        print(f"No {log_name} response log found in Skills/log/. Run send_payloads.py first.")
        return

    print(f"📄 Reading response from: {html_file}")

    with open(html_file, "r") as f:
        content = f.read()

    meta = parse_meta(content)
    input_str = meta.get("input_sent", "")
    probe_mode = meta.get("probe_mode", "curl")

    sinks = []
    if meta.get("sinks_b64"):
        try:
            sinks = json.loads(base64.b64decode(meta["sinks_b64"])
                               .decode("utf-8", "replace"))
        except Exception:
            sinks = []
    if sinks:
        print(f"DOM sinks observed: {', '.join(sorted({n for n, _ in sinks}))}")

    items = items_from_meta(meta, kind)
    print(f"Items: {len(items)} ({'items_json from log' if meta.get('items_json') else 'static list fallback'})")

    seps = None
    try:
        seps = json.loads(meta.get("seps_json", "null"))
    except (ValueError, TypeError):
        seps = None
    indexed = bool(seps) and len(seps) == len(items) + 1
    print(f"Boundaries: {'indexed (' + str(len(seps)) + ')' if indexed else 'legacy x'}")

    response_body = strip_html_comments(content)
    dom_hint = bool(_DOM_SRC_RE.search(response_body)
                    and _DOM_SINK_RE.search(response_body))
    if dom_hint:
        print("DOM plumbing detected: page scripts read a location.* source "
              "and call a DOM sink")

    reflected_matches, refl_positions = extract_reflected_all(response_body)

    # DOM-sink surfaces: marker inside a sink ARGUMENT gives the honest
    # post-decode verdict — the rendered DOM re-encodes it ('>' -> '&gt;'
    # in text nodes), which would misreport a usable char as FAIL.
    sink_names = [None] * len(reflected_matches)
    sink_args = [None] * len(reflected_matches)
    for sname, sarg in sinks:
        for m in re.finditer(re.escape(MARKER_START) + r"(.*?)"
                             + re.escape(MARKER_END), sarg, re.DOTALL):
            reflected_matches.append(m.group(1))
            refl_positions.append({"index": len(reflected_matches),
                                   "start": -1, "end": -1, "sink": sname})
            sink_names.append(sname)
            sink_args.append(sarg)

    results = []
    attribution_quote = None

    if not reflected_matches:
        print("[NOT FOUND] No reflection detected in response.")
        # Request-level block? A deny page gives no per-item evidence —
        # but send_payloads bisects the item set on that anomaly and
        # writes <stem>_attribution.json with real per-item verdicts.
        verdicts, adata = [], {}
        attrib = html_file.replace(".html", "_attribution.json") \
            if isinstance(html_file, str) else None
        if attrib and os.path.exists(attrib):
            try:
                adata = json.load(open(attrib))
                verdicts = adata.get("verdicts") or []
            except Exception:
                verdicts = []
        if not verdicts:
            print("         Ambiguous: no reflection surface, filter/WAF "
                  "rejected the request, or reflection is client-side "
                  "only (DOM).")
            print("         -> Escalate: send_payloads.py --render --url "
                  "\"...\" (DOM sinks)")
            print("            then send_payloads.py --isolate --url "
                  "\"...\" (per-char)")
            return
        print("         Request-level block confirmed (baseline reflects")
        print("         but the combined probe was denied). Bisect results:")
        # the baseline marker DID reflect — its position reveals the
        # injection context the deny page erased (attr/JS/html + quote)
        bctx = ["request-level block (bisected)"]
        bbody, bmark = adata.get("baseline_body"), adata.get("baseline_marker")
        if bbody and bmark:
            bctx = detect_reflection_context(bbody, bmark) or bctx
            print(f"         Surface context (from baseline): {bctx}")
            for q in ('"', "'", "`"):
                if re.search(r"[=(\s]" + re.escape(q) +
                             r"[^" + re.escape(q) + r"]*" +
                             re.escape(bmark), bbody):
                    attribution_quote = q
                    break
        for i, v in enumerate(verdicts, 1):
            verd = v.get("verdict")
            results.append({
                "reflection_index": 0,
                "position": -1,
                "character_index": i,
                "character_name": v.get("name"),
                "character": v.get("expected"),
                "expected": v.get("expected"),
                "got_back": (v.get("got") if verd != "blocked"
                             else f"request blocked — HTTP "
                                  f"{v.get('status', '?')}"),
                "passed": (True if verd == "passed"
                           else None if verd in ("indeterminate",
                                                 "unresolved")
                           else False),
                "needs_bypass": verd != "passed",
                "contexts": bctx,
            })

    expected_chars = [v for _, v in items]

    for refl_idx, reflected in enumerate(reflected_matches, start=1):
        sink_name = sink_names[refl_idx - 1]
        print(f"--- Reflection [{refl_idx}] ---")
        print(f"    Full reflected: {MARKER_START}{reflected}{MARKER_END}")

        if sink_name is not None:
            # The sink arg is itself the parseable context: for HTML sinks
            # the marker may land inside an attribute of the written markup
            # (e.g. <img src="...searchTerms=MARKER">) — detect that from the
            # arg, not from the page DOM, so attr-breakout grammar applies.
            if sink_name in _DOM_JS_SINKS:
                inner = "javascript raw"
            elif sink_name in _DOM_URL_SINKS:
                inner = "attribute url value"
            else:
                inner = detect_reflection_context(
                    sink_args[refl_idx - 1],
                    MARKER_START + reflected + MARKER_END)[0]
            contexts = [f"dom sink: {sink_name} ({inner})"]
        else:
            contexts = detect_reflection_context(content, MARKER_START + reflected + MARKER_END)
        print(f"    Context:    {', '.join(contexts)}")
        print()

        if indexed:
            parts = extract_items(reflected, seps, len(items))
        else:
            parts = split_by_separator(reflected, len(items))

        if parts is None:
            print(f"    [WARNING] Reflected content split by '{SEPARATOR}' gave an unexpected part count.")
            print(f"    Reflected: {reflected}")
            print("    -> Anomaly: filter mangled the separator. Escalate with")
            print("       send_payloads.py --isolate --url \"...\"")
            print()
            continue

        for i, (name, expected_char) in enumerate(items):
            got = parts[i]

            if got is None:
                print(f"    [{i + 1}] {name} ('{expected_char}')")
                print(f"        Expected:  {expected_char}")
                print(f"        Got back:  <merged — boundary lost>")
                print(f"        Verdict:   INDETERMINATE - merged with neighbour item")
                print()
                results.append({
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
                })
                continue

            passed = got == expected_char

            print(f"    [{i + 1}] {name} ('{expected_char}')")
            print(f"        Expected:  {expected_char}")
            print(f"        Got back:  {got}")
            print(f"        Verdict:   {'PASS - reflected unchanged' if passed else 'FAIL - changed/encoded/removed'}")
            print(f"        Bypass:    {'NO' if passed else 'YES'}")
            print()

            results.append({
                "reflection_index": refl_idx,
                "position": refl_positions[refl_idx - 1]["start"],
                "character_index": i + 1,
                "character_name": name,
                "character": expected_char,
                "expected": expected_char,
                "got_back": got,
                "passed": passed,
                "needs_bypass": not passed,
                "contexts": contexts,
            })

    if not results:
        return

    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print()
    print(f"{'#':<4} {'Character':<20} {'Expected':<12} {'Got back':<20} {'Bypass':<8}")
    print("-" * 68)
    for r in results:
        print(f"{r['character_index']:<4} {r['character_name']:<20} {str(r['expected']):<12} {str(r['got_back']):<20.20} {'YES' if r['needs_bypass'] else 'NO':<8}")
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
            print(f"  [OK] {r['character_name']} ('{r['character']}') -> '{r['expected']}' == '{r['got_back']}'")
        print()

    if failed:
        print(f"[FAIL] {len(failed)} character(s) changed/encoded/removed (bypass needed):")
        for r in failed:
            print(f"  [!] {r['character_name']} ('{r['character']}') -> '{r['expected']}' != '{r['got_back']}'")
        print()
        print("  These characters need a bypass technique (see skill.md).")
        if len(passed) == 0:
            print("  [ANOMALY] All items failed — could be a combination-triggered")
            print("            filter rather than per-character blocking.")
            print("            -> Escalate: send_payloads.py --isolate --url \"...\"")
    else:
        print("[OK] All characters passed through unchanged. No filter/encoding detected.")
        print("     Standard XSS payloads should work without bypass.")

    # Save analysis results to centralized log (Single Source of Truth)
    out_file = new_log_path(out_name, "json")
    with open(out_file, "w") as f:
        json.dump({
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
        }, f, indent=2, ensure_ascii=False)
    print(f"\n💾 Analysis saved to: {out_file}")


if __name__ == "__main__":
    main()
