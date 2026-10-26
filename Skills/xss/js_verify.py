#!/usr/bin/env python3
"""
js_verify.py — "did the reflected payload produce live JavaScript?"

Port of Dalfox's js_context_verify (payload_range_hits_sink) to a dependency-
free mini lexer. A real AST parser would be ideal, but for verification we
only need two span lists from a <script> body / on* handler:

  strings : (start,end) of string literals + template literal *text* parts
  calls   : (start,end) of call-expression callees — ident(, ident`…`,
            obj[…](   — anything that would invoke code
  assigns : (start,end) of `onerror=sink`-style sink-function assignments
            (the onerror=alert;throw 1 idiom fires window.onerror via throw)
  throws  : (start,end) of `throw` statements

Two guards, mirroring Dalfox:

  1. STRING GUARD — a payload range STRICTLY INSIDE one string literal never
     broke out; call-like text inside it is data, not code.
  2. SINK HIT — a call span (or assign+throw pair) FULLY INSIDE the payload's
     byte range means the injection itself produced live code.

Known honest limits (vs a real parser): regex-literal vs division is a
heuristic, unreachable-code reachability is not modelled, and shadowed
builtins cannot be detected statically — render-mode __fired remains the
final arbiter for those.
"""
import re

_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")

# keywords after which '/' starts a regex, not a division
_KW = {
    "return", "typeof", "case", "do", "else", "in", "of", "new", "delete",
    "void", "instanceof", "yield", "await", "throw", "var", "let", "const",
    "function", "if", "while", "for", "switch", "with", "import", "extends",
}
# window.onerror-target properties assigned sink functions (require throw)
_SINK_PROPS = {
    "onerror", "onload", "onfocus", "onclick", "onmouseover", "onmessage",
}
# Direct DOM HTML-parsing assignment sinks (fire without throw)
_HTML_ASSIGN_SINKS = {"innerHTML", "outerHTML", "srcdoc"}
# Navigation assignment sinks (fire without throw when RHS is javascript:)
_NAV_ASSIGN_SINKS = {"location", "href"}


def _skip_string(src, i):
    """i at opening ' or ". Return index after closing quote."""
    q = src[i]
    j = i + 1
    n = len(src)
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == q:
            return j + 1
        j += 1
    return n


def _skip_comment(src, i):
    """i at / or < of a comment start. Return end, or 0 if not a comment."""
    if src.startswith("//", i) or src.startswith("<!--", i):
        j = src.find("\n", i)
        return len(src) if j < 0 else j
    if src.startswith("/*", i):
        j = src.find("*/", i + 2)
        return len(src) if j < 0 else j + 2
    return 0


def _skip_regex(src, i):
    """i at '/' opening a regex literal. Honor \\ escapes and [] classes."""
    j = i + 1
    n = len(src)
    in_class = False
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            # consume flags
            j += 1
            while j < n and src[j].isalpha():
                j += 1
            return j
        elif c == "\n":
            return j
        j += 1
    return n


def _skip_template(src, i, out):
    """i at backtick. Record literal chunks into out['strings'], lex ${}
    interiors as code (recursively). Return index after closing backtick."""
    n = len(src)
    j = i + 1
    lit_start = i  # include the opening backtick in the literal span
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == "`":
            j += 1
            out["strings"].append((lit_start, j))
            return j
        if src.startswith("${", j):
            out["strings"].append((lit_start, j + 2))
            end = _skip_balanced(src, j + 1, out)
            _lex(src[j + 2:end - 1], j + 2, out) if end > j + 3 else None
            j = end
            lit_start = j
            continue
        j += 1
    out["strings"].append((lit_start, n))
    return n


def _skip_balanced(src, i, out):
    """i at the brace/paren/bracket that starts a nested region (src[i] is the
    opener's pair end char position+1 handled by caller convention: i points
    AT the opener). Returns index AFTER the matching closer. Honors strings,
    comments, templates and regex literals."""
    pairs = {"{": "}", "(": ")", "[": "]"}
    open_ch = src[i - 1] if i else src[i]
    # i points just after opener's first char for "${": opener is '{'
    if i > 0 and src[i - 1] == "{":
        open_ch = "{"
    close_ch = pairs.get(open_ch, "}")
    depth = 1
    j = i
    n = len(src)
    while j < n:
        c = src[j]
        if c in "'\"":
            j = _skip_string(src, j)
            continue
        if c == "`":
            j = _skip_template(src, j, out)
            continue
        ce = _skip_comment(src, j)
        if ce:
            j = ce
            continue
        if c == open_ch or (open_ch == "{" and c == "{"):
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return n


def _lex(src, base, out):
    """Scan code-state JS. Fills out['strings'/'calls'/'assigns'/'throws']
    with (start,end) spans offset by base."""
    i, n = 0, len(src)
    last_atom = False      # previous token can end a value -> '/' = division
    while i < n:
        c = src[i]
        if c.isspace():
            i += 1
            continue
        ce = _skip_comment(src, i)
        if ce:
            i = ce
            continue
        if c in "'\"":
            j = _skip_string(src, i)
            out["strings"].append((base + i, base + j))
            i = j
            last_atom = True
            continue
        if c == "`":
            i = _skip_template(src, i, out)
            last_atom = True
            continue
        if c == "/" and not last_atom:
            i = _skip_regex(src, i)
            last_atom = True
            continue
        m = _IDENT_RE.match(src, i)
        if m:
            name = m.group(0)
            j = m.end()
            if name == "throw":
                out["throws"].append((base + i, base + j))
                i = j
                last_atom = False
                continue
            if name in _SINK_PROPS or name in _HTML_ASSIGN_SINKS \
                    or name in _NAV_ASSIGN_SINKS:
                # onerror = alert  /  el.innerHTML = '…'  /  location = 'javascript:…'
                k = j
                while k < n and src[k].isspace():
                    k += 1
                if k < n and src[k] == "=" and src[k:k + 2] != "==":
                    k += 1
                    while k < n and src[k].isspace():
                        k += 1
                    rhs = _IDENT_RE.match(src, k)
                    if name in _HTML_ASSIGN_SINKS and (
                            rhs or src[k:k + 1] in "'\"`"):
                        out.setdefault("sink_assigns", []).append(
                            (base + i, base + k))
                        i = k
                        last_atom = False
                        continue
                    if name in _NAV_ASSIGN_SINKS and src[k:k + 1] in "'\"`" \
                            and re.match(r"""['"`]\s*javascript:""",
                                         src[k:], re.I):
                        out.setdefault("sink_assigns", []).append(
                            (base + i, base + k))
                        i = k
                        last_atom = False
                        continue
                    if name in _SINK_PROPS and (
                            rhs or src[k:k + 1] in "'\"`"):
                        out["assigns"].append((base + i, base + k))
                        i = k
                        last_atom = False
                        continue
            # call: ident(  /  obj.x(  /  obj['k']+'l'(  /  ident`
            k = j
            while True:
                while k < n and src[k].isspace():
                    k += 1
                if src[k:k + 1] == ".":
                    m2 = _IDENT_RE.match(src, k + 1)
                    if m2:
                        k = m2.end()
                        continue
                    break
                if src[k:k + 1] == "[":
                    k = _skip_balanced(src, k + 1, out)
                    continue
                break
            if src[k:k + 1] == "(":
                out["calls"].append((base + i, base + k + 1))
                i = k + 1
                last_atom = True
                continue
            if src[k:k + 1] == "`":
                out["calls"].append((base + i, base + k + 1))
                i = _skip_template(src, k, out)
                last_atom = True
                continue
            i = j
            last_atom = name not in _KW
            continue
        if c.isdigit():
            while i < n and (src[i].isalnum() or src[i] in ".xXbBoO"):
                i += 1
            last_atom = True
            continue
        if c in ")]}":
            last_atom = True
        else:
            last_atom = False
        i += 1


def lex_js(src):
    """Return {'strings','calls','assigns','throws','sink_assigns'} span lists."""
    out = {"strings": [], "calls": [], "assigns": [], "throws": [],
           "sink_assigns": []}
    _lex(src, 0, out)
    return out


def _strictly_inside(s, e, spans):
    return any(a < s and e < b for a, b in spans)


def _hits_in_range(s, e, spans):
    """Calls/assigns/throws fully inside payload range -> the injection
    produced them. Returns (call_hit, assign, throw)."""
    calls = [c for c in spans["calls"] if s <= c[0] and c[1] <= e]
    assigns = [a for a in spans["assigns"] if s <= a[0] and a[1] <= e]
    throws = [t for t in spans["throws"] if s <= t[0] and t[1] <= e]
    return calls, assigns, throws


def _sink_assigns_in_range(s, e, spans):
    return [a for a in spans.get("sink_assigns", [])
            if s <= a[0] and a[1] <= e]


def payload_hits_call(src, payload):
    """True if ANY verbatim occurrence of payload in src produces a live
    call — i.e. not strictly inside a string literal AND containing a call
    span, a direct DOM/nav sink assignment, or an assign+throw pair.
    Mirrors Dalfox payload_range_hits_sink."""
    if not payload:
        return False, ""
    spans = lex_js(src)
    candidates = [payload]
    if '\\"' in payload or "\\'" in payload:
        exp_esc = payload.replace('\\"', '\\\\"').replace("\\'", "\\\\'")
        if exp_esc != payload:
            candidates.append(exp_esc)
    found = False
    for cand in candidates:
        start = 0
        while True:
            idx = src.find(cand, start)
            if idx < 0:
                break
            start = idx + 1
            s, e = idx, idx + len(cand)
            if _strictly_inside(s, e, spans["strings"]):
                continue  # trapped inside a string literal — dead
            found = True
            calls, assigns, throws = _hits_in_range(s, e, spans)
            if calls:
                cs, ce = calls[0]
                return True, f"call survived: {src[cs:ce]}…"
            sinks = _sink_assigns_in_range(s, e, spans)
            if sinks:
                sa = sinks[0]
                return True, f"DOM/nav sink assignment survived: {src[sa[0]:sa[1]]}"
            if assigns and throws:
                a = assigns[0]
                return True, f"sink assignment + throw: {src[a[0]:a[1]]}"
    if not found:
        return None, "payload not reflected verbatim"
    return False, "payload reflected but no surviving call"


def payload_live_in_js(src, needle, marker=None):
    """needle = the marked payload (or core). Verbatim first; if absent and
    marker given, estimate the payload span as len(needle) bytes ending at
    the marker — a stripped payload's residue still sits right before it."""
    ok, ev = payload_hits_call(src, needle)
    if ok is not None:
        return ok, ev
    if not marker or marker not in src:
        return False, "payload not reflected"
    spans = lex_js(src)
    pos = src.find(marker)
    s = max(0, pos - len(needle) - 4)
    calls, assigns, throws = _hits_in_range(s, pos + len(marker), spans)
    if calls:
        return True, f"call survived (stripped payload): {src[calls[0][0]:calls[0][1]]}…"
    sinks = _sink_assigns_in_range(s, pos + len(marker), spans)
    if sinks:
        sa = sinks[0]
        return True, f"DOM/nav sink assignment survived: {src[sa[0]:sa[1]]}"
    if assigns and throws:
        a = assigns[0]
        return True, f"sink assignment + throw: {src[a[0]:a[1]]}"
    return False, "marker reflected but executable core stripped"


def extract_intended_js(payload):
    """Pull the JS fragment our payload intended to run, for attr/URL checks:
    on*=<js>  ->  handler body;  javascript:<js> -> after scheme; else the
    whole payload (js_string/js_raw breakouts are JS themselves)."""
    m = re.search(
        r"on\w+\s*=\s*(\"[^\"]*\"|'[^']*'|\"[^\"]*$|'[^']*$|[^\s>]+)",
        payload)
    if m:
        return m.group(1).strip("'\"")
    m = re.search(r"(?:javascript|data)\s*:\s*(.{1,200})", payload, re.I | re.S)
    if m:
        frag = m.group(1)
        # the tail ends at the tag's closing '>' or quote — not payload bytes
        frag = re.split(r"[<'\">]", frag, maxsplit=1)[0]
        return frag.strip()
    return payload


def script_blocks(html):
    """Yield (open_tag, body) of every <script> in raw html."""
    for m in re.finditer(r"(?is)<script\b[^>]*>(.*?)</script\s*>", html):
        yield m.group(0)[: m.group(0).find(">") + 1], m.group(1)


def script_tag_executable(open_tag):
    """False for data blocks browsers never run: type=application/json,
    ld+json, text/template, module-shim, etc."""
    m = re.search(r'type\s*=\s*["\']?([^"\'>\s]+)', open_tag, re.I)
    if not m:
        return True
    t = m.group(1).lower()
    return t in ("text/javascript", "application/javascript", "module",
                 "text/babel", "text/jsx", "importmap", "speculationrules") \
        or "javascript" in t or "ecmascript" in t
