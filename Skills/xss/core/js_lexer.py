"""
Dependency-free JavaScript mini-lexer and call-survival verifier.

Port of Dalfox's `js_context_verify` (`payload_range_hits_sink`) extended with:
  - Standard identifier & member calls (`alert(1)`, `window.alert(1)`)
  - Computed bracket calls (`self['a'+'lert'](1)`, `top["\\x61lert"](1)`)
  - Optional-chaining calls (`alert?.(1)`, `window?.alert?.(1)`)
  - Parenthesized & comma-operator indirect calls (`(alert)(1)`, `(0,alert)(1)`)
  - Higher-order callback calls (`[1].find(alert)`, `Reflect.apply(alert,0,[1])`)
  - Non-alphanumeric JSFuck calls (`[][...][...](...)()`)
  - Tagged template calls (`alert`1``, `(alert)`1``)
  - Direct DOM/navigation sink assignments (`innerHTML=...`, `location='javascript:...'`)
  - Exception-handler sink pairs (`onerror=alert;throw 1`, `{onerror=alert}throw 1`)
"""
from __future__ import annotations

import re
from typing import Any

from .types import LexSpans

_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_JS_PROTO_STR_RE = re.compile(r"""['"`]\s*javascript:""", re.I)
_ON_HANDLER_EXTRACT_RE = re.compile(
    r"on\w+\s*=\s*(\"[^\"]*\"|'[^']*'|\"[^\"]*$|'[^']*$|[^\s>]+)"
)
_SCHEME_EXTRACT_RE = re.compile(
    r"(?:javascript|data)\s*:\s*(.{1,4000})", re.I | re.S
)
_SCRIPT_BLOCK_RE = re.compile(r"(?is)<script\b[^>]*>(.*?)</script\s*>")
_SCRIPT_TYPE_RE = re.compile(r'type\s*=\s*["\']?([^"\'>\s]+)', re.I)

# Keywords after which '/' starts a regex literal, not division
_KW: frozenset[str] = frozenset(
    {
        "return",
        "typeof",
        "case",
        "do",
        "else",
        "in",
        "of",
        "new",
        "delete",
        "void",
        "instanceof",
        "yield",
        "await",
        "throw",
        "var",
        "let",
        "const",
        "function",
        "if",
        "while",
        "for",
        "switch",
        "with",
        "import",
        "extends",
    }
)

# Control-flow keywords whose `(cond)` is NOT a parenthesized function callee
_CONTROL_PAREN_KW: frozenset[str] = frozenset(
    {"if", "while", "for", "switch", "with", "catch", "function"}
)

# Higher-order array/reflection methods that require a surviving callback identifier
_CALLBACK_METHODS: frozenset[str] = frozenset(
    {"find", "map", "forEach", "filter", "some", "every", "flatMap", "reduce"}
)

# window.onerror-target properties assigned sink functions (require throw)
_SINK_PROPS: frozenset[str] = frozenset(
    {"onerror", "onload", "onfocus", "onclick", "onmouseover", "onmessage"}
)

# Direct DOM HTML-parsing assignment sinks (fire without throw)
_HTML_ASSIGN_SINKS: frozenset[str] = frozenset({"innerHTML", "outerHTML", "srcdoc"})

# Navigation assignment sinks (fire without throw when RHS is javascript:)
_NAV_ASSIGN_SINKS: frozenset[str] = frozenset({"location", "href"})

_EXECUTABLE_SCRIPT_TYPES: frozenset[str] = frozenset(
    {
        "text/javascript",
        "application/javascript",
        "module",
        "text/babel",
        "text/jsx",
        "importmap",
        "speculationrules",
    }
)


def _skip_string(src: str, i: int) -> int:
    """`i` at opening `'` or `"`. Return index after closing quote."""
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


def _skip_comment(src: str, i: int) -> int:
    """`i` at `/` or `<` of a comment start. Return end index, or 0 if not a comment."""
    if src.startswith("//", i) or src.startswith("<!--", i):
        j = src.find("\n", i)
        return len(src) if j < 0 else j
    if src.startswith("/*", i):
        j = src.find("*/", i + 2)
        return len(src) if j < 0 else j + 2
    return 0


def _skip_ws_and_comments(src: str, i: int) -> int:
    """Advance `i` past any whitespace and inline comments."""
    n = len(src)
    while i < n:
        if src[i].isspace():
            i += 1
            continue
        ce = _skip_comment(src, i)
        if ce:
            i = ce
            continue
        break
    return i


def _skip_regex(src: str, i: int) -> int:
    """`i` at `/` opening a regex literal. Honor `\\` escapes and `[]` classes."""
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
            j += 1
            while j < n and src[j].isalpha():
                j += 1
            return j
        elif c == "\n":
            return j
        j += 1
    return n


def _skip_template(src: str, i: int, out: dict[str, list[tuple[int, int]]]) -> int:
    """`i` at backtick. Record literal chunks into `out['strings']`, lex `${}`
    interiors as code recursively. Return index after closing backtick."""
    n = len(src)
    j = i + 1
    lit_start = i
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
            if end > j + 3:
                _lex(src[j + 2 : end - 1], j + 2, out)
            j = end
            lit_start = j
            continue
        j += 1
    out["strings"].append((lit_start, n))
    return n


def _skip_balanced(src: str, i: int, out: dict[str, list[tuple[int, int]]]) -> int:
    """`i` points just after the opening brace/paren/bracket. Returns index
    AFTER the matching closer, honoring strings, comments, templates."""
    pairs = {"{": "}", "(": ")", "[": "]"}
    open_ch = src[i - 1] if i else src[i]
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


def _empty_spans() -> dict[str, list[tuple[int, int]]]:
    return {
        "strings": [],
        "calls": [],
        "assigns": [],
        "throws": [],
        "sink_assigns": [],
    }


def _lex(src: str, base: int, out: dict[str, list[tuple[int, int]]]) -> None:
    """Scan code-state JS. Fills `out` with `(start, end)` spans offset by `base`."""
    i, n = 0, len(src)
    last_atom = False
    last_kw = ""
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
            last_kw = ""
            continue
        if c == "`":
            i = _skip_template(src, i, out)
            last_atom = True
            last_kw = ""
            continue
        if c == "/" and not last_atom:
            i = _skip_regex(src, i)
            last_atom = True
            last_kw = ""
            continue

        # Computed array-literal member call: JSFuck `[][...][...](...)()`
        if c == "[" and not last_atom and src[i : i + 2] == "[]":
            dummy = _empty_spans()
            k = i + 2
            brackets_seen = 0
            while k < n:
                k = _skip_ws_and_comments(src, k)
                if src[k : k + 2] == "?.":
                    k = _skip_ws_and_comments(src, k + 2)
                if src[k : k + 1] == "[":
                    end_b = _skip_balanced(src, k + 1, dummy)
                    if end_b <= k + 2:
                        # Empty `[]` inside member access is not a valid method key
                        brackets_seen = 0
                        break
                    brackets_seen += 1
                    k = end_b
                    continue
                break
            if brackets_seen >= 1 and src[k : k + 1] == "(":
                # A 2-step property chain `[][method]["constructor"](code)`
                # only constructs a Function; it requires a trailing `()` call
                # to actually execute.
                if brackets_seen >= 2:
                    end_args = _skip_balanced(src, k + 1, dummy)
                    k_invoke = _skip_ws_and_comments(src, end_args)
                    if src[k_invoke : k_invoke + 1] != "(":
                        i = end_args
                        last_atom = True
                        last_kw = ""
                        continue
                out["calls"].append((base + i, base + k + 1))
                out["strings"].extend(
                    (base + s, base + e) for s, e in dummy["strings"]
                )
                i = k + 1
                last_atom = True
                last_kw = ""
                continue

        # Parenthesized callee invocation: `(alert)(1)`, `(0,alert)(1)`, `(alert)`1``
        if c == "(" and not last_atom and last_kw not in _CONTROL_PAREN_KW:
            dummy = _empty_spans()
            end_p = _skip_balanced(src, i + 1, dummy)
            if end_p > i + 2 and end_p <= n:
                interior = src[i + 1 : end_p - 1]
                k = _skip_ws_and_comments(src, end_p)
                if src[k : k + 2] == "?.":
                    k = _skip_ws_and_comments(src, k + 2)
                if src[k : k + 1] in ("(", "`") and (
                    _IDENT_RE.search(interior) or "][" in interior
                ):
                    out["calls"].append((base + i, base + k + 1))
                    _lex(interior, base + i + 1, out)
                    if src[k : k + 1] == "`":
                        i = _skip_template(src, k, out)
                    else:
                        i = k + 1
                    last_atom = True
                    last_kw = ""
                    continue

        m = _IDENT_RE.match(src, i)
        if m:
            name = m.group(0)
            j = m.end()
            if name == "throw":
                out["throws"].append((base + i, base + j))
                i = j
                last_atom = False
                last_kw = "throw"
                continue
            if (
                name in _SINK_PROPS
                or name in _HTML_ASSIGN_SINKS
                or name in _NAV_ASSIGN_SINKS
            ):
                k = _skip_ws_and_comments(src, j)
                if k < n and src[k] == "=" and src[k : k + 2] != "==":
                    k = _skip_ws_and_comments(src, k + 1)
                    rhs = _IDENT_RE.match(src, k)
                    rhs_ok = bool(rhs and rhs.group(0) not in _KW)
                    if name in _HTML_ASSIGN_SINKS and (
                        rhs_ok or src[k : k + 1] in "'\"`"
                    ):
                        out.setdefault("sink_assigns", []).append(
                            (base + i, base + k)
                        )
                        i = k
                        last_atom = False
                        last_kw = ""
                        continue
                    if (
                        name in _NAV_ASSIGN_SINKS
                        and src[k : k + 1] in "'\"`"
                        and _JS_PROTO_STR_RE.match(src[k:])
                    ):
                        out.setdefault("sink_assigns", []).append(
                            (base + i, base + k)
                        )
                        i = k
                        last_atom = False
                        last_kw = ""
                        continue
                    if name in _SINK_PROPS and (
                        rhs_ok or src[k : k + 1] in "'\"`["
                    ):
                        out["assigns"].append((base + i, base + k))
                        i = k
                        last_atom = False
                        last_kw = ""
                        continue

            # Call expression: ident( / ident?.( / obj.x( / obj['k']+'l'( / ident`
            k = j
            last_prop = name
            while True:
                k = _skip_ws_and_comments(src, k)
                if src[k : k + 2] == "?.":
                    k_after = _skip_ws_and_comments(src, k + 2)
                    m2 = _IDENT_RE.match(src, k_after)
                    if m2:
                        last_prop = m2.group(0)
                        k = m2.end()
                        continue
                    if src[k_after : k_after + 1] == "[":
                        k = _skip_balanced(src, k_after + 1, out)
                        continue
                    # Optional-chaining call `ident?.(` or `ident?.`1``
                    k = k_after
                    break
                if src[k : k + 1] == ".":
                    k_after = _skip_ws_and_comments(src, k + 1)
                    m2 = _IDENT_RE.match(src, k_after)
                    if m2:
                        last_prop = m2.group(0)
                        k = m2.end()
                        continue
                    break
                if src[k : k + 1] == "[":
                    k = _skip_balanced(src, k + 1, out)
                    continue
                break

            if src[k : k + 1] == "(":
                # Higher-order callback methods (`[1].find(alert)`, `Reflect.apply(alert,0,[1])`)
                # only count if their first argument still contains a surviving identifier
                if last_prop in _CALLBACK_METHODS or (
                    name == "Reflect" and last_prop == "apply"
                ):
                    dummy = _empty_spans()
                    end_call = _skip_balanced(src, k + 1, dummy)
                    arg_body = src[k + 1 : max(k + 1, end_call - 1)]
                    first_arg = arg_body.split(",", 1)[0]
                    if not _IDENT_RE.search(first_arg):
                        i = k + 1
                        last_atom = True
                        last_kw = ""
                        continue
                out["calls"].append((base + i, base + k + 1))
                i = k + 1
                last_atom = True
                last_kw = ""
                continue
            if src[k : k + 1] == "`":
                out["calls"].append((base + i, base + k + 1))
                i = _skip_template(src, k, out)
                last_atom = True
                last_kw = ""
                continue
            i = j
            last_atom = name not in _KW
            last_kw = name if name in _KW else ""
            continue

        if c.isdigit():
            while i < n and (src[i].isalnum() or src[i] in ".xXbBoO"):
                i += 1
            last_atom = True
            last_kw = ""
            continue
        if c in ")]}":
            last_atom = True
        else:
            last_atom = False
        last_kw = ""
        i += 1


def lex_js(src: str) -> LexSpans:
    """Return `{'strings', 'calls', 'assigns', 'throws', 'sink_assigns'}` span lists."""
    out = _empty_spans()
    _lex(src, 0, out)
    return out  # type: ignore[return-value]


def _strictly_inside(s: int, e: int, spans: list[tuple[int, int]]) -> bool:
    return any(a < s and e < b for a, b in spans)


def _hits_in_range(
    s: int, e: int, spans: LexSpans
) -> tuple[list[tuple[int, int]], list[tuple[int, int]], list[tuple[int, int]]]:
    """Return `(calls, assigns, throws)` fully inside `[s, e]`."""
    calls = [c for c in spans["calls"] if s <= c[0] and c[1] <= e]
    assigns = [a for a in spans["assigns"] if s <= a[0] and a[1] <= e]
    throws = [t for t in spans["throws"] if s <= t[0] and t[1] <= e]
    return calls, assigns, throws


def _sink_assigns_in_range(s: int, e: int, spans: LexSpans) -> list[tuple[int, int]]:
    return [
        a for a in spans.get("sink_assigns", []) if s <= a[0] and a[1] <= e
    ]


def payload_hits_call(src: str, payload: str) -> tuple[bool | None, str]:
    """Return `(True, evidence)` if ANY verbatim occurrence of `payload` in
    `src` produces a live call, `(False, reason)` if reflected but inert, or
    `(None, reason)` if not reflected verbatim."""
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
                continue
            found = True
            calls, assigns, throws = _hits_in_range(s, e, spans)
            if calls:
                cs, ce = calls[0]
                return True, f"call survived: {src[cs:ce]}…"
            sinks = _sink_assigns_in_range(s, e, spans)
            if sinks:
                sa = sinks[0]
                return (
                    True,
                    f"DOM/nav sink assignment survived: {src[sa[0]:sa[1]]}",
                )
            if assigns and throws:
                a = assigns[0]
                return True, f"sink assignment + throw: {src[a[0]:a[1]]}"
    if not found:
        return None, "payload not reflected verbatim"
    return False, "payload reflected but no surviving call"


def payload_live_in_js(
    src: str, needle: str, marker: str | None = None
) -> tuple[bool, str]:
    """Verify whether `needle` (or its residue before `marker`) produced live
    executable JavaScript in `src`."""
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
        return (
            True,
            f"call survived (stripped payload): {src[calls[0][0]:calls[0][1]]}…",
        )
    sinks = _sink_assigns_in_range(s, pos + len(marker), spans)
    if sinks:
        sa = sinks[0]
        return True, f"DOM/nav sink assignment survived: {src[sa[0]:sa[1]]}"
    if assigns and throws:
        a = assigns[0]
        return True, f"sink assignment + throw: {src[a[0]:a[1]]}"
    return False, "marker reflected but executable core stripped"


def extract_intended_js(payload: str) -> str:
    """Extract the JS fragment a payload intended to execute for attribute/URL
    verification (`on*=<js>` -> handler body; `javascript:<js>` -> scheme body)."""
    m = _ON_HANDLER_EXTRACT_RE.search(payload)
    if m:
        return m.group(1).strip("'\"")
    m = _SCHEME_EXTRACT_RE.search(payload)
    if m:
        frag = m.group(1)
        frag = re.split(r"[<'\">]", frag, maxsplit=1)[0]
        return frag.strip()
    return payload


def script_blocks(html: str) -> Any:
    """Yield `(open_tag, body)` of every `<script>` element in raw HTML."""
    for m in _SCRIPT_BLOCK_RE.finditer(html):
        yield m.group(0)[: m.group(0).find(">") + 1], m.group(1)


def script_tag_executable(open_tag: str) -> bool:
    """Return `False` for non-executable data script blocks (`application/json`,
    `ld+json`, `text/template`, etc.)."""
    m = _SCRIPT_TYPE_RE.search(open_tag)
    if not m:
        return True
    t = m.group(1).lower()
    return (
        t in _EXECUTABLE_SCRIPT_TYPES
        or "javascript" in t
        or "ecmascript" in t
    )
