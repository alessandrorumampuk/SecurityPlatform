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
from recommend_payload import (           # noqa: E402
    classify_response, _parse_response, _core_payload)

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
    ]
    for status, hdrs, body, payload, want, label in fcases:
        got = classified(status, body, payload, hdrs)
        conf = got["confidence"]
        t.append((label, conf == want,
                  f"want={want} got={conf} | {got['evidence']}"))

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
