"""
Shared constants, probe vocabularies, context mappings, and pre-compiled regexes
for the XSS skill pipeline.
"""
from __future__ import annotations

import re

DEFAULT_UA: str = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

MARKER_START: str = "testing1"
MARKER_END: str = "testing2"
NUMERIC_PROBE_MARKER: str = "90197752"
SEPARATOR: str = "x"  # Legacy fallback separator for pre-indexed logs
PLACEHOLDER: str = "{xss_testing}"
MARKER_TEMPLATE: str = "vvm{id}"

PROBE_CHARS: frozenset[str] = frozenset("'\"<>/\\")
DIALOG_FUNCS: tuple[str, ...] = ("alert", "confirm", "prompt", "print")
GLOBAL_OBJECTS: tuple[str, ...] = ("self", "window", "globalThis", "top", "frames")
SINK_FALLBACK_FUNCS: tuple[str, ...] = (
    "eval",
    "setTimeout",
    "Function",
    "fetch",
    "open",
)

# Layer A: 6 fundamental syntactic characters
CHARACTERS: list[tuple[str, str]] = [
    ("single_quote", "'"),
    ("double_quote", '"'),
    ("greater_than", ">"),
    ("less_than", "<"),
    ("slash", "/"),
    ("backslash", "\\"),
]

# Layer B/C (--probe2): keyword, junction, case, and normalization probes
KEYWORDS: list[tuple[str, str]] = [
    ("parentheses", "()"),
    ("backtick", "`"),
    ("alert", "alert"),
    ("confirm", "confirm"),
    ("prompt", "prompt"),
    ("script_tag", "<script>"),
    ("javascript_proto", "javascript:"),
    ("onerror", "onerror"),
    ("img_tag", "<img>"),
    ("entity_lt", "&lt;"),
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
    # Junction probes: WAF signatures fire on combinations, not atoms
    ("call_alert", "alert(1)"),
    ("call_confirm", "confirm(1)"),
    ("call_prompt", "prompt(1)"),
    ("call_print", "print()"),
    ("tick_alert", "alert`1`"),
    ("tick_confirm", "confirm`1`"),
    ("tick_prompt", "prompt`1`"),
    ("tick_print", "print`1`"),
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
    ("js_break_dquote", '"-alert(1)-'),
    ("proto_href", "href=javascript:"),
    # Case-mutation probes: cheap WAFs sign lowercase only
    ("case_script", "ScRiPt"),
    ("case_onload", "OnLoAd"),
    ("case_proto", "JaVaScRiPt:"),
    # Context-syntax probes for comment/template-literal/statement escapes
    ("space", " "),
    ("semicolon", ";"),
    ("braces", "{}"),
    ("newline", "\n"),
    ("comment_close", "*/"),
    ("interp", "${"),
    # Join-operator probes for the `{q} OP fn OP {q}` js-string family —
    # a stripped operator leaves an unparseable `''fn''` composite, so each
    # emitted variant must be gated on its operator's survival.
    ("minus", "-"),
    ("plus", "+"),
    ("star", "*"),
    ("pipe", "|"),
    ("amp", "&"),
    ("caret", "^"),
    ("comma", ","),
    ("bang", "!"),
    ("eq", "="),
    ("percent", "%"),
    ("quest", "?"),
    ("dot", "."),
    # Char-ref spelling variants
    ("hex_ref", "&#x65;"),
    ("nosemi_ref", "&#x65"),
    # Multi-decode & Unicode NFKC normalization probes
    ("double_url_lt", "%3c"),
    ("fullwidth_lt", "\uff1c"),
]

# Grammar primitives (XSStrike genGen model)
TAG_HANDLERS: list[tuple[str, str, str, tuple[str, str, str]]] = [
    ("img", "onerror", "src=x", ("img_tag", "onerror", "pair_img_onerror")),
    ("svg", "onload", "", ("svg_tag", "onload", "pair_svg_onload")),
    ("details", "ontoggle", "open", ("details_tag", "ontoggle", "pair_details_ontoggle")),
    ("body", "onload", "", ("body_tag", "onload", "pair_body_onload")),
    ("iframe", "onload", "", ("iframe_tag", "onload", "pair_iframe_onload")),
]

CONSUMING_TAGS: list[str] = [
    "noscript",
    "style",
    "title",
    "textarea",
    "iframe",
    "script",
]

RAWTEXT_CONTAINERS: tuple[str, ...] = (
    "noscript",
    "style",
    "title",
    "textarea",
    "xmp",
    "noembed",
    "template",
    "iframe",
)

INERT_DOM_CONTAINERS: tuple[str, ...] = (
    "textarea",
    "title",
    "xmp",
    "noembed",
    "noscript",
    "template",
    "style",
)

INERT_SCRIPT_SINKS: tuple[str, ...] = (
    "innerhtml",
    "outerhtml",
    "insertadjacenthtml",
    "createcontextualfragment",
)

GEN_EV: dict[str, str] = {
    "onload": "gen_handler",
    "onerror": "gen_h_error",
}

INNER_QUOTE_CTXS: tuple[str, ...] = (
    "attr_handler",
    "attr_url",
    "attr_srcdoc",
    "js_string",
)

# Map context description fragments -> normalized internal context key
CONTEXT_MAP: list[tuple[str, str]] = [
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

# Curated case-library references (confidence-10 knowledge source)
CASE_REF: dict[str, str] = {
    "breakout_tag": "xss inside an attribute value inside a tag without angle brackets encoded.md",
    "attr_inject": "xss inside an attribute value inside a tag.md",
    "js_breakout": "xss into javascript string without angle brackets encoded.md",
    "js_string_exec": "xss into javascript string with angle brackets encoded.md",
    "tag_breakout": "xss inside a tag.md",
    "body_direct": "xss without encoding and filtering.md",
    "gt_missing": "xss without greater than.md",
    "comment_break": "xss with consuming tags.md",
    "protocol": "xss with javascript protocol.md",
    "obfuscation": "xss with obfuscation.md",
    "special_attrs": "xss with special attributes.md",
    "tag_removed": "xss tag removed.md",
    "no_parens": "xss without parentheses.md",
}

DOM_SINK_CTX: dict[str, str] = {
    "document.write": "dom sink: document.write (html body)",
    "document.writeln": "dom sink: document.writeln (html body)",
    "innerHTML": "dom sink: innerHTML (html body)",
    "eval": "dom sink: eval (javascript raw)",
    "setTimeout(string)": "dom sink: setTimeout(string) (javascript raw)",
}

DOM_JS_SINKS: tuple[str, ...] = (
    "eval",
    "setTimeout(string)",
    "setInterval(string)",
    "Function",
)

DOM_URL_SINKS: tuple[str, ...] = (
    "location.assign",
    "location.replace",
    "window.open",
    "location",
)

# Curated high-signal parameter names for bucketed hidden-parameter mining
COMMON_PARAMS: list[str] = [
    "q", "s", "search", "query", "keyword", "keywords", "id", "page",
    "url", "redirect", "next", "return", "returnUrl", "callback", "cb",
    "jsonp", "name", "user", "username", "msg", "message", "error", "err",
    "title", "text", "body", "content", "html", "data", "input", "val",
    "value", "view", "template", "tpl", "file", "path", "folder", "dir",
    "lang", "locale", "type", "cat", "category", "sort", "order", "filter",
    "ref", "source", "src", "dest", "target", "action", "cmd", "debug",
    "test", "echo", "tag", "term", "token", "code", "email", "key", "item",
    "out", "format", "style", "theme", "color", "label", "comment", "note",
]

# Pre-compiled regexes for DOM source & sink analysis
DOM_PARAM_RE = re.compile(r"""\.(?:get|getAll|has)\(\s*["']([\w-]+)["']""")
DOM_SEARCH_RE = re.compile(
    r"location\.search\b|location\.href\b|document\.(?:URL|documentURI)\b"
)
DOM_HASH_RE = re.compile(r"location\.hash\b")
DOM_PATH_RE = re.compile(r"location\.pathname\b")
CALLBACK_RE = re.compile(
    r"^(callback|cb|jsonp|jsonpcallback|json_callback|jsonpcb|call|"
    r"func|method|cbfn|onload)$",
    re.I,
)
POSTMSG_RE = re.compile(r"""addEventListener\(\s*["']message["']|\.onmessage\s*=""")

SURFACE_SINKS: dict[str, re.Pattern[str]] = {
    "innerHTML": re.compile(r"\.innerHTML\s*="),
    "outerHTML": re.compile(r"\.outerHTML\s*="),
    "document.write": re.compile(r"document\.write(?:ln)?\s*\("),
    "eval()": re.compile(r"\beval\s*\("),
    "new Function()": re.compile(r"new\s+Function\s*\("),
    "setTimeout(string)": re.compile(r"""setTimeout\s*\(\s*["']"""),
    "insertAdjacentHTML": re.compile(r"insertAdjacentHTML\s*\("),
    ".html()": re.compile(r"\.html\s*\("),
}

DOM_SRC_HINT_RE = re.compile(
    r"location\.(?:search|hash|href|pathname|host(?:name)?|port|protocol)\b"
    r"|document\.(?:URL|URLUnencoded|documentURI|baseURI|referrer|cookie)\b"
    r"|window\.name\b|localStorage|sessionStorage"
    r"|event\.data\b|onmessage\b|addEventListener\s*\(\s*['\"]message"
)

DOM_SINK_HINT_RE = re.compile(
    r"document\.(?:write|writeln|open)\b|\.(?:inner|outer)HTML\b"
    r"|insertAdjacentHTML\b|createContextualFragment\b|\.srcdoc\b"
    r"|\beval\s*\(|new\s+Function\b|set(?:Timeout|Interval)\s*\(\s*['\"]"
    r"|location\.(?:assign|replace)\s*\(|\bwindow\.open\s*\(|\.location\s*="
    r"|setAttribute\s*\(\s*['\"]on\w+"
    r"|\$\.(?:parseHTML|globalEval)\s*\("
    r"|\.(?:html|append|prepend|after|before|replaceWith|replaceAll"
    r"|insertAfter|insertBefore|wrap(?:Inner|All)?)\s*\("
)

# Playwright init script injected before any page script runs
RENDER_HOOK_JS: str = """
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
