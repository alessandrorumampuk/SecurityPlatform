"""
HTML & JavaScript context analysis, attack-surface HTML parsing, and
structural breakout computation.
"""
from __future__ import annotations

from html.parser import HTMLParser
import os
import re
import urllib.parse
from typing import Any, Sequence

from .boundary import strip_html_comments
from .constants import (
    CONTEXT_MAP,
    DOM_HASH_RE,
    DOM_PARAM_RE,
    DOM_PATH_RE,
    DOM_SEARCH_RE,
    PLACEHOLDER,
    POSTMSG_RE,
    RAWTEXT_CONTAINERS,
    SURFACE_SINKS,
)

_META_REFRESH_URL_RE = re.compile(r"url\s*=\s*([^;]+)", re.I)
_SCRIPT_ENCLOSING_RE = re.compile(
    r"<script\b[^>]*>(.*?)(?:</script\s*>|$)", re.IGNORECASE | re.DOTALL
)
_OPEN_TAG_NAME_RE = re.compile(r"^<([a-zA-Z][a-zA-Z0-9:-]*)")
_RAWTEXT_RES: dict[str, re.Pattern[str]] = {
    ctag: re.compile(
        rf"<{ctag}\b[^>]*>(.*?)(?:</{ctag}\s*>|$)", re.IGNORECASE | re.DOTALL
    )
    for ctag in RAWTEXT_CONTAINERS
}

_URL_ATTR_NAMES: frozenset[str] = frozenset(
    {"href", "src", "action", "formaction", "data", "xlink:href", "poster"}
)
_DATA_URL_TOKENS: tuple[str, ...] = (
    "url",
    "href",
    "src",
    "link",
    "api",
    "ajax",
    "endpoint",
)
_EMBEDDED_TAGS: frozenset[str] = frozenset(
    {
        "iframe",
        "frame",
        "embed",
        "object",
        "video",
        "audio",
        "source",
        "track",
        "area",
        "base",
    }
)
_IGNORED_INPUT_TYPES: frozenset[str] = frozenset(
    {"hidden", "submit", "button", "image", "reset"}
)


class SurfaceParser(HTMLParser):
    """Collect same-host links with query params, embedded URLs, scripts, and forms."""

    def __init__(self, host: str) -> None:
        super().__init__(convert_charrefs=True)
        self.host = host
        self._base: str = ""
        self.links: list[str] = []
        self.embedded: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.scripts: list[str] = []
        self.script_srcs: list[str] = []
        self._form: dict[str, Any] | None = None
        self._in_script: bool = False
        self._script_buf: list[str] = []

    def _collect_embedded(self, raw: str) -> None:
        u = self._absolute(self._base, raw)
        if (
            u
            and urllib.parse.urlsplit(u).hostname == self.host
            and urllib.parse.urlsplit(u).query
        ):
            self.embedded.append(u)

    def _absolute(self, base: str, href: str) -> str | None:
        try:
            u = urllib.parse.urljoin(base, href)
        except Exception:
            return None
        if urllib.parse.urlsplit(u).scheme not in ("http", "https"):
            return None
        return u

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        d = {k: (v or "") for k, v in attrs}
        if tag == "script":
            self._in_script = True
            self._script_buf = []
            src = d.get("src")
            if src:
                u = self._absolute(self._base, src)
                if u and urllib.parse.urlsplit(u).hostname == self.host:
                    self.script_srcs.append(u)
        elif tag == "a" and d.get("href"):
            u = self._absolute(self._base, d["href"])
            if (
                u
                and urllib.parse.urlsplit(u).hostname == self.host
                and urllib.parse.urlsplit(u).query
            ):
                self.links.append(u)
        elif tag == "form":
            self._form = {
                "action": d.get("action", ""),
                "method": (d.get("method") or "get").lower(),
                "fields": [],
            }
        elif self._form is not None and tag in ("input", "textarea", "select"):
            name = d.get("name")
            ftype = (d.get("type") or "text").lower()
            if name and ftype not in _IGNORED_INPUT_TYPES:
                self._form["fields"].append(name)

        if tag == "meta" and "refresh" in (d.get("http-equiv") or "").lower():
            m = _META_REFRESH_URL_RE.search(d.get("content") or "")
            if m:
                self._collect_embedded(m.group(1).strip(" '\""))
        elif tag in _EMBEDDED_TAGS:
            for k in ("src", "data", "href", "poster"):
                if d.get(k):
                    self._collect_embedded(d[k])
        for k, v in d.items():
            if not v:
                continue
            if k == "formaction" or (
                k.startswith("data-")
                and any(t in k for t in _DATA_URL_TOKENS)
            ):
                self._collect_embedded(v)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "script" and self._in_script:
            self.scripts.append("".join(self._script_buf))
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_buf.append(data)


def param_templates(url: str, host: str) -> list[tuple[str, str]]:
    """Build one `{xss_testing}` URL template per query parameter of a same-host URL."""
    u = urllib.parse.urlsplit(url)
    if (u.hostname or "") != host or not u.query:
        return []
    segs = u.query.split("&")
    out: list[tuple[str, str]] = []
    for i, seg in enumerate(segs):
        key = seg.split("=", 1)[0]
        if not key:
            continue
        q = "&".join(
            s if j != i else f"{key}={PLACEHOLDER}" for j, s in enumerate(segs)
        )
        out.append((urllib.parse.urlunsplit(u._replace(query=q)), key))
    return out


def dom_source_params(
    script_texts: Sequence[str],
) -> tuple[set[str], bool, bool, bool]:
    """Return `(param_names, reads_search, reads_hash, reads_path)` from scripts."""
    names: set[str] = set()
    search = hash_ = path = False
    for src in script_texts:
        names.update(DOM_PARAM_RE.findall(src))
        if DOM_SEARCH_RE.search(src):
            search = True
        if DOM_HASH_RE.search(src):
            hash_ = True
        if DOM_PATH_RE.search(src):
            path = True
    return names, search, hash_, path


def dom_extras(script_texts: Sequence[str]) -> tuple[bool, list[str]]:
    """Return `(postmessage_source_seen, sorted_sink_names)` from scripts."""
    postmsg = any(POSTMSG_RE.search(s) for s in script_texts)
    sinks = sorted(
        n
        for n, rx in SURFACE_SINKS.items()
        if any(rx.search(s) for s in script_texts)
    )
    return postmsg, sinks


def compute_js_breakout(prefix: str) -> tuple[str, str, str]:
    """Scan a `<script>` prefix up to the injection marker and return
    `(js_subctx, enclosing_quote, structural_closer)`.

    Tracks string/template/comment states and unbalanced `( [ { ${` openers so
    nested reflections like `foo({a: ["MARKER"]})` get closer `"]})`.
    """
    state = "code"
    stack: list[str] = []
    i, n = 0, len(prefix)
    while i < n:
        c = prefix[i]
        if state == "code":
            if c == "'":
                state = "squote"
            elif c == '"':
                state = "dquote"
            elif c == "`":
                state = "template"
            elif c == "/" and prefix[i : i + 2] == "//":
                state = "lcomment"
                i += 1
            elif c == "/" and prefix[i : i + 2] == "/*":
                state = "bcomment"
                i += 1
            elif c in "([{":
                stack.append({"{": "}", "(": ")", "[": "]"}[c])
            elif c in ")]}":
                if stack and stack[-1] == c:
                    stack.pop()
                elif c == "}" and stack and stack[-1] == "}`":
                    stack.pop()
                    state = "template"
        elif state == "squote":
            if c == "\\":
                i += 2
                continue
            if c == "'":
                state = "code"
        elif state == "dquote":
            if c == "\\":
                i += 2
                continue
            if c == '"':
                state = "code"
        elif state == "template":
            if c == "\\":
                i += 2
                continue
            if c == "`":
                state = "code"
            elif c == "$" and prefix[i : i + 2] == "${":
                stack.append("}`")
                state = "code"
                i += 2
                continue
        elif state == "lcomment":
            if c == "\n":
                state = "code"
        elif state == "bcomment":
            if c == "*" and prefix[i : i + 2] == "*/":
                state = "code"
                i += 1
        i += 1

    closer_tail = "".join(reversed(stack))
    if state == "bcomment":
        return "javascript block comment", "", "*/" + closer_tail
    if state == "lcomment":
        return "javascript line comment", "", "\n" + closer_tail
    if state == "template":
        return "javascript template literal", "`", "`" + closer_tail
    if state in ("squote", "dquote"):
        q = "'" if state == "squote" else '"'
        return "javascript string", q, q + closer_tail
    return "javascript raw", "", closer_tail


def _parse_open_tag_before(prefix_from_lt: str) -> tuple[str, str, str] | None:
    """If `prefix_from_lt` (`'<tag attr1="v" attr2="...'`) is an unclosed HTML
    start tag (no unquoted `>` before the end), return
    `(tag_name, attr_name, quote_char_or_empty)`, or `None` if closed."""
    m = _OPEN_TAG_NAME_RE.match(prefix_from_lt)
    if not m:
        return None
    tag = m.group(1).lower()
    i, n = m.end(), len(prefix_from_lt)
    in_q: str | None = None
    attr_name = ""
    after_eq = False
    while i < n:
        c = prefix_from_lt[i]
        if in_q:
            if c == in_q:
                in_q = None
                after_eq = False
                attr_name = ""
        else:
            if c == ">":
                return None
            if c in ('"', "'"):
                if after_eq:
                    in_q = c
            elif c == "=":
                after_eq = True
            elif c.isspace() or c == "/":
                if after_eq:
                    after_eq = False
                    attr_name = ""
            else:
                if not after_eq:
                    j = i
                    while (
                        j < n
                        and not prefix_from_lt[j].isspace()
                        and prefix_from_lt[j] not in "=>\"'/"
                    ):
                        j += 1
                    attr_name = prefix_from_lt[i:j].lower()
                    i = j
                    continue
        i += 1
    if in_q:
        return tag, attr_name, in_q
    if after_eq:
        return tag, attr_name, ""
    return tag, "", ""


def inspect_reflection_point(
    content: str, reflected_full: str, pos: int | None = None
) -> tuple[list[str], str, str]:
    """Position-aware context, quote, and JS-closer detector for a single
    reflection occurrence. Returns `(contexts_list, quote_char, js_closer)`."""
    raw_pos = content.find(reflected_full) if pos is None else pos
    if raw_pos < 0:
        raw_pos = 0
    # 1. HTML comment check on raw content before stripping comments
    c_open = content.rfind("<!--", 0, raw_pos)
    if c_open >= 0 and content.find("-->", c_open, raw_pos) < 0:
        return ["html comment"], "", ""

    body = strip_html_comments(content)
    bpos = body.find(reflected_full)
    if bpos < 0:
        bpos = min(raw_pos, len(body))

    # 2. Enclosing <script> check via prefix lexical scan
    for sm in _SCRIPT_ENCLOSING_RE.finditer(body):
        if sm.start(1) <= bpos < sm.end(1):
            prefix = body[sm.start(1) : bpos]
            js_ctx, q, closer = compute_js_breakout(prefix)
            return [js_ctx], q, closer

    # 3. Enclosing rawtext / consuming tag check
    for ctag, rx in _RAWTEXT_RES.items():
        for tm in rx.finditer(body):
            if tm.start(1) <= bpos < tm.end(1):
                return [f"inside {ctag} tag"], "", ""

    # 4. Universal HTML tag / attribute check strictly before bpos
    lt = body.rfind("<", 0, bpos)
    if lt >= 0:
        tag_info = _parse_open_tag_before(body[lt:bpos])
        if tag_info is not None:
            _tag, attr, q = tag_info
            if attr.startswith("on"):
                return ["attribute event-handler value"], q, ""
            if attr == "srcdoc":
                return ["attribute srcdoc value"], q, ""
            if attr in _URL_ATTR_NAMES:
                return ["attribute url value"], q, ""
            has_enc_q = (
                "&#039;" in reflected_full or "&quot;" in reflected_full
            )
            has_raw_q = "'" in reflected_full or '"' in reflected_full
            if has_enc_q and not has_raw_q:
                return ["attribute value (quotes encoded)"], q, ""
            return ["attribute value (quotes NOT encoded)"], q, ""

    return ["html body (text content)"], "", ""


def detect_reflection_context(
    content: str, reflected_full: str, pos: int | None = None
) -> list[str]:
    """Detect where in the HTML the input is reflected."""
    ctxs, _q, _closer = inspect_reflection_point(
        content, reflected_full, pos=pos
    )
    return ctxs


def normalize_contexts(contexts: Sequence[str]) -> list[str]:
    """Map human-readable context labels to internal grammar keys."""
    keys: list[str] = []
    for c in contexts:
        c_low = c.lower()
        for frag, key in CONTEXT_MAP:
            if frag in c_low:
                keys.append(key)
                break
    return keys or ["html"]


def detect_quote(source_html: str, marker_full: str) -> str:
    """Fallback quote detector: inspect saved response HTML around `marker_full`."""
    if not source_html or not os.path.exists(source_html):
        return '"'
    with open(source_html, encoding="utf-8", errors="replace") as fh:
        body = fh.read()
    esc = re.escape(marker_full)
    for q in ('"', "'", "`"):
        rq = re.escape(q)
        if re.search(rf"[=(\s]{rq}[^{rq}]*{esc}", body, re.DOTALL):
            return q
    if re.search(rf"=[^\s\"'>]*{esc}", body):
        return ""
    return '"'


def breakers(ctx: str, quote: str) -> list[str]:
    """Minimal string needed to escape the context (XSStrike 'breaker')."""
    if ctx == "html":
        return [""]
    if ctx == "attr":
        if quote == "":
            return [">", " autofocus onfocus="]
        return [quote + ">", f"{quote} autofocus onfocus={quote}"]
    if ctx == "js_string":
        return ["</script>", quote + "-"]
    if ctx in (
        "attr_handler",
        "attr_url",
        "attr_srcdoc",
        "js_raw",
        "js_template",
    ):
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
