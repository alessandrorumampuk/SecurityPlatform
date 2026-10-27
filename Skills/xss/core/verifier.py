"""
Marker-based DOM & JavaScript verification engine (Dalfox R/V model).

Grades injected candidate payloads:
  - `V`       : Confirmed executable DOM position + surviving live JS call/sink
  - `R`       : Reflected in response, but inert / trapped / stripped
  - `blocked` : Rejected by WAF / server (HTTP >= 400 with no reflection)
  - `none`    : Not reflected in response
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from html import escape as html_escape, unescape as html_unescape
from html.parser import HTMLParser
import re
import secrets
import string
from typing import Any
from urllib.parse import quote

from .composer import compose
from .constants import INERT_DOM_CONTAINERS, MARKER_TEMPLATE, PLACEHOLDER
from . import js_lexer as js_verify
from .obfuscators import usable
from .transport import (
    fetch_rendered,
    parse_raw_http_response,
    send_verify_request,
)

_EXEC_SCHEME_RE = re.compile(r"\s*(javascript:|data:text|vbscript:)", re.I)
_SRCDOC_EXEC_RE = re.compile(r"(on\w+=|<script|&lt;script|onerror)", re.I)
_CSP_DIRECTIVE_RE = re.compile(r"(?:script-src|default-src)")
_EMPTY_COMMENT_HUSK_RE = re.compile(r"/\*\s*\*/")
_WINDOW_ONERROR_QUAL_RE = re.compile(
    r"(?:self|window|top|parent|globalThis|frames)\s*\.\s*onerror\s*="
)
_SCHEME_PREFIX_STRIP_RE = re.compile(
    r"^\s*(?:javascript|data:text/html[^,]*,)\s*", re.I
)


class MarkerDomCheck(HTMLParser):
    """Walk the HTML response and record whether the marker element lands in
    an executable DOM position (`on*` handler, `<script>` body, `javascript:`/`data:`
    URL, or `<iframe srcdoc>`)."""

    _INERT_CONTAINERS = INERT_DOM_CONTAINERS

    def __init__(self, marker: str, script_inert: bool = False) -> None:
        super().__init__(convert_charrefs=False)
        self.marker = marker
        self.script_inert = script_inert
        self.executable = False
        self.evidence = ""
        self._in_script = False
        self._script_nonexec = False
        self._script_buf: str | None = None
        self._inert_tag: str | None = None
        self.script_hits: list[str] = []
        self.attr_hits: list[tuple[str, str, str]] = []
        self.url_hits: list[tuple[str, str, str]] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        t_low = tag.lower()
        if self._inert_tag is not None:
            return
        d = dict(attrs)
        if t_low == "script":
            self._in_script = True
            self._script_buf = ""
            stype = (d.get("type") or "").strip().lower()
            self._script_nonexec = bool(
                stype
                and stype
                not in (
                    "text/javascript",
                    "application/javascript",
                    "module",
                    "text/ecmascript",
                    "application/ecmascript",
                )
                and "javascript" not in stype
                and "ecmascript" not in stype
            )
        joined = " ".join(str(v or "") for v in d.values())
        has_marker = self.marker in joined or self.marker in "".join(d.keys())
        if has_marker:
            for k, v in d.items():
                if k.startswith("on"):
                    self.executable = True
                    self.attr_hits.append((tag, k, v or ""))
                    self.evidence = (
                        f"<{tag}> marker element carries event handler {k}"
                    )
                if (
                    k in ("href", "src", "action", "formaction")
                    and v
                    and _EXEC_SCHEME_RE.match(v)
                ):
                    self.executable = True
                    self.url_hits.append((tag, k, v))
                    self.evidence = (
                        f"<{tag}> marker element has executable {k} URL"
                    )
                if k == "srcdoc" and v and _SRCDOC_EXEC_RE.search(v):
                    self.executable = True
                    self.evidence = (
                        "marker inside <iframe srcdoc> executable HTML"
                    )
            if (
                t_low == "script"
                and not self.script_inert
                and not self._script_nonexec
            ):
                self.executable = True
                self.evidence = "marker inside <script> element"
        if t_low in self._INERT_CONTAINERS:
            self._inert_tag = t_low

    def handle_endtag(self, tag: str) -> None:
        t_low = tag.lower()
        if self._inert_tag == t_low:
            self._inert_tag = None
            return
        if self._inert_tag is not None:
            return
        if t_low == "script":
            if (
                self._script_buf
                and self.marker in self._script_buf
                and not self._script_nonexec
            ):
                self.script_hits.append(self._script_buf)
            self._in_script = False
            self._script_nonexec = False
            self._script_buf = None

    def handle_data(self, data: str) -> None:
        if self._inert_tag is not None:
            return
        if self._in_script:
            if self._script_buf is not None:
                self._script_buf += data
            if (
                not self.script_inert
                and not self._script_nonexec
                and self.marker in data
            ):
                self.executable = True
                self.evidence = "marker inside <script> body"


def _core_payload(marked: str, marker: str) -> str:
    """Strip `<!--marker-->` or `/*marker*/` tail and any in-payload `marker`."""
    core = marked.replace(f"<!--{marker}-->", "")
    return core.replace(marker, "")


def _parse_response(raw: str) -> tuple[int, dict[str, str], str]:
    """Alias for `parse_raw_http_response` kept for backward compatibility."""
    return parse_raw_http_response(raw)


def _locate_anchor(
    body: str, marker: str, marked: str
) -> tuple[str | None, str]:
    """Find what reflected in `body`: `marker` first, then `core` fallbacks
    (verbatim -> HTML-escaped -> URL-encoded)."""
    if marker in body:
        return marker, "marker"
    core = _core_payload(marked, marker)
    for variant, style in (
        (core, "core"),
        (html_escape(core), "core html-encoded"),
        (quote(core, safe=""), "core url-encoded"),
    ):
        if variant and variant in body:
            return variant, style
    return None, ""


def classify_response(
    status: int,
    headers: dict[str, str],
    body: str,
    payload: str,
    marker: str,
    marked: str | None = None,
) -> dict[str, str]:
    """Pure response classifier:
    `blocked? -> marker/core anchor? -> executable DOM position? -> surviving JS call? -> V / R / none`."""
    if marked is None:
        marked = payload.replace(MARKER_TEMPLATE, marker)
        if "vvm" not in marked:
            marked += f"<!--{marker}-->"
    core = _core_payload(marked, marker)
    csp = headers.get("content-security-policy", "")
    csp_note = ""
    if (
        csp
        and _CSP_DIRECTIVE_RE.search(csp)
        and "unsafe-inline" not in csp
    ):
        csp_note = (
            " | CSP: script-src lacks 'unsafe-inline' — inline payload likely blocked"
        )

    needle, style = _locate_anchor(body, marker, marked)
    if needle is None:
        if status >= 400:
            return {
                "payload": marked,
                "confidence": "blocked",
                "evidence": f"HTTP {status} — request rejected before reflection",
            }
        return {
            "payload": marked,
            "confidence": "none",
            "evidence": "payload not reflected"
            + (f" (HTTP {status})" if status else ""),
        }

    chk = MarkerDomCheck(needle)
    chk.feed(body)
    if not chk.executable:
        ev = (
            f"marker stripped but {style} reflected, not in executable position"
            if style != "marker"
            else "marker reflected but not in executable position"
        )
        return {"payload": marked, "confidence": "R", "evidence": ev}

    # 1. JS contexts: marker inside <script> body
    if chk.script_hits:
        needles = [marked, core] if style == "marker" else [needle]
        mk = marker if style == "marker" else None
        for script_text in chk.script_hits:
            for nd in needles:
                live, det = js_verify.payload_live_in_js(script_text, nd, mk)
                if live:
                    ev = chk.evidence + " — " + det
                    return {
                        "payload": marked,
                        "confidence": "V",
                        "evidence": ev + csp_note,
                    }
        return {
            "payload": marked,
            "confidence": "R",
            "evidence": (
                "marker in <script> but no surviving call — "
                "executable core stripped or trapped"
            ),
        }

    # 2. Inline event-handler attributes (`on*=...`)
    if chk.attr_hits:
        intended = js_verify.extract_intended_js(core)
        husk = _EMPTY_COMMENT_HUSK_RE.sub("", intended)
        unesc_intended = html_unescape(intended)
        needles = (
            [intended]
            + ([husk] if husk != intended else [])
            + ([unesc_intended] if unesc_intended != intended else [])
        )
        mk = marker if style == "marker" else None
        for _tag, _attr, val in chk.attr_hits:
            uv = html_unescape(val)
            for nd in needles:
                live, det = js_verify.payload_live_in_js(uv, nd, mk)
                if live:
                    if (
                        det.startswith("sink assignment + throw: onerror")
                        and _tag.lower() != "body"
                        and not _WINDOW_ONERROR_QUAL_RE.search(uv)
                    ):
                        continue
                    return {
                        "payload": marked,
                        "confidence": "V",
                        "evidence": chk.evidence + " — " + det + csp_note,
                    }
        return {
            "payload": marked,
            "confidence": "R",
            "evidence": (
                "marker element has on* handler but injected JS did not survive"
            ),
        }

    # 3. `javascript:` / `data:` URL attributes
    if chk.url_hits:
        intended = js_verify.extract_intended_js(core)
        husk = _EMPTY_COMMENT_HUSK_RE.sub("", intended)
        unesc_intended = html_unescape(intended)
        needles = (
            [intended]
            + ([husk] if husk != intended else [])
            + ([unesc_intended] if unesc_intended != intended else [])
        )
        mk = marker if style == "marker" else None
        for _tag, _attr, val in chk.url_hits:
            uv = html_unescape(val)
            body_js = _SCHEME_PREFIX_STRIP_RE.sub("", uv)
            live = False
            det = ""
            for nd in needles:
                live, det = js_verify.payload_live_in_js(body_js, nd, mk)
                if live:
                    break
            if live:
                return {
                    "payload": marked,
                    "confidence": "V",
                    "evidence": (
                        chk.evidence
                        + " — "
                        + det
                        + " (requires click if href)"
                        + csp_note
                    ),
                }
        return {
            "payload": marked,
            "confidence": "R",
            "evidence": "executable URL attr but injected JS did not survive",
        }

    return {
        "payload": marked,
        "confidence": "V",
        "evidence": chk.evidence + csp_note,
    }


def verify_payload(
    url: str,
    payload: str,
    render: bool = False,
    comment_ok: bool = True,
) -> dict[str, str]:
    """Inject `payload` with a unique `vvm<6-alpha>` marker and grade `V` or `R`."""
    marker = "vvm" + "".join(
        secrets.choice(string.ascii_lowercase) for _ in range(6)
    )
    marked = payload.replace(MARKER_TEMPLATE, marker)
    if "vvm" not in marked:
        marked += f"<!--{marker}-->" if comment_ok else f"/*{marker}*/"
    target = url.replace(PLACEHOLDER, quote(marked, safe=""))

    if render:
        try:
            body, rmeta = fetch_rendered(target)
        except Exception as e:
            return {
                "payload": marked,
                "confidence": "error",
                "evidence": f"render failed: {e}",
            }
        fired = rmeta.get("fired") or []
        sink_hits = [
            n for n, a in rmeta.get("sinks", []) if marker in a
        ]
        if fired:
            return {
                "payload": marked,
                "confidence": "V",
                "evidence": "executed: " + "; ".join(fired[:3]),
            }
        if marker not in body and not sink_hits:
            core = _core_payload(marked, marker)
            if core in body:
                return {
                    "payload": marked,
                    "confidence": "R",
                    "evidence": (
                        "marker stripped but core payload reflected — did not execute"
                    ),
                }
            return {
                "payload": marked,
                "confidence": "none",
                "evidence": "payload not reflected (rendered DOM)",
            }
        chk = MarkerDomCheck(marker, script_inert=True)
        chk.feed(body)
        if chk.executable:
            return {
                "payload": marked,
                "confidence": "R",
                "evidence": chk.evidence + " — position only, did not fire",
            }
        ev = (
            "marker reached sink: " + ", ".join(sorted(set(sink_hits)))
            if sink_hits
            else "marker reflected but not in executable position"
        )
        return {"payload": marked, "confidence": "R", "evidence": ev}

    try:
        status, headers, body = send_verify_request(target, timeout=15)
    except Exception as e:
        return {"payload": marked, "confidence": "error", "evidence": str(e)}
    return classify_response(status, headers, body, payload, marker, marked)


def candidate_tier(cand: dict[str, Any]) -> int:
    """Rank equal-efficiency candidates:
      Tier 0: Direct payloads executing as-is
      Tier 1: Splitter / specific bypass probes matching observed filter behavior
      Tier 2: Blind mutations / obfuscated call forms (case, entity, unicode,
              indirect-call, bracket-access, dynamic jsfuck)
    """
    t = cand["technique"]
    if "splitter" in t or "bypass" in t:
        return 1
    if (
        cand["case_ref"] == "tag_removed"
        or "case-mutated" in t
        or "entity" in t
        or "unicode-escaped" in t
        or "indirect-call" in t
        or "bracket-access" in t
        or "jsfuck" in t
    ):
        return 2
    return 0


def run_verification_waves(
    url: str,
    initial_candidates: list[dict[str, Any]],
    ctx: str,
    quote_ch: str,
    scores: dict[str, int],
    kw: dict[str, bool],
    kwv: dict[str, tuple[str, str]],
    inert: bool,
    esc_q: set[str],
    js_brk: str,
    rid: int,
    max_len: int | None,
    top_n: int,
    render: bool,
    dom_hint: bool,
    letter_stripper: bool = False,
) -> list[dict[str, str]]:
    """Execute adaptive multi-wave verification (`fn_cap = 2 -> 4 -> 8 -> 16`)
    followed by hybrid static-to-Playwright escalation when static verification
    yields only `[R]` or the page has DOM plumbing."""
    seen: set[str] = set()
    verified: list[dict[str, str]] = []
    cap = 2
    wave = list(initial_candidates)
    comment_ok = (
        not letter_stripper
        and usable("<", scores)
        and usable(">", scores)
    )
    workers = 1 if (render or rid == 0 or letter_stripper) else 4

    while wave:
        found = False
        batch: list[str] = []
        for c in wave:
            if c["payload"] not in seen:
                seen.add(c["payload"])
                batch.append(c["payload"])
        if not batch:
            break
        if workers > 1 and len(batch) > 1:
            with ThreadPoolExecutor(
                max_workers=min(workers, len(batch))
            ) as ex:
                b_vers = list(
                    ex.map(
                        lambda p: verify_payload(
                            url, p, render=False, comment_ok=comment_ok
                        ),
                        batch,
                    )
                )
            for v in b_vers:
                verified.append(v)
                if v["confidence"] == "V":
                    found = True
                    if cap > 2:
                        break
        else:
            for p in batch:
                v = verify_payload(
                    url, p, render=render, comment_ok=comment_ok
                )
                verified.append(v)
                if v["confidence"] == "V":
                    found = True
                    if cap > 2:
                        break
        if found or cap >= 16 or letter_stripper:
            break
        cap *= 2
        more = compose(
            ctx,
            quote_ch,
            scores,
            kw,
            kwv,
            inert=inert,
            fn_cap=cap,
            escaped_q=esc_q,
            js_breakout=js_brk,
            deny=(rid == 0),
            letter_stripper=letter_stripper,
        )
        if max_len:
            more_fit = [c for c in more if len(c["payload"]) <= max_len]
            if more_fit:
                more = more_fit
        more.sort(key=lambda c: (-c["efficiency"], candidate_tier(c)))
        wave = [c for c in more if c["payload"] not in seen][:top_n]

    # Hybrid Static -> Render Escalation (C3)
    if not render and not any(v["confidence"] == "V" for v in verified):
        has_r = any(v["confidence"] == "R" for v in verified)
        if has_r or dom_hint:
            for idx, c in enumerate(initial_candidates[:2]):
                rv = verify_payload(
                    url, c["payload"], render=True, comment_ok=comment_ok
                )
                if rv["confidence"] == "V":
                    if idx < len(verified):
                        verified[idx] = rv
                    else:
                        verified.append(rv)
                    break

    return verified
