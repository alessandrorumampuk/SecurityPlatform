"""
Indexed boundary token generation, probe string assembly, and reflection
extraction helpers.
"""
from __future__ import annotations

import json
import re
import secrets
import string
import urllib.parse
from typing import Sequence

from .constants import (
    CHARACTERS,
    KEYWORDS,
    MARKER_END,
    MARKER_START,
    SEPARATOR,
)

_COMMENT_STRIP_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_META_COMMENT_RE = re.compile(r"<!--\s*(\w+):\s*(.*?)\s*-->", re.DOTALL)
_MARKER_SPAN_RE = re.compile(
    re.escape(MARKER_START) + r"(.*?)" + re.escape(MARKER_END), re.DOTALL
)


def random_tag_name() -> str:
    """Generate a 3-letter random tag name for the generic tag-stripper probe."""
    return "".join(secrets.choice(string.ascii_letters) for _ in range(3))


def keyword_items() -> list[tuple[str, str]]:
    """Build the Layer B/C keyword probe item list: `KEYWORDS` plus one random
    junk tag (`rand_tag`, e.g. `<xDh>`) and 10 `gen_*` generic-shape control
    probes using a benign random identifier.

    Ordering invariants:
      1. `rand_tag` is inserted BEFORE the first `<`-bearing item so forward-
         matching regexes (`/<script[^>]*>/`) cannot swallow it.
      2. All `gen_*` probes carrying `>` precede the first unclosed `</` item.
    """
    items = list(KEYWORDS)
    idx = next((i for i, (_, v) in enumerate(items) if "<" in v), len(items))
    items.insert(idx, ("rand_tag", f"<{random_tag_name()}>"))
    ident = random_tag_name()
    gen: list[tuple[str, str]] = [
        ("gen_call", f"{ident}()"),
        ("gen_tick", f"{ident}`1`"),
        ("gen_script", f"<script>{ident}()</script>"),
        ("gen_handler", f"<svg onload={ident}()>"),
        ("gen_h_error", f"<img onerror={ident}()>"),
        ("gen_jsurl", f"javascript:{ident}()"),
        ("gen_break_squote", f"'-{ident}()-'"),
        ("gen_break_dquote", f'"-{ident}()-"'),
        ("gen_bracket", "self['a'+'b']()"),
        ("gen_u6brace", "\\u{62}"),
    ]
    ci = next((n for n, (_, v) in enumerate(items) if v.startswith("</")), len(items))
    items[ci:ci] = gen
    return items


def make_boundaries(items: Sequence[tuple[str, str]]) -> list[str]:
    """Generate `len(items) + 1` indexed boundary tokens (`4 random letters +
    2-digit index`) guaranteed not to collide with any probe item or marker."""
    vals = [v for _, v in items] + [MARKER_START, MARKER_END]
    seps: list[str] = []
    for i in range(len(items) + 1):
        while True:
            b = (
                "".join(secrets.choice(string.ascii_letters) for _ in range(4))
                + f"{i:02d}"
            )
            if all(b not in v for v in vals):
                break
        seps.append(b)
    return seps


def build_probe_string(items: Sequence[tuple[str, str]]) -> tuple[str, list[str]]:
    """Construct `testing1{sep0}{item0}{sep1}...{sepN}testing2` and return
    `(probe_str, seps)`."""
    seps = make_boundaries(items)
    probe_str = (
        MARKER_START
        + "".join(seps[i] + v for i, (_, v) in enumerate(items))
        + seps[-1]
        + MARKER_END
    )
    return probe_str, seps


def extract_indexed_items(
    reflected: str, seps: Sequence[str], count: int
) -> list[str | None]:
    """Extract `count` items bounded by `seps[i]` and `seps[i + 1]`.
    Returns `None` for any item whose left or right boundary was lost or
    inverted."""
    bpos = [reflected.find(b) for b in seps]
    parts: list[str | None] = []
    for i in range(count):
        if bpos[i] < 0 or bpos[i + 1] < 0:
            parts.append(None)
            continue
        lo = bpos[i] + len(seps[i])
        hi = bpos[i + 1]
        parts.append(reflected[lo:hi] if hi >= lo else None)
    return parts


def split_by_separator(
    reflected: str, expected_count: int | None = None
) -> list[str] | None:
    """Legacy extractor for logs written before indexed boundaries existed."""
    parts = reflected.split(SEPARATOR)
    if len(parts) != (expected_count or len(CHARACTERS)):
        return None
    return parts


def parse_html_meta(content: str) -> dict[str, str]:
    """Extract leading `<!-- key: value -->` metadata comments from a saved
    probe HTML log. Multiline-safe so the `newline` probe item inside
    `input_sent` does not break extraction."""
    meta: dict[str, str] = {}
    # Only scan the metadata header prefix (up to first 4096 chars)
    header_slice = content[:4096]
    for m in _META_COMMENT_RE.finditer(header_slice):
        key = m.group(1)
        if key not in meta:
            meta[key] = m.group(2)
    return meta


def strip_html_comments(content: str) -> str:
    """Remove all `<!-- ... -->` HTML comments from `content`."""
    return _COMMENT_STRIP_RE.sub("", content)


def items_from_meta(meta: dict[str, str], kind: str) -> list[tuple[str, str]]:
    """Recover the exact `(name, value)` probe items from `items_json` in
    log metadata, falling back to static lists for older logs."""
    raw = meta.get("items_json")
    if raw:
        try:
            return [(str(n), str(v)) for n, v in json.loads(raw)]
        except (ValueError, TypeError):
            pass
    if kind == "keywords":
        return list(KEYWORDS)
    return list(CHARACTERS)


def extract_reflected_all(
    response: str,
) -> tuple[list[str], list[dict[str, int]]]:
    """Find all `testing1...testing2` reflections in `response`, with a 4-pass
    URL-unquote fallback for middleboxes/sinks that URL-encode reflections."""
    matches = list(_MARKER_SPAN_RE.finditer(response))
    if not matches and (
        MARKER_START in response
        or "%74esting1" in response.lower()
        or MARKER_START in urllib.parse.unquote(response)
    ):
        dec = response
        for _ in range(4):
            nxt = urllib.parse.unquote(dec)
            if nxt == dec:
                break
            dec = nxt
            matches = list(_MARKER_SPAN_RE.finditer(dec))
            if matches:
                break
    reflected = [m.group(1) for m in matches]
    positions = [
        {"index": i + 1, "start": m.start(), "end": m.end()}
        for i, m in enumerate(matches)
    ]
    return reflected, positions
