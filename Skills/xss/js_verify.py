#!/usr/bin/env python3
"""
js_verify.py — "did the reflected payload produce live JavaScript?"

Facade module re-exporting the dependency-free JS span lexer and call-survival
verifier from `core.js_lexer`.
"""
from __future__ import annotations

from core.js_lexer import (
    _HTML_ASSIGN_SINKS,
    _IDENT_RE,
    _KW,
    _NAV_ASSIGN_SINKS,
    _SINK_PROPS,
    _hits_in_range,
    _lex,
    _sink_assigns_in_range,
    _skip_balanced,
    _skip_comment,
    _skip_regex,
    _skip_string,
    _skip_template,
    _strictly_inside,
    extract_intended_js,
    lex_js,
    payload_hits_call,
    payload_live_in_js,
    script_blocks,
    script_tag_executable,
)

__all__ = [
    "_HTML_ASSIGN_SINKS",
    "_IDENT_RE",
    "_KW",
    "_NAV_ASSIGN_SINKS",
    "_SINK_PROPS",
    "_hits_in_range",
    "_lex",
    "_sink_assigns_in_range",
    "_skip_balanced",
    "_skip_comment",
    "_skip_regex",
    "_skip_string",
    "_skip_template",
    "_strictly_inside",
    "extract_intended_js",
    "lex_js",
    "payload_hits_call",
    "payload_live_in_js",
    "script_blocks",
    "script_tag_executable",
]
