"""
Type definitions and zero-overhead data structures for the XSS pipeline.

Uses `TypedDict` for JSON-serialized dictionaries (zero runtime instantiation
or serialization overhead) and `@dataclass(slots=True)` for per-reflection
composition state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TypedDict


class SurfaceTarget(TypedDict):
    type: str
    template: str
    param: str


class PostForm(TypedDict):
    action: str
    fields: list[str]


class DomExtras(TypedDict):
    postmessage: bool
    sinks: list[str]


class ReflectionPosition(TypedDict, total=False):
    index: int
    start: int
    end: int
    sink: str


class ReflectionItemResult(TypedDict, total=False):
    reflection_index: int
    position: int
    character_index: int
    character_name: str
    character: str
    expected: str
    got_back: str | None
    passed: bool | None
    needs_bypass: bool | None
    verdict: str
    contexts: list[str]
    quote: str | None
    js_breakout: str


class PayloadCandidate(TypedDict):
    payload: str
    technique: str
    case_ref: str
    efficiency: int


class VerificationResult(TypedDict):
    payload: str
    confidence: str
    evidence: str


class LexSpans(TypedDict):
    strings: list[tuple[int, int]]
    calls: list[tuple[int, int]]
    assigns: list[tuple[int, int]]
    throws: list[tuple[int, int]]
    sink_assigns: list[tuple[int, int]]


@dataclass(slots=True)
class ComposeState:
    """Pre-computed grammar state for a single reflection point.

    Instantiated once per `compose()` invocation so individual context
    strategy functions share pre-filtered function lists, splitters, and
    capability flags without recreating nested closures.
    """

    ctx: str
    quote: str
    scores: dict[str, int]
    kw: dict[str, bool]
    kwv: dict[str, tuple[str, str]]
    inert: bool = False
    fn_cap: int = 2
    escaped_q: set[str] = field(default_factory=set)
    js_breakout: str = ""
    deny: bool = False
    letter_stripper: bool = False
    marker: str = "vvm{id}"

    # Derived state populated during initialization
    rsplit: list[str] = field(default_factory=list)
    hfuncs: list[str] = field(default_factory=list)
    jfuncs: list[str] = field(default_factory=list)
    tags_ok: bool = False
    slash_ok: bool = False
    space_ok: bool = False
    q_ok: bool = False
    script_ok: bool = False
    out: list[dict[str, Any]] = field(default_factory=list)
