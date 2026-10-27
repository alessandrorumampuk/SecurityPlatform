"""
Dynamic, deterministic JSFuck compiler for non-alphanumeric XSS synthesis.

Instead of relying on a static pre-encoded payload string, this module compiles
arbitrary JavaScript expressions on-the-fly from atomic JavaScript primitives
(`![]`, `!![]`, `[][[]]`, `+[![]]`, `[]["at"]`, and base-36 `Number.toString`).

Supports three execution modes matching jsfuck.com:
  1. `eval_source=False`                   -> String expression only (`"alert(1)"`),
                                              used for string-eval sinks (`eval(...)`).
  2. `eval_source=True, parent_scope=False`-> `[]["at"]["constructor"]("alert(1)")()`,
                                              executes via `Function` constructor.
  3. `eval_source=True, parent_scope=True` -> `[]["at"]["constructor"]("return eval")()("alert(1)")`,
                                              executes via `eval` in parent scope.

Also supports `compact=True` for letter-stripping filters (`/[a-zA-Z]/`) that
allow digits `0-9` (detected via `NUMERIC_PROBE_MARKER`), shrinking payload
length by ~45% while remaining 100% letter-free.
"""
from __future__ import annotations

from functools import lru_cache


def encode_digit(d: int, compact: bool = False) -> str:
    """Encode a single digit `0..9` into JSFuck (`+[]`, `+!+[]`, `!+[]+!+[]`, ...)
    or a raw digit when `compact=True`."""
    if compact:
        return str(d)
    if d == 0:
        return "+[]"
    if d == 1:
        return "+!+[]"
    return "!+[]" + "+!+[]" * (d - 1)


def encode_index(n: int, compact: bool = False) -> str:
    """Encode a non-negative integer `n` for bracket indexing `[index]`."""
    if compact:
        return str(n)
    if n < 10:
        return encode_digit(n, False)
    digits = [int(ch) for ch in str(n)]
    first = encode_digit(digits[0], False)
    rest = "".join(f"[{encode_digit(d, False)}]" for d in digits[1:])
    return f"{first}+{rest}"


def encode_number(n: int, compact: bool = False) -> str:
    """Encode a non-negative integer `n` as a coerced JavaScript `Number`."""
    if compact:
        return f"({n})"
    if n < 10:
        return f"({encode_digit(n, False)})"
    return f"(+({encode_index(n, False)}))"


@lru_cache(maxsize=4)
def _build_char_table(compact: bool = False) -> tuple[dict[str, str], str, str]:
    """Derive the character dictionary, `[]["at"]` expression, and
    `"constructor"` expression purely from runtime JS string layout."""
    table: dict[str, str] = {}

    def idx(expr: str, pos: int) -> str:
        return f"({expr})[{encode_index(pos, compact)}]"

    # Stage 1: Primitive boolean / undefined / NaN string coercions
    primitives = (
        ("![]+[]", "false"),
        ("!![]+[]", "true"),
        ("[][[]]+[]", "undefined"),
        ("+[![]]+[]", "NaN"),
    )
    for expr, val in primitives:
        for pos, ch in enumerate(val):
            if ch not in table:
                table[ch] = idx(expr, pos)

    # Stage 2: Derive `[]["at"]` ("function at() { [native code] }")
    at_key = f"{table['a']}+{table['t']}"
    at_fn = f"[][{at_key}]"
    at_str_expr = f"{at_fn}+[]"
    # Canonical V8/SpiderMonkey/JSC layout of `Function.prototype.toString` for `at`:
    # "function at() { [native code] }"
    #  0123456789012
    for pos, ch in (
        (3, "c"),
        (8, " "),
        (11, "("),
        (12, ")"),
    ):
        if ch not in table:
            table[ch] = idx(at_str_expr, pos)

    # "truefunction at()..." puts 'o' at index 10
    table["o"] = f"(!![]+{at_fn})[{encode_index(10, compact)}]"

    # Stage 3: Assemble `"constructor"` and `"toString"`
    ctor_expr = "+".join(table[ch] for ch in "constructor")

    # Derive capital 'S' from `([]+[])["constructor"]+[]` -> "function String()..." (index 9)
    str_ctor_str = f"([]+[])[{ctor_expr}]+[]"
    table["S"] = idx(str_ctor_str, 9)
    table["g"] = idx(str_ctor_str, 14)

    to_string_expr = "+".join(table[ch] for ch in "toString")

    # Stage 4: Digits '0'..'9'
    for d in range(10):
        table[str(d)] = f"[{encode_digit(d, compact)}]"

    # Stage 5: Any remaining lowercase 'a'..'z' via `(val)["toString"](radix)`
    for codepoint in range(ord("a"), ord("z") + 1):
        ch = chr(codepoint)
        if ch not in table:
            val = codepoint - 87  # 'a' -> 10 .. 'z' -> 35
            radix = val + 1
            num_expr = encode_number(val, compact)
            rad_expr = encode_index(radix, compact)
            table[ch] = f"{num_expr}[{to_string_expr}]({rad_expr})"

    return table, at_fn, ctor_expr


def jsfuck_encode(
    code: str,
    eval_source: bool = True,
    parent_scope: bool = False,
    compact: bool = False,
) -> str:
    """Dynamically compile `code` into a non-alphanumeric JSFuck expression.

    Args:
        code: JavaScript source string to encode (e.g. `"alert(1)"`).
        eval_source: Wrap in `[]["at"]["constructor"](...)()` so it executes.
        parent_scope: Execute via `Function("return eval")()(code)` (Form #3).
        compact: Allow raw digits `0-9` for indices when only letters are stripped.
    """
    if not code:
        return "[]+[]"
    table, at_fn, ctor_expr = _build_char_table(compact=compact)
    parts: list[str] = []
    for ch in code:
        if ch in table:
            parts.append(table[ch])
        else:
            # Universal fallback via `String.fromCharCode(cp)` constructed dynamically
            cp = ord(ch)
            from_char_code = jsfuck_encode(
                "return String.fromCharCode",
                eval_source=True,
                parent_scope=False,
                compact=compact,
            )
            parts.append(f"({from_char_code}({encode_index(cp, compact)}))+[]")

    body_expr = "+".join(parts)
    if len(parts) == 1 and parts[0].startswith("["):
        body_expr = "[]+" + body_expr

    if not eval_source:
        return body_expr

    if parent_scope:
        ret_eval = jsfuck_encode(
            "return eval",
            eval_source=False,
            parent_scope=False,
            compact=compact,
        )
        return f"{at_fn}[{ctor_expr}]({ret_eval})()({body_expr})"

    return f"{at_fn}[{ctor_expr}]({body_expr})()"
