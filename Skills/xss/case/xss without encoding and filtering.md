1. XSS without Encoding and Filtering
- Payload: <script>alert(1)</script>
- Condition: No encoding or filtering applied to user input
- Case: Input is reflected directly into HTML without any sanitization
- Output: <script>alert(1)</script>
