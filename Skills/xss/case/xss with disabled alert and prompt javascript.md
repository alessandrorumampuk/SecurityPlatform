1. XSS with Disabled Alert and Prompt
- Payload: <script>confirm(1)</script>
- Condition: alert() and prompt() functions are blocked or overridden
- Case: alert and prompt are disabled but confirm and other dialog functions remain available
- Output: <script>confirm(1)</script>
