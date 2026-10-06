# End-to-End Lab Solving Audit

**Audit date:** 2026-10-04  
**Labs exercised:** BOLA/IDOR, BFLA, Reflected XSS  
**Final run:** Fresh copy of the application and seeded SQLite database, opened at `http://127.0.0.1:8011` (XSS opened at `http://localhost:8011` to avoid any session cookie). The final solving run used dashboard links, visible lab controls, progressive hints, and browser-observed responses. It did not use source inspection, database queries, hidden JavaScript calls, or manual status changes to discover or perform the exploits.

## Result Summary

| Lab | Discoverable | Exploitable | Secure comparison works | Completion works | Independently solvable |
|---|---|---|---|---|---|
| BOLA/IDOR | PASS | PASS | PASS | PASS | PASS |
| BFLA | PASS | PASS | PASS | PASS | PASS |
| Reflected XSS | PASS | PASS | PASS | PASS | PASS |

Each PASS is based on a fresh browser solve and observed UI/network results, not on the verifier alone. Invalid scenarios were also tried and rejected.

## Environment and Method

The clean app initialized the documented local test identities: Alice (`alice` / `alice123`, standard user), Bob (`bob` / `bob123`, standard user), and admin (`admin` / `admin123`, administrator). Seed record IDs 1 and 2 were shown as Alice's records; IDs 3 and 4 belong to Bob. No existing workspace DB state was used by this clean run.

The dashboard `/labs` was the entry point for each lab. For BOLA and BFLA, the learner used Alice's visible, prefilled account. XSS was opened on `localhost` without a session cookie and required no login. The browser Network traffic and rendered UI were observed directly. Server completion statuses were confirmed after returning to `/labs`.

## BOLA/IDOR

### Initial State

The dashboard card says to access Bob's records as Alice. The lab introduction explains that authenticated patients use record identifiers and asks whether one patient can retrieve another patient's record. It shows Alice and Bob credentials, a **Start Lab** button, and a progressive **Hint** control. Starting MediVault exposes a login form, Alice's dashboard, **My Records**, a request inspector, an ID lookup field, a secure comparison control, and **Complete Lab**.

### Discovery and Hints

After signing in, **My Records** displayed IDs 1 and 2, both owned by Alice. The inspector showed the collection request `GET /api/records` and its JSON response. The lookup helper says to start with a visible ID and try another. Opening Alice's row shows an object-specific `GET /records/1` path in the inspector, revealing that the numeric path component is the object reference.

Hints progress from examining individual record identifiers and request paths, to comparing requests and ownership, to using **Open a record by ID** and comparing the returned owner/status. The first hint is useful without revealing the full exploit; the final hint unblocks a learner who has not found the lookup field. The visible helper plus the consecutive IDs make Bob's record discoverable without assuming an internal function name.

### Exact Solve and Requests

1. From `/labs`, open BOLA/IDOR, click **Start Lab**, then sign in as Alice. The browser sent `POST /auth/login` with `{"username":"alice","password":"alice123"}` and received HTTP 200. `/auth/me` returned Alice with role `user`.
2. Click **My Records**. The visible table showed `#1 Alice's Medical Record` and `#2 Alice's Financial Report`; the request inspector showed `GET /api/records` returning those two IDs.
3. Enter `2` in **Open a record by ID** and click **Open record**. `GET /records/2` returned HTTP 200 with owner `alice`. Clicking **Complete Lab** produced the visible alert `Completion conditions not met: conditions_not_met`; an own-record read does not satisfy cross-owner evidence.
4. Click **Back**, enter `3`, and click **Open record**. The inspector showed `GET /records/3`, HTTP 200, with `{"id":3,"title":"Bob's Medical Record","content":"Patient notes","owner":"bob"}`. This is the demonstrated BOLA behavior.
5. Click **Compare with secure endpoint**. The browser sent `GET /secure/records/3`, which returned HTTP 404 and `{"detail":"Record not found"}`. The UI showed “Record not found.”
6. Click **Complete Lab**. The browser sent `POST /labs/bola/complete` with `{"labId":"bola","record_id":3}` and received HTTP 200 with `verified:true` and `reason:"passed"`. The lab completion panel appeared. Returning to `/labs` showed BOLA **COMPLETED**.

### Completion and Assessment

The backend requires an authenticated user and a successful `record_access` audit row for that same user and the submitted record ID/path, with a recorded different owner. The UI-supplied ID identifies the evidence to check; it is not proof by itself. A missing ID, Alice-owned ID 2, or no audit event fails. The old write routes no longer produce the read action. The secure route did not create evidence for the vulnerable demonstration.

The initial obstacle was that the table showed only Alice's records and had no ID-edit control; the old guide incorrectly expected a hidden `openRecordDetail()` call. The visible numeric lookup and request-path hint fix this without weakening `/secure/records/{id}`. This final solve required no DevTools console commands.

## BFLA

### Initial State

The lab describes function-level authorization and says a regular user should not access administrative functions. It visibly identifies the preloaded Alice account and role, starts with **Admin Endpoints (Vulnerable)** and **List Users**, and offers endpoint/action selectors, **Send Request**, a side-by-side **Run Comparison**, and progressive hints. Test controls are disabled until login succeeds. Completion guidance no longer lists the answer endpoints in advance.

### Discovery and Hints

The first hint directs the learner to inspect what the request controls allow; the second asks for the same administrative action through both endpoint types and comparison of HTTP status; the third introduces `/admin` versus `/secure/admin` as request paths. The control labels themselves reveal the operation category and whether a comparison is vulnerable or secure, so the route can be investigated without guessing or searching source.

### Exact Solve and Requests

1. Open BFLA from `/labs`. The visible account note identifies Alice (`alice` / `alice123`) as a standard user. Click **Login** and wait for `Logged in as alice (user)`; testing controls then become enabled.
2. First select **Admin Endpoints (Secure)** and leave **List Users** selected. **Send Request** displayed `GET /secure/admin/users` with HTTP 403 and `{"detail":"Administrator privileges required"}`. Clicking **Mark Lab as Complete** showed `Completion not verified: conditions_not_met`.
3. Select **Admin Endpoints (Vulnerable)** and click **Send Request**. The current request pane showed only `GET /admin/users`, HTTP 200, and the synthetic user list including Alice, Bob, and admin.
4. Click **Run Comparison**. The vulnerable panel showed the user list and the secure panel showed the administrator-required 403 response.
5. Click **Mark Lab as Complete**. The browser sent `POST /labs/bfla/complete` with `{"labId":"bfla","evidence":{"action":"admin_access_as_user"}}`; it returned `verified:true`, `reason:"passed"`. The UI reported success and `/labs` showed BFLA **COMPLETED**.

### Completion and Assessment

The verifier requires the caller to still be role `user` and a successful server audit for `/admin/users` or `/admin/debug` with the exact regular-user action. Secure-only requests and admin operations are rejected. An admin’s ordinary access cannot satisfy the learner's role-bypass objective.

Before fixes, the visible completion text gave the exact vulnerable endpoint, and controls could be clicked before login completed. The completion copy now describes the evidence generically, account/role are explicit, controls are disabled until login succeeds, and the single-request panel clears stale output when changing endpoint choice. The regular-user vulnerable-versus-secure flow remains genuine.

## Reflected XSS

### Initial State

The dashboard describes a controlled reflected XSS demonstration. The portal is usable without an account. It shows a payload field prefilled with `<script>parent.postMessage("xss-lab-executed","*")</script>`, an endpoint selector, **Test Payload**, request/response text panels, a rendered iframe, a comparison panel, progressive hints, and **Mark Lab as Complete**.

### Discovery and Hints

The input label says its value is reflected by the `username` parameter. The first hint asks the learner to compare the entered value with the HTTP response; the second names the username query parameter and asks for raw-versus-encoded comparison; the third explains the execution message expected from the isolated frame. This is progressively more specific and matches the UI. The prefilled payload provides a harmless, working starting example while leaving payload experimentation available.

### Exact Solve and Requests

1. Open XSS from `/labs` on `http://localhost:8011`; no login request or session was used.
2. With **Secure Endpoint (/secure/xss)** selected, click **Test Payload**. `GET /secure/xss?username=<encoded-payload>&attempt_id=` returned HTTP 200 with the script HTML-encoded. The execution indicator stayed “Payload execution not observed.” Clicking **Mark Lab as Complete** was blocked with guidance to test the vulnerable endpoint; no completion request was sent.
3. Select **Vulnerable Endpoint (/xss)** and click **Run Comparison**. The browser sent both `GET /xss?username=<encoded-payload>&attempt_id=<uuid>` and `GET /secure/xss?username=<encoded-payload>&attempt_id=<same-uuid>`. Both returned HTTP 200. The vulnerable HTML contained the raw script; the secure HTML contained `&lt;script&gt;...`. The isolated iframe sent `xss-lab-executed`, and the page displayed “Payload execution observed in the isolated frame.”
4. Click **Mark Lab as Complete**. The browser sent `POST /labs/xss/complete` with `{"labId":"xss","evidence":{"payload":"<script>parent.postMessage(\"xss-lab-executed\",\"*\")</script>","attempt_id":"<same-uuid>"}}`. The server returned `verified:true`, `reason:"passed"`; the UI showed success and the dashboard displayed XSS **COMPLETED**.

### Browser Boundary and Completion

An additional harmless probe used `<img src=x onerror="document.body.setAttribute('data-outside-sandbox','yes')">`. Before the fix, that probe set the marker on the top-level lab page: `showResponseInfo()` inserted raw HTTP response text with `innerHTML`, outside the iframe. The UI now appends request and response text using text nodes. Retest showed the literal markup in the response panel and the top-level marker remained absent. The iframe has `sandbox="allow-scripts"` without `allow-same-origin`; the standard payload still executed in the iframe after it settled. A browser Network entry for the deliberately invalid `src=x` probe returned 404; that expected image failure did not execute in the parent page.

The backend permits anonymous XSS completion but requires active markup plus a successful server-side vulnerable-request audit whose exact payload and unique attempt ID match the submitted evidence. Empty/non-executable payloads, secure-only requests, mismatched payloads, mismatched attempt IDs, and no-request evidence fail in tests. The browser UI additionally requires the same payload's execution message before sending completion.

**Residual limitation:** The server cannot independently attest that a browser executed JavaScript. A learner bypassing the UI can make the vulnerable request and directly submit matching evidence. The normal UI proves execution in its sandbox before submitting; this is documented as a local-lab trust boundary, not claimed as server-verifiable browser proof.

## Fixes Applied

- Added the visible BOLA record-ID lookup and progressive hint; the prior guide's hidden-function workflow is no longer needed.
- BOLA completion now matches a successful cross-owner GET audit record to the submitted ID. Update/delete audit events are distinct and cannot impersonate a read.
- BFLA now exposes the preloaded standard-user account, gates request/completion controls until login succeeds, removes endpoint names from initial completion guidance, clears the previous request result on a new send, and verifies successful vulnerable-route evidence for a current regular user.
- XSS now sends the actual payload with a unique attempt ID, renders request/response content as text in the parent page, confines executable markup to the scripts-only sandbox, requires observed same-payload execution in the UI, and verifies the exact server-side vulnerable request without requiring login.
- The public status endpoint accepts only `in_progress`; direct attempts to set `completed` return HTTP 400. Successful verification alone marks a lab complete.

## Automated and Browser Results

- Maintained pytest modules run in a disposable project copy: **46 passed**, one Starlette/httpx deprecation warning.
- Final clean browser solve on a fresh app/database: all three labs passed. BOLA: own-record completion rejected, Bob ID 3 returned 200, secure version returned 404, completion and dashboard passed. BFLA: secure-only access returned 403 and completion failed; vulnerable `/admin/users` returned 200, comparison showed 200/403, completion and dashboard passed. XSS: secure-only did not execute and was blocked; vulnerable payload executed in the sandbox, secure comparison encoded it, completion and dashboard passed anonymously.
- Parent-page injection retest: response markup stayed text, parent marker stayed absent, and the intended payload still executed in the isolated frame. No page exceptions or iframe sandbox warnings were observed in the final run.
- Obsolete fixed-port network probes and print-only diagnostics were retired. The unique legacy `xss_browser_test.py` Selenium script was retained but not run because it requires Chrome/ChromeDriver and an unused port 8000; the integrated browser performed the final learner workflows.

## Remaining Limitations

- Dashboard status is global in memory and resets on server restart; SQLite audit evidence persists.
- A historical successful BOLA GET by the same account for the same record ID remains eligible; it is not tied to the current lab start.
- BFLA verification accepts a matching successful vulnerable-route audit event already stored for that regular-user account; it is not tied to a specific page visit.
- XSS server verification proves a matching vulnerable request and payload/attempt pair, not browser execution itself; execution is locally observed by the lab UI.
- Existing database initialization is idempotent rather than a reset. Non-default IDs or prior audit events can affect later attempts; do not clear records or logs to force completion.