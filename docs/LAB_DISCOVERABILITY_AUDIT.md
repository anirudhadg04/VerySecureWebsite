# Lab Discoverability Audit

**Reviewed:** 2026-10-04  
**Labs present:** BOLA/IDOR, BFLA, Reflected XSS

## Summary

The project contains three lab portals. BFLA exposed request and response controls, but its completion text named the solution endpoints before discovery, testing controls were active before login finished, and response output accumulated across endpoint changes. BOLA had a real vulnerable GET route and a request inspector, but Alice's table hid Bob's records and there was no visible way to vary an observed ID; its previous guide required an undocumented JavaScript function. XSS had a payload form and vulnerable/secure comparison, but the form initially sent the username rather than the payload, completion accepted unrelated historical requests, the page required an invisible authenticated session, and its iframe sandbox combined `allow-scripts` with `allow-same-origin`. A hands-on probe also confirmed raw response markup executed in the top-level response panel outside the sandbox.

Each lab now has a discoverable UI path. Vulnerable endpoints remain vulnerable, secure endpoints retain their access-control or output-encoding behavior, and completion requires server-side evidence tied to the requested resource, role, or payload. The public status route also previously accepted `completed` directly; it now accepts only progress updates, leaving completion status to the verifier.

## Lab Matrix

| Lab | Intended vulnerability | Discovery method | Exploitation method | Hidden knowledge required? | Issues found and changes |
|---|---|---|---|---|---|
| BOLA/IDOR (`bola`) | `GET /records/{id}` returns a record without checking ownership; `/secure/records/{id}` enforces ownership. | Open one of Alice's visible rows, inspect its `GET /records/{id}` in Request Inspector, then use the visible **Open a record by ID** control to vary the object reference. | As Alice, request a Bob-owned ID and compare the record owner and response with the secure endpoint. | No. The ID field and inspector are visible; progressive hints point to changing the object ID. | Previously required `openRecordDetail(id)` from DevTools and the table hid Bob's rows. Added visible request control; completion now matches the submitted ID to a successful cross-owner GET, not a write audit event. |
| BFLA (`bfla`) | `/admin/users` and `/admin/debug` omit role checks; `/secure/admin/*` requires an administrator. | Sign in with the visibly documented preloaded standard account, then use endpoint/action selectors, request/response panels, and **Run Comparison**. Progressive hints guide status-code comparison. | As Alice, inspect a privileged response from the vulnerable selector and compare it with the same action through the secure selector. | No. Account, roles, controls, and paths are visible or progressively hinted. | Removed solution endpoint names from initial completion copy, documented the default account/role, disabled API/completion controls until login succeeds, cleared stale single-request output, and tightened verifier role/path/success checks. |
| Reflected XSS (`xss`) | `/xss?username=...` reflects raw markup; `/secure/xss` HTML-encodes it. | Enter the prefilled controlled payload in the visible form; inspect the text-only response and compare both endpoint choices. Progressive hints explain reflection and the isolated-frame execution signal. | Submit the payload to the vulnerable route and observe execution only in the scripts-only sandbox; compare with the encoded secure response. | No. The payload input, endpoint selector, response view, execution state, and hints are visible. No login is required. | The payload was not sent at first, completion accepted unrelated old logs, and the page's response panel executed reflected markup outside its iframe. Fixed request construction, attempt/payload correlation, anonymous verification, text-only response rendering, execution feedback, and sandbox flags. |

## Prerequisites

Start from the repository root:

```powershell
python -m uvicorn app.main:app --reload
```

The default address is `http://127.0.0.1:8000`. The default synthetic credentials are `alice` / `alice123` (role `user`), `bob` / `bob123` (role `user`), and `admin` / `admin123` (role `admin`). They are initialized in `app/init_db.py`.

The default SQLite file is `verysecurewebsite.db` relative to the process working directory. Initialization creates tables and seed users/records only when the users table is empty. If any user exists, it returns without resetting or repairing users, records, or audit history. Restarting the app is not a reset. The seeded record IDs are Alice 1 and 2, Bob 3 and 4; always use the IDs and ownership shown by the current application responses when data has changed.

Use a modern browser with JavaScript and cookies enabled. Browser DevTools Network, Console, Elements, and Sources panels are useful for observing requests, responses, reflection, and client behavior. The in-app controls are sufficient for the guided flows. Burp Suite or another HTTP client can be used to inspect and replay the observed requests, but no lab requires guessing an endpoint or invoking a page-global JavaScript function.

## Learner Flows

### BOLA/IDOR

1. From `/labs`, open **BOLA/IDOR - Object Level Authorization**, click **Start Lab**, and sign in as Alice.
2. Click **My Records** and open one of Alice's rows. Note its numeric ID and observe `GET /records/{id}` in Request Inspector.
3. In **Open a record by ID**, enter another candidate ID. The clean seed uses IDs 3 and 4 for Bob. Click **Open record** and inspect the response. A Bob owner and HTTP 200 from the vulnerable route demonstrate the flaw; a missing ID returns 404.
4. Click **Compare with secure endpoint**. Bob's record returns 404 from `/secure/records/{id}`; Alice's own record remains available.
5. With the Bob-owned record open, click **Complete Lab**. Expect `verified:true`, the completion panel, and **Completed** on the dashboard.

### BFLA

1. From `/labs`, open the BFLA lab. The username and password fields show the seeded Alice account; sign in as Alice.
2. Leave **Admin Endpoints (Vulnerable)** and **List Users** selected, then click **Send Request**. Inspect the request path and the user list response.
3. Click **Run Comparison**. The vulnerable request returns 200; the secure request returns 403 with an administrator-required response.
4. Reveal hints as needed, then click **Mark Lab as Complete**. Expect the completion message and **Completed** on the dashboard.
5. As a negative check, sign in as admin and use only the secure endpoint. A successful admin operation is not evidence that a regular user bypassed authorization; completion must remain unverified.

### Reflected XSS

1. From `/labs`, open the Reflected XSS lab. No account is required.
2. The payload field is prefilled with `<script>parent.postMessage("xss-lab-executed","*")</script>`. Click **Test Payload** with **Vulnerable Endpoint (/xss)** selected.
3. Inspect the displayed request path and response. The payload is in the `username` query parameter, appears as raw markup in the response, and should produce **Payload execution observed in the isolated frame**.
4. Click **Run Comparison**. The vulnerable response contains raw script markup and executes in the scripts-only sandbox; the secure response contains escaped markup and does not send the execution signal.
5. Click **Mark Lab as Complete** after the execution signal. Expect successful verification and **Completed** on the dashboard. Selecting only the secure endpoint does not produce execution and the UI blocks completion.

## Completion Verification

All completion routes are `POST /labs/{lab_id}/complete`. A passed result writes `lab_completion:{lab_id}` and sets that lab's in-memory status to `completed`; the dashboard reads `/labs/{lab_id}/status`. The separate public status POST accepts only `in_progress`; callers cannot set `completed` or reset a lab. A failed JSON result is HTTP 200 with `verified:false` and a reason; failed results do not mark status completed.

| Lab | Evidence accepted by the backend | Rejected cases |
|---|---|---|
| BOLA | Authenticated caller; top-level `record_id` (the current UI shape) or nested `evidence.record_id`; matching successful `record_access` audit row by the same user and same `/records/{id}` path; recorded owner differs from caller. Legacy rows with no recorded owner use a current DB ownership lookup. | No matching audit row; own record; missing, malformed, or different ID; failed audit event; PUT/DELETE-only access. |
| BFLA | Authenticated caller whose current role is `user`; successful audit event with action `admin_access:role=user` and path `/admin/users` or `/admin/debug`. | Admin caller; secure endpoint only; no matching vulnerable-route audit event; unrelated path or role. |
| XSS | Authentication is not required. Evidence must include an active-markup payload and attempt ID that exactly match a successful `xss_vulnerable_attempt` request recorded by the server. The UI additionally requires an execution message from the vulnerable sandbox for the same payload before sending completion. | Empty/non-executable evidence; secure-route-only request; payload mismatch; missing or different attempt ID; no server-side vulnerable request. |

The frontend does not decide completion by itself. In BOLA and BFLA, a visible result is not enough unless the corresponding audit row matches the authenticated user and evidence. In XSS, a client-supplied payload is not sufficient unless it matches an actual vulnerable-endpoint request and unique attempt ID.

## Changes and Rationale

- `app/templates/bola_lab.html`: added the visible numeric ID replay control, keeping the API request inspector and existing secure comparison.
- `app/main.py`: separated BOLA GET audit events from update/delete events; bound BOLA verification to a successful matching read and record ID; scoped BFLA verification to a current regular user and successful vulnerable route; correlated XSS completion with exact payload and attempt ID; allowed anonymous XSS completion to match its no-login portal; marked verified labs completed in server status; prevented clients from directly setting completion status.
- `app/templates/bfla_lab.html`: added three progressive hints, explicitly identified the preloaded standard account, gated controls until successful login, removed initial endpoint giveaways, and cleared previous single-request output on each send.
- `app/templates/xss_lab.html`: sends the actual payload, adds progressive hints and execution state, requires execution before its completion request, renders request/response values with text nodes, avoids duplicate form submissions, and removes `allow-same-origin` from script sandboxes.
- `test_bola_bfla.py`: updated the existing XSS completion cases to use actual payload/attempt evidence and no login.
- `tests/test_bola_completion_verifier.py`: covers matching IDs, invalid/fabricated evidence, read-vs-write evidence, secure denial, and BOLA status.
- `tests/test_lab_verification.py`: covers BFLA role/route evidence, XSS payload/attempt correlation, anonymous success, invalid/secure-only cases, direct status rejection, and text-only XSS response rendering/sandbox flags.
- `docs/LAB_COMPLETION_TEST_GUIDE.md`: replaces the undocumented console workaround with the visible BOLA lookup flow and reflects current verifier behavior.

## Limitations and Known Issues

- Lab status is held in memory and resets when the server process restarts; audit rows persist in SQLite. Dashboard status is not a durable completion record.
- A prior successful BOLA GET for the same user and record ID remains eligible; BOLA does not currently require the GET to occur after the current lab start. The submitted record ID must still match that event.
- BFLA accepts any matching successful event already recorded for that same regular-user account; it is not tied to a particular page visit.
- XSS completion correlates a real vulnerable request, active-markup signature, payload, and attempt ID. The backend cannot independently attest that a browser executed JavaScript; the lab UI observes execution in the sandbox before it submits. A learner bypassing that UI could call HTTP endpoints directly, which remains a limitation of browser-based proof in this local training app.
- Existing databases may have legacy audit rows or non-default IDs. Do not delete records or clear audit history as a completion workaround. Use the visible request inspector and response to find valid current IDs.
- `init_db()` does not reset existing data. Back up the database before any manual maintenance.

## Validation Results

- Maintained pytest modules in a disposable copy: **46 passed**, with one Starlette/httpx deprecation warning.
- The XSS parent-page injection probe was rerun after the renderer fix: the reflected payload appeared as text, the parent marker remained absent, and the default payload still executed within the sandbox. No page errors or iframe sandbox warnings were observed in the final browser run.
- Browser E2E on a clean copy of the final source: all three labs completed through the dashboard and visible UI controls. BOLA returned Bob's data from the vulnerable GET, 404 from the secure GET, and completed. BFLA returned 200 for Alice on the vulnerable endpoint and 403 on the secure endpoint, then completed. XSS was completed anonymously after the payload executed in the sandbox; the secure response was encoded and secure-only testing was blocked from completion.
- Dashboard status displayed **COMPLETED** for BOLA, BFLA, and XSS after successful verification.
- A direct `POST /labs/xss/status` with `{"status":"completed"}` returned HTTP 400 and did not alter status. The regression suite also rejects fabricated/mismatched BOLA and XSS evidence, BFLA completion by admin, XSS secure-only evidence, and BOLA write-only evidence.
- No page errors or iframe sandbox warnings were observed in the final browser run. Expected HTTP failures were observed for the secure BOLA comparison (404), secure BFLA comparison (403), and rejected direct status update (400).
- Obsolete fixed-port and print-only probes were retired. The unique legacy `xss_browser_test.py` Selenium script was retained but not included in pytest because it needs Chrome/ChromeDriver and an unused port 8000; the integrated browser exercised the current end-to-end flow.