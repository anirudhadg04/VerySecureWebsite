# BOLA Lab Completion Test Guide

This guide follows the current BOLA lab implementation in `app/templates/bola_lab.html`, `app/main.py`, `app/init_db.py`, and `app/config.py`. It distinguishes the vulnerability demonstration from the separate server-side completion check.

## 1. Lab Overview

- **Lab ID:** `bola`
- **Lab name:** BOLA / IDOR - Object Level Authorization
- **Objective:** While authenticated as Alice, retrieve a record owned by Bob by requesting its ID from the vulnerable record endpoint.
- **Intended vulnerability:** `GET /records/{record_id}` returns an existing record without checking that the authenticated user owns it.
- **Secure comparison:** `GET /secure/records/{record_id}` restricts its query to the authenticated user's records. A foreign or missing record returns HTTP 404 with `{"detail":"Record not found"}`; it does not return 403.
- **Expected outcome:** Alice sees the contents and owner of Bob's record from `/records/{id}`. The completion endpoint accepts a matching server-side cross-owner `record_access` audit event for Alice.
- **Required learner account and role:** Use the seeded `alice` account with role `user`. The current verifier requires authentication but does not itself require the username `alice` or role `user`; Alice is required for the stated learning objective.
- **Seeded credentials:** `alice` / `alice123`. Other seeded accounts are `bob` / `bob123` (role `user`) and `admin` / `admin123` (role `admin`). These values are set by `app/init_db.py`; the login panel in the current template displays Alice's credentials.

The BOLA lab is selected from `/labs` and opens at `/bola_lab.html`. The frontend uses `/api/records` to populate “My Records”; that API returns only the current user's records. The visible **Open a record by ID** control lets learners replay the observed request with a changed object ID; the request inspector displays the path and response.

## 2. Prerequisites

1. Open a terminal in the repository root and start the app with `python -m uvicorn app.main:app --reload`. The default address is `http://127.0.0.1:8000`; use the host and port printed by Uvicorn if they differ. The source default is port 8000.
2. The app creates tables on import and calls `init_db()`. Initialization creates the seed users and four records only when the `users` table is empty. If even one user already exists, it returns without reseeding, cleaning, or repairing users, records, or audit history. Restarting the app does not reset data. The small schema migration may add `record_owner_id` to an older audit table.
3. By default, SQLite is `verysecurewebsite.db` in the process working directory. Start the app from the repository root to use the workspace database. Confirm that Alice, Bob, and their records exist before testing. The default seed assigns Alice records 1 and 2, and Bob records 3 and 4, but existing data can change these IDs.
4. To find current record IDs and owners, inspect the database without changing it. For example, from the repository root run:

   ```sql
   SELECT records.id, records.title, users.username AS owner
   FROM records JOIN users ON records.owner_id = users.id
   ORDER BY records.id;
   ```

   Run that query in a SQLite client against `verysecurewebsite.db`. Use an existing record whose owner is Bob; do not assume its ID is 3 if the database has been used before.
5. Use a modern browser with JavaScript, cookies, and developer tools enabled. Open the lab on the same origin as the running app. The session cookie is HTTP-only, so JavaScript cannot read it; same-origin `fetch` calls with credentials include it automatically.
6. Start the BOLA lab and sign in as Alice. For a clean run, log out of other accounts in this browser first. Old audit events do not need to be cleared to make a valid run, but they can make a later completion attempt pass without a new demonstration; use a fresh database only if you want to isolate history, and back up data before any manual reset.

## 3. Exact Steps to Complete the Lab

1. **Open the lab.** Navigate to `http://127.0.0.1:8000/labs`, select the BOLA/IDOR lab, or navigate directly to `/bola_lab.html`. The page title is “BOLA / IDOR Lab.” This selects lab ID `bola` and loads the MediVault simulation.
2. **Start the lab.** Click **Start Lab**. The introduction hides, MediVault appears, and the page sends `POST /labs/bola/status` with `{"status":"in_progress"}`. This sets in-memory lab status only; it is not BOLA completion evidence and is lost when the server restarts.
3. **Sign in as Alice.** In MediVault, enter `alice` and `alice123`, then click **Sign in**. The page sends `POST /auth/login` with JSON `{"username":"alice","password":"alice123"}`. Expect HTTP 200 and a `session_id` cookie. The frontend then calls `/auth/me` and displays Alice's dashboard.
4. **Inspect an object reference.** Click **My Records** and open one of Alice's rows. Note its numeric ID and the `GET /records/<id>` path in the request inspector. The default seed uses consecutive IDs, with Alice's records 1 and 2 and Bob's records 3 and 4.
5. **Test another object ID.** Return to **My Records**, enter a nearby ID in **Open a record by ID**, and click **Open record**. If the response is 404, try another existing ID; when the response shows `"owner":"bob"`, you have demonstrated cross-user access. Confirm that the request inspector shows `GET /records/<BOB_RECORD_ID>` returning 200 and the Bob-owned record. No console command or database edit is required.
6. **Record the backend evidence.** The successful vulnerable GET should create an `audit_logs` row with Alice's `user_id`, `action='record_access'`, `path='/records/<BOB_RECORD_ID>'`, `success=1`, and `record_owner_id` equal to Bob's user ID. The handler commits the row before returning the record. If the record does not exist, it returns 404 before creating this audit event.
7. **Optionally compare the secure route.** In record detail, click **Compare with secure endpoint**. This sends `GET /secure/records/<BOB_RECORD_ID>`. Expect HTTP 404 and `{"detail":"Record not found"}` for Bob's record. This demonstrates the ownership restriction, but the completion verifier does not require this comparison.
8. **Submit completion.** Click **Complete Lab** in the page header. The button briefly reads **Verifying…**. The browser sends `POST /labs/bola/complete`, includes the session cookie, and sends JSON `{"labId":"bola","record_id":<BOB_RECORD_ID>}`. Expect HTTP 200 and `{"verified":true,"lab_id":"bola","verified_at":"<timestamp>","reason":"passed"}`. The completion panel appears, the button changes to **Completed**, and the page dispatches its `labCompleted` event.
9. **Confirm the dashboard.** Return to `/labs`. After successful verification, the backend sets in-memory status to `completed`, and the dashboard's status request should display BOLA as **Completed**. Status is held in memory, so a server restart resets the dashboard status even though the database audit history remains.

## 4. Expected Results

| Step | Expected Behavior | Backend Evidence | Completion Relevance |
|---|---|---|---|
| 1. Open lab | BOLA MediVault page loads | `GET /bola_lab.html` | Selects the target lab; no completion evidence |
| 2. Start lab | MediVault is shown; status becomes in progress | `POST /labs/bola/status` | Educational/status only; not checked by completion verifier |
| 3. Sign in | Alice dashboard loads | `POST /auth/login`, `GET /auth/me`; session cookie | Required: completion requires an authenticated user; use Alice for the objective |
| 4. Identify record | A current Bob-owned ID is known | Read-only database lookup; `/api/records` itself lists Alice's records only | Needed to target an existing other-owner record; no audit evidence by itself |
| 5. Vulnerable GET | Alice sees Bob's record in the inspector/detail view | `GET /records/{id}` returns 200 and writes `record_access` with Bob's owner ID | **Mandatory evidence** for a clean valid run |
| 6. Confirm audit | Audit row is associated with Alice and a different owner | `audit_logs.user_id`, `action`, `path`, `record_owner_id` | Directly matches the verifier's condition |
| 7. Secure comparison | Secure endpoint returns 404 for Bob's record | `GET /secure/records/{id}`; no completion audit needed | Optional educational comparison; not checked by verifier |
| 8. Complete | Completion panel appears | `POST /labs/bola/complete`; successful call writes `lab_completion:bola` | Mandatory submission; backend verification must pass |
| 9. Dashboard | BOLA status displays completed | Successful verification sets `_lab_status['bola']='completed'`; dashboard reads it with `GET /labs/bola/status` | Confirms the verified result is reflected in the UI |

The vulnerable GET plus an authenticated completion submission are the intended mandatory actions. Viewing both Bob records, comparing the secure endpoint, revealing hints, or opening the dashboard are educational or confirmation steps, not verifier requirements.

## 5. Completion Procedure

### Frontend handler and request

The **Complete Lab** button calls `attemptCompletion()` in `app/templates/bola_lab.html`. It refuses to submit if the page's local `state.user` is empty; disables the button; then sends:

- **Method and endpoint:** `POST /labs/bola/complete`
- **Headers:** `Content-Type: application/json`
- **Credentials:** `credentials: 'include'`
- **Body:** `{"labId":"bola","record_id":state.currentRecordId}`

On `verified: true`, the frontend shows the completion panel, changes the button to **Completed**, updates the in-memory status display, and dispatches `labCompleted`. For a JSON response with `verified: false`, it alerts `Completion conditions not met: <reason>` and re-enables the button. Network/JSON errors show `Verification failed: <message>`.

### Backend conditions

`POST /labs/{lab_id}/complete` in `app/main.py` currently does the following for `lab_id == "bola"`:

1. Requires a resolvable current user; otherwise it returns `verified:false` and `reason:"user_not_authenticated"`.
2. Attempts to parse JSON. A parse failure becomes an empty object.
3. Reads the record ID from `json_body.evidence.record_id`, falling back to the frontend's top-level `json_body.record_id`; malformed or missing values do not identify a valid record.
4. Queries audit rows belonging to the current user with `action == "record_access"`.
5. Requires the audit row to be successful and its path to parse as `/records/<integer>` with an ID equal to the submitted record ID. It then passes if the saved `record_owner_id` differs from the current user's ID. For a legacy row with `record_owner_id == null`, it checks current ownership in the database.
6. It does not check `labId` inside the request body or whether the event occurred during this lab attempt; a historical successful GET for the same record ID can satisfy a later attempt. PUT and DELETE use different audit actions and do not satisfy the read-verification condition.
7. If verified, it writes `lab_completion:bola` for the current user, commits, and sets the in-memory BOLA status to `completed`. It returns HTTP 200 JSON with `verified:true`, `lab_id`, a timestamp, and `reason:"passed"`. Otherwise it returns HTTP 200 JSON with `verified:false`, `verified_at:null`, and `reason:"conditions_not_met"`.

Thus a successful demonstration and a completion result are related but distinct: the browser may show Bob's record, but completion relies on a matching persisted server-side audit log for the authenticated account and the same record ID. The request body identifies which audit event to verify; it is not proof that the event happened by itself. Historical audit rows for that user and same record ID remain eligible.

## 6. Troubleshooting

### `conditions_not_met`

- In Developer Tools **Network**, inspect the `POST /labs/bola/complete` request: confirm HTTP 200, JSON body, and that it was sent to the same app/origin as the lab. Capture its response body. HTTP 200 with `verified:false` is an application-level failed verification, not a transport error.
- Confirm Alice is still signed in: `GET /auth/me` should return HTTP 200 and `username:"alice"`. If it returns 401, sign in again and repeat the vulnerable GET in that session.
- Before clicking Complete, use **Open a record by ID** in **My Records**. Confirm `GET /records/<id>` is HTTP 200 and the returned owner is Bob. A record ID that is missing returns 404 and does not create the expected GET audit row.
- If the UI showed Bob's data but completion still fails, inspect the database audit row. The verifier filters by Alice's `user_id` and exact `action='record_access'`; confirm the request was authenticated as Alice and the row has a different `record_owner_id`.

### Missing audit events

The vulnerable GET writes the audit row after confirming the record exists; its audit-write exception is swallowed by the route. A 200 response without a corresponding audit row therefore indicates a database/session/write issue. Check Uvicorn output, verify that the app and your SQLite inspection tool refer to the same working-directory database, and inspect the audit table with the query below. Do not create a synthetic audit row to force completion.

```sql
SELECT audit_logs.id, audit_logs.user_id, users.username,
       audit_logs.action, audit_logs.path, audit_logs.success,
       audit_logs.record_owner_id, audit_logs.timestamp
FROM audit_logs
LEFT JOIN users ON users.id = audit_logs.user_id
WHERE audit_logs.action = 'record_access'
ORDER BY audit_logs.id DESC;
```

### Incorrect IDs or account/role

- Determine ownership from the current `records`/`users` join, not from the default seed's assumed IDs or stale notes. Use an existing Bob-owned record.
- The table lists only the signed-in user's records, but **Open a record by ID** sends the same request for any entered ID. Start from a visible ID and test nearby values; the response identifies whether the record exists and who owns it.
- Use Alice (`alice` / `alice123`) for the learning objective. The verifier requires an authenticated user and a matching cross-owner audit event; it does not hardcode Alice's username or role.

### Missing or malformed evidence

The UI sends top-level `record_id`; the backend also accepts `evidence.record_id`. Missing, malformed, or mismatched IDs do not verify by themselves and must match a cross-owner audit path. Inspect both the actual payload and the audit row; do not edit browser storage or fabricate evidence. A historical matching audit event can still satisfy verification.

### Database inconsistencies

`init_db()` does not reset existing rows and skips all seeding when any user exists. Check that Alice and Bob exist, the target record exists, and its `owner_id` maps to Bob. The legacy audit fallback can only verify a row with null `record_owner_id` while the referenced record still exists. If the record was deleted, preserve the database and logs for diagnosis rather than reinitializing over it.

### Stale browser state or unexpected HTTP responses

- Reload `/bola_lab.html`, sign in again, then start the lab and make a fresh vulnerable GET. The page stores `currentRecordId` and user state in JavaScript memory; reloading clears that state. The session cookie is HTTP-only, while the page's restore code tries to inspect `document.cookie`, so a reload may not restore the UI's signed-in state even while the browser still sends the cookie to the server.
- `GET /secure/records/<Bob ID>` returning 404 is expected. `GET /records/<Bob ID>` returning 404 means the ID is missing; 401/other errors should be investigated in the Network response and server log.
- `POST /labs/bola/complete` without a valid session returns JSON `user_not_authenticated`; malformed JSON may be treated as empty evidence, but completion still depends on audit history. A network failure or non-JSON response is shown by the frontend as `Verification failed` rather than `conditions_not_met`.
- Compare server working directory, host/port, and SQLite path before drawing conclusions from DB inspection. The dashboard status is in memory and resets on server restart; audit rows are stored in SQLite.