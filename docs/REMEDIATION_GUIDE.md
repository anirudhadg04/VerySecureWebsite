# VerySecureWebsite - Remediation Guide

**Status**: Phase 3B - Secure counterparts implemented and validated
**Date**: 2026-10-02

---

## Overview

This guide documents the secure counterparts implemented for VUL-001 (BOLA/IDOR) and VUL-002 (BFLA). The intentionally vulnerable endpoints are preserved at their original paths (`/records/`, `/admin/`) as training challenges. All new secure routes are mounted under the `/secure/` prefix to keep them clearly distinguishable.

**Design principle**: secure routes enforce authorization inside the route handler itself using the `get_current_user` dependency, returning 404 for non-existent or non-owned resources (BOLA) and 403 for insufficient privilege (BFLA).

---

## 1. Authentication dependency

`app/main.py` line 46-68:

```python
def get_current_user(
    request: Request,
    db=Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Extract user from request. Supports session cookie or bearer token."""
    # Try to get user from session (cookie-based)
    session_cookie = request.cookies.get("session_id")
    user = None
    if session_cookie:
        user = db.query(User).filter(
            User.username == session_cookie.split(":")[0] if ":" in session_cookie else None
        ).first()
    # Fall back to bearer token if no session
    if not user and credentials:
        user = db.query(User).filter(User.username == credentials.credentials).first()
    return user
```

- Reads the `session_id` cookie set by `POST /auth/login`.
- Falls back to a bearer token in the `Authorization` header (lab use only).
- Returns `None` when neither is present.

## 2. Login authentication (fix applied in Phase 3B)

`app/main.py` line 72-75 (model) and line 118-152 (endpoint):

```python
class LoginRequest(BaseModel):
    username: str
    password: str
```

```python
@app.post("/auth/login")
def login(
    login_data: LoginRequest,
    response: Response,
    db=Depends(get_db),
):
    """Login and set session cookie."""
    user = db.query(User).filter(User.username == login_data.username).first()
    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    import time
    session_value = f"{user.username}:{int(time.time())}"
    response.set_cookie(
        key="session_id",
        value=session_value,
        httponly=settings.COOKIE_HTTP_ONLY,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path="/",
    )
    return {"message": f"Logged in as {user.username}", "user_role": user.role, "user_id": user.id}
```

**Credential delivery**: credentials are now submitted as a JSON body: `{"username": "...", "password": "..."}`. (Previously the endpoint accepted query parameters only; the change keeps the existing test suite and browser API clients compatible.)

---

## 3. BOLA remediation - secure record routes

`app/main.py` lines 352-442.

### 3.1 GET `/secure/records` — list owned records only

```python
@app.get("/secure/records")
def secure_list_records(db=Depends(get_db), current_user=Depends(get_current_user)):
    """List only records owned by the current user. Ownership validation enforced."""
    records = db.query(Record).filter(Record.owner_id == current_user.id).all()
    return records
```

Secures the `/records` (list all) endpoint by filtering on `owner_id == current_user.id`.

### 3.2 GET `/secure/records/{record_id}` — ownership-checked retrieval

```python
@app.get("/secure/records/{record_id}")
def secure_get_record(record_id: int, db=Depends(get_db), current_user=Depends(get_current_user)):
    """Get a specific record with ownership validation. Returns 404 if not owned."""
    record = db.query(Record).filter(
        Record.id == record_id,
        Record.owner_id == current_user.id
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"id": record.id, "title": record.title, "content": record.content,
            "owner": record.owner.username if record.owner else None}
```

Secures the `/records/{id}` (read) endpoint. Ownership is checked at query time; non-owned records are indistinguishable from missing records (404), which is the recommended behavior for BOLA remediation.

### 3.3 PUT `/secure/records/{record_id}` — ownership-checked update

```python
@app.put("/secure/records/{record_id}")
def secure_update_record(record_id: int, title: str = "", content: str = "",
                         db=Depends(get_db), current_user=Depends(get_current_user)):
    """Update a record with ownership validation. Returns 404 if not owned."""
    record = db.query(Record).filter(
        Record.id == record_id,
        Record.owner_id == current_user.id
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    if title:
        record.title = title
    if content:
        record.content = content
    db.commit()
    return {"id": record.id, "title": record.title, "content": record.content}
```

Secures the `/records/{id}` (modify) endpoint with the same ownership-at-query-time pattern.

### 3.4 DELETE `/secure/records/{record_id}` — ownership-checked deletion

```python
@app.delete("/secure/records/{record_id}")
def secure_delete_record(record_id: int, db=Depends(get_db), current_user=Depends(get_current_user)):
    """Delete a record with ownership validation. Returns 404 if not owned."""
    record = db.query(Record).filter(
        Record.id == record_id,
        Record.owner_id == current_user.id
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    db.delete(record)
    db.commit()
    return {"detail": "Record deleted"}
```

Secures the `/records/{id}` (delete) endpoint.

### 3.5 Note on the existing `/api/records` endpoint

The pre-existing `/api/records` GET endpoint (`app/main.py:453`) also returns only the current user's records:

```python
records = db.query(Record).filter(Record.owner_id == current_user.id).all() if current_user else []
```

It defensively returns an empty list when `current_user` is None. This endpoint was retained as-is; the `/secure/records` routes above are the canonical secure implementation.

---

## 4. BFLA remediation - secure admin routes

`app/main.py` lines 452-487.

### 4.1 Authorization dependency

```python
def require_admin(current_user=Depends(get_current_user)):
    """Enforces admin role. Raises 403 if not an administrator."""
    if not current_user or current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator privileges required")
    return current_user
```

A reusable dependency that short-circuits any non-admin request with HTTP 403, evaluated before the handler runs.

### 4.2 GET `/secure/admin/users` — admin-only user listing

```python
@app.get("/secure/admin/users")
def secure_list_users(db=Depends(get_db), current_user=Depends(require_admin)):
    """List all users - admin only."""
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username, "email": u.email, "role": u.role} for u in users]
```

Secures the `/admin/users` endpoint by gating it behind `require_admin`.

### 4.3 GET `/secure/admin/debug` — admin-only debug info

```python
@app.get("/secure/admin/debug")
def secure_debug_info(db=Depends(get_db), current_user=Depends(require_admin)):
    """Debug endpoint - admin only. Minimal configuration without sensitive internals."""
    return {"app_name": settings.APP_NAME, "app_version": settings.APP_VERSION,
            "debug": settings.DEBUG, "host": settings.HOST, "port": settings.PORT}
```

Secures the `/admin/debug` endpoint and removes exposure of sensitive configuration (e.g., `database_url`, cookie flags) from the response.

---

## 5. Endpoint reference

### Secure (new, Phase 3B)

| Endpoint | Method | Auth | Authorization | Response on violation |
|---|---|---|---|---|
| `/secure/records` | GET | user | owner_id == current_user.id | 404 (if no owned records: empty list) |
| `/secure/records/{id}` | GET | user | owner_id == current_user.id | 404 |
| `/secure/records/{id}` | PUT | user | owner_id == current_user.id | 404 |
| `/secure/records/{id}` | DELETE | user | owner_id == current_user.id | 404 |
| `/secure/admin/users` | GET | admin | role == "admin" | 403 |
| `/secure/admin/debug` | GET | admin | role == "admin" | 403 |

### Preserved vulnerable endpoints (training only, behavior unchanged)

| Endpoint | Method | Vulnerability |
|---|---|---|
| `/records` | GET | returns ALL records |
| `/records/{id}` | GET | no ownership check |
| `/records/{id}` | PUT | no ownership check |
| `/records/{id}` | DELETE | no ownership check |
| `/admin/users` | GET | any authenticated user |
| `/admin/debug` | GET | any authenticated user |

### Authentication

| Endpoint | Method | Description |
|---|---|---|
| `/auth/login` | POST | JSON body `{"username", "password"}` → sets `session_id` cookie |
| `/auth/logout` | POST | invalidates session cookie |
| `/auth/me` | GET | current user profile |
| `/auth/register` | POST | new user registration |

---

## 6. Testing the secure routes

Run the full regression suite:

```bash
python -m pytest test_bola_bfla.py -v
```

Expected outcome: **18 passed** (8 pre-existing vulnerable-endpoint tests + 1 database ownership verification + 1 pre-existing secure API test + 6 new BOLA secure tests + 4 new BFLA secure tests).

### BOLA secure tests

| Test | Expected behavior |
|---|---|
| `test_bola_secure_list_records` | Alice sees only records 1, 2 on `/secure/records` |
| `test_bola_secure_get_own_record` | `GET /secure/records/1` → 200 for owner, 404 otherwise |
| `test_bola_secure_cannot_access_bobs_record` | Alice → 404 on `/secure/records/3` |
| `test_bola_secure_cannot_modify_bobs_record` | Alice → 404 on `PUT /secure/records/3` |
| `test_bola_secure_cannot_delete_bobs_record` | Alice → 404 on `DELETE /secure/records/3` |
| `test_bola_secure_bob_cannot_access_alices_record` | Bob → 404 on `/secure/records/1` |

### BFLA secure tests

| Test | Expected behavior |
|---|---|
| `test_bfla_secure_admin_can_access_users` | Admin → 200 on `/secure/admin/users` |
| `test_bfla_secure_regular_user_cannot_access_users` | Alice → 403 on `/secure/admin/users` |
| `test_bfla_secure_admin_can_access_debug` | Admin → 200, no sensitive keys exposed |
| `test_bfla_secure_regular_user_cannot_access_debug` | Alice → 403 on `/secure/admin/debug` |

## 7. Verification

Each secure test performs: authenticate as a user → attempt cross-user / privileged action → assert denial. The test suite additionally confirms the vulnerable endpoints still behave as originally found (no regression of the training material).

## 8. Recommendations for production hardening

The secure routes fix the access-control logic specifically, but production hardening should also consider:

1. **Credential storage**: the session value is `username:timestamp` in a client-side cookie. For production, replace with a server-side session store keyed by a random session ID.
2. **Rate limiting**: login is unthrottled; add throttling to prevent brute-force guessing.
3. **Audit logging**: the `AuditLog` model exists but is not wired into the record/admin routes; log all successful/denied access attempts.
4. **Input validation**: secure routes accept `title`/`content` with no validation; add Pydantic models for request bodies.
5. **CSRF protection**: session-cookie-based state changes should include CSRF tokens.
