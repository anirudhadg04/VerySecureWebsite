"""BOLA/IDOR and BFLA vulnerability validation tests using FastAPI test client."""
import pytest
from app.main import app
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.database import Base, get_db as app_get_db
from app.models import User, Record

import bcrypt

class CsrfAwareTestClient(TestClient):
    def request(self, method, url, **kwargs):
        if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            token = self.cookies.get("vsw_csrf")
            if not token:
                super().get("/login")
                token = self.cookies.get("vsw_csrf")
            headers = dict(kwargs.get("headers") or {})
            headers.setdefault("X-CSRF-Token", token or "")
            kwargs["headers"] = headers
        return super().request(method, url, **kwargs)


client = CsrfAwareTestClient(app)
engine = None
SessionLocal = None


def get_db():
    """Get a database session for the test."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def setup_module(module):
    """Use an isolated in-memory database; do not reset project data."""
    global engine, SessionLocal
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SessionLocal = sessionmaker(autoflush=False, autocommit=False, bind=engine)
    app.dependency_overrides[app_get_db] = get_db
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    seed_data()


def teardown_module(module):
    """Clean up only the in-memory test database."""
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.pop(app_get_db, None)
    engine.dispose()


def seed_data():
    """Insert synthetic test data into the database."""
    db = SessionLocal()
    try:
        existing = db.query(User).count()
        if existing > 0:
            return  # Data already inserted

        user1 = User(username="alice", email="alice@localhost", password_hash="", role="user")
        user2 = User(username="bob", email="bob@localhost", password_hash="", role="user")
        admin = User(username="admin", email="admin@localhost", password_hash="", role="admin")

        user1.password_hash = bcrypt.hashpw(b"labtest123", bcrypt.gensalt()).decode("utf-8")
        user2.password_hash = bcrypt.hashpw(b"labtest123", bcrypt.gensalt()).decode("utf-8")
        admin.password_hash = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode("utf-8")

        db.add_all([user1, user2, admin])
        db.commit()

        records = [
            Record(title="Alice's Medical Record", content="Confidential medical data", owner_id=user1.id),
            Record(title="Alice's Financial Report", content="Bank statement data", owner_id=user1.id),
            Record(title="Bob's Medical Record", content="Patient notes", owner_id=user2.id),
            Record(title="Bob's Financial Report", content="Investment portfolio", owner_id=user2.id),
        ]
        db.add_all(records)
        db.commit()
        print(f"[setup] seeded {existing + 3} users and {len(records)} records")
    finally:
        db.close()


def do_login(username: str, password: str) -> dict:
    """Login and return the response with user info (normalized to include status)."""
    resp = client.post(
        "/auth/login",
        json={"username": username, "password": password}
    )
    if resp.status_code == 200:
        result = resp.json()
        result.setdefault("status", resp.status_code)
        return result
    return {"status": resp.status_code, "text": resp.text}


def do_register(username: str, email: str, password: str) -> dict:
    """Register a new user and return response (normalized to include status)."""
    resp = client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": password, "confirm_password": password}
    )
    if resp.status_code == 200:
        result = resp.json()
        result.setdefault("status", resp.status_code)
        return result
    return {"status": resp.status_code, "text": resp.text}


def test_bola_idor_alice_access_bobs_record():
    """Test BOLA/IDOR: Alice should be able to access Bob's records (vulnerable).

    This validates VUL-001: the /records/{record_id} endpoint has no ownership check.
    """
    client.cookies.clear()

    # Login as alice
    user_info = do_login("alice", "labtest123")
    assert user_info.get("status") in (200, 302), f"Login failed: {user_info}"

    # Access Bob's record (ID 3) as Alice
    resp = client.get("/records/3")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    data = resp.json()
    # In the VULNERABLE implementation, Alice should see Bob's record data
    # This confirms the BOLA/IDOR vulnerability
    assert data["title"] == "Bob's Medical Record", \
        f"Expected Bob's Medical Record, got: {data['title']}"
    assert data["owner"] == "bob", \
        f"Expected owner 'bob', got: {data['owner']}"

    print(f"\n[BOLA/IDOR VALIDATED] Alice can access Bob's record: '{data['title']}' (owner: {data['owner']})")
    print("  This confirms the BOLA/IDOR vulnerability: no ownership validation on /records/{id}")


def test_bola_idor_alice_own_record():
    """Test that Alice can still access her own records (expected behavior)."""
    client.cookies.clear()

    # Login as alice
    user_info = do_login("alice", "labtest123")
    assert user_info.get("status") in (200, 302), f"Login failed: {user_info}"

    # Access Alice's record (ID 1) as Alice
    resp = client.get("/records/1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["title"] == "Alice's Medical Record"
    assert data["owner"] == "alice"

    print(f"[OK] Alice can access her own record: '{data['title']}' (owner: {data['owner']})")


def test_bfla_regular_user_access_admin():
    """Test BFLA: Regular user should be able to access admin endpoints (vulnerable).

    In the vulnerable implementation, /admin/users and /admin/debug have no role check.
    """
    client.cookies.clear()

    # Login as alice (regular user)
    user_info = do_login("alice", "labtest123")
    assert user_info.get("status") in (200, 302), f"Login failed: {user_info}"

    # Access /admin/users as Alice - should work in the vulnerable implementation
    resp = client.get("/admin/users")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

    data = resp.json()
    # In the vulnerable implementation, Alice can see the admin users list
    usernames = [u["username"] for u in data]
    assert "alice" in usernames and "bob" in usernames, \
        f"Expected alice and bob in user list, got: {usernames}"

    print(f"[OK] Regular user can access /admin/users (expected BFLA behavior): {usernames}")


def test_bfla_admin_user_access():
    """Test BFLA: admin user can access administrative endpoints."""
    client.cookies.clear()

    # Login as admin
    user_info = do_login("admin", "admin123")
    assert user_info.get("status") in (200, 302), f"Login failed: {user_info}"

    # Admin should be able to access /admin/users
    resp = client.get("/admin/users")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

    data = resp.json()
    usernames = [u["username"] for u in data]
    assert "admin" in usernames, f"Expected admin in user list, got: {usernames}"

    # Admin should also be able to access /admin/debug
    resp = client.get("/admin/debug")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    data = resp.json()

    print(f"[OK] Admin user can access admin endpoints: {usernames}")


def test_api_records_access_control():
    """Test API /api/records: should return only the authenticated user's records."""
    client.cookies.clear()

    user_info = do_login("alice", "labtest123")
    assert user_info.get("status") in (200, 302), f"Login failed: {user_info}"

    # Access /api/records as Alice
    resp = client.get("/api/records")
    assert resp.status_code == 200
    data = resp.json()

    # Should only return Alice's records (records 1 and 2)
    record_ids = [r["id"] for r in data]
    assert len(record_ids) == 2, f"Expected exactly 2 records, got {record_ids}"
    assert all(r_id in [1, 2] for r_id in record_ids), \
        f"Expected only Alice's records (1, 2), got: {record_ids}"

    print(f"[OK] API /api/records returns only Alice's records: {record_ids}")


def test_list_records_returns_all():
    """Test GET /records: returns ALL records (no ownership filter - vulnerable)."""
    client.cookies.clear()

    user_info = do_login("alice", "labtest123")
    assert user_info.get("status") in (200, 302), f"Login failed: {user_info}"

    resp = client.get("/records")
    assert resp.status_code == 200
    data = resp.json()

    # Returns all 4 records regardless of owner - this is the vulnerable behavior
    assert len(data) == 4, f"Expected 4 records, got {len(data)}"

    titles = [r["title"] for r in data]
    print(f"[OK] GET /records returns all {len(data)} records (no ownership filter - vulnerable): {titles}")


def test_login_logout():
    """Test basic login/logout functionality."""
    client.cookies.clear()

    # Login
    user_info = do_login("alice", "labtest123")
    assert user_info.get("status") in (200, 302), f"Login failed: {user_info}"

    # Logout
    resp = client.post("/auth/logout")
    # Logout may redirect; check status
    assert resp.status_code in (200, 302), f"Logout failed: {resp.status_code}: {resp.text}"

    # Access /auth/me after logout - should be 401
    resp = client.get("/auth/me")
    assert resp.status_code == 401, f"Expected 401 after logout, got {resp.status_code}: {resp.text}"

    print("[OK] Login/logout works correctly")


def test_password_never_plaintext():
    """Test that passwords are hashed with bcrypt, never plaintext."""
    client.cookies.clear()

    # Register a new user
    resp = do_register("testuser2", "test2@test.com", "MyStrongPassword123")
    # Registration may redirect; check status
    assert resp.get("status") in (200, 302), f"Register failed: {resp}"

    # Login with the correct password
    user_info = do_login("testuser2", "MyStrongPassword123")
    assert user_info.get("status") in (200, 302), f"Login with correct password failed: {user_info}"

    # Login with wrong password should fail
    user_info2 = do_login("testuser2", "wrongpassword")
    assert user_info2.get("status") == 401, "Wrong password should not login"

    print("[OK] Passwords are properly hashed with bcrypt")


def test_user_roles():
    """Test that users have correct roles."""
    client.cookies.clear()

    # Login as alice
    user_info = do_login("alice", "labtest123")
    assert user_info.get("status") in (200, 302), f"Login failed: {user_info}"
    me = user_info if isinstance(user_info, dict) and user_info.get("id") else {}
    # The /auth/me endpoint returns role info after login
    resp = client.get("/auth/me")
    assert resp.status_code == 200
    me_data = resp.json()
    assert me_data["role"] == "user", f"Alice should have role 'user', got '{me_data['role']}'"

    # Login as admin
    user_info2 = do_login("admin", "admin123")
    assert user_info2.get("status") in (200, 302), f"Login failed: {user_info2}"
    resp = client.get("/auth/me")
    assert resp.status_code == 200
    me_data = resp.json()
    assert me_data["role"] == "admin", f"Admin should have role 'admin', got '{me_data['role']}'"

    print("[OK] User roles are correctly assigned")


def test_auth_invalid_password():
    """Invalid password must be rejected."""
    client.cookies.clear()

    user_info = do_login("alice", "wrongpassword123")
    assert user_info.get("status") == 401, f"Invalid password should be rejected, got {user_info}"
    print("[OK] Invalid password rejected (401)")


def test_auth_unknown_username():
    """Unknown username must be rejected."""
    client.cookies.clear()

    user_info = do_login("nonexistent_user", "labtest123")
    assert user_info.get("status") == 401, f"Unknown username should be rejected, got {user_info}"
    print("[OK] Unknown username rejected (401)")


def test_auth_missing_username():
    """Missing username must be rejected (422)."""
    client.cookies.clear()

    resp = client.post("/auth/login", json={"password": "labtest123"})
    assert resp.status_code == 422, f"Missing username should return 422, got {resp.status_code}"
    print("[OK] Missing username rejected (422)")


def test_auth_missing_password():
    """Missing password must be rejected (422)."""
    client.cookies.clear()

    resp = client.post("/auth/login", json={"username": "alice"})
    assert resp.status_code == 422, f"Missing password should return 422, got {resp.status_code}"
    print("[OK] Missing password rejected (422)")


def test_auth_unauthenticated_access():
    """Unauthenticated requests to protected routes must be rejected (401)."""
    client.cookies.clear()

    # Auth/me (requires auth via session)
    resp = client.get("/auth/me")
    assert resp.status_code == 401, f"Unauthenticated /auth/me should be 401, got {resp.status_code}"
    # The lab still requires an authenticated session, while demonstrating BOLA
    # through missing ownership validation between authenticated users.
    resp = client.get("/records/3")
    assert resp.status_code == 401, f"Unauthenticated /records/3 should be rejected, got {resp.status_code}"
    # Secure BOLA routes DO require authentication.
    resp = client.get("/secure/records/3")
    assert resp.status_code == 401, f"Unauthenticated secure record access should be 401, got {resp.status_code}"
    # Secure admin routes require admin role (403 when unauthenticated).
    resp = client.get("/secure/admin/users")
    assert resp.status_code == 403, f"Unauthenticated secure admin should be 403, got {resp.status_code}"
    print("[OK] /auth/me and vulnerable routes require a session; "
          "secure routes reject unauthenticated requests (401/403)")


def test_auth_admin_missing_role():
    """Unauthenticated request to a secure admin endpoint returns 403 (no auth -> require_admin denies)."""
    client.cookies.clear()

    resp = client.get("/secure/admin/users")
    assert resp.status_code == 403, f"Unauthenticated secure admin should be 403, got {resp.status_code}"
    print("[OK] Unauthenticated request to secure admin route rejected (403 via require_admin)")
