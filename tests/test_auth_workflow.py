from datetime import timedelta
from urllib.parse import urlsplit

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import auth, main
from app.database import Base, get_db
from app.email_service import SMTPDeliveryError
from app.models import PasswordResetToken, User
from app.security import opaque_token_hash, verify_password


def test_registration_login_logout_and_user_scoped_progress(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'auth.db'}", connect_args={"check_same_thread": False})
    factory = sessionmaker(autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(main.app) as client:
            client.get("/register")
            client.headers["X-CSRF-Token"] = client.cookies["vsw_csrf"]
            assert client.get("/labs", follow_redirects=False).status_code == 303
            assert client.get("/bola_lab.html", follow_redirects=False).status_code == 303
            first_payload = {
                "username": "alice", "email": "alice@example.test",
                "password": "StrongPassword123", "confirm_password": "StrongPassword123",
            }
            created = client.post("/auth/register", json=first_payload)
            assert created.status_code == 200
            assert client.post("/auth/register", json=first_payload).status_code == 409
            duplicate_email = dict(first_payload, username="anotheruser")
            assert client.post("/auth/register", json=duplicate_email).status_code == 409

            db = factory()
            alice = db.query(User).filter_by(username="alice").one()
            assert verify_password("StrongPassword123", alice.password_hash)
            assert "StrongPassword123" not in alice.password_hash
            db.close()

            second_payload = {
                "username": "bob", "email": "bob@example.test",
                "password": "StrongPassword456", "confirm_password": "StrongPassword456",
            }
            assert client.post("/auth/register", json=second_payload).status_code == 200

            logged_in = client.post("/auth/login", json={"username": "alice", "password": "StrongPassword123"})
            assert logged_in.status_code == 200
            assert client.get("/auth/me").json()["username"] == "alice"
            assert client.get("/api/labs/progress").json()["labs"]["bfla"]["status"] == "not_started"

            assert client.get("/admin/users").status_code == 200
            completed = client.post("/labs/bfla/complete", json={"labId": "bfla"})
            assert completed.json()["verified"] is True
            assert client.get("/api/labs/progress").json()["labs"]["bfla"]["status"] == "completed"

            assert client.post("/auth/logout").status_code == 200
            assert client.get("/auth/me").status_code == 401
            assert client.post("/auth/login", json={"username": "bob", "password": "StrongPassword456"}).status_code == 200
            assert client.get("/api/labs/progress").json()["labs"]["bfla"]["status"] == "not_started"
            assert client.post("/auth/logout").status_code == 200
            assert client.post("/auth/login", json={"username": "alice", "password": "StrongPassword123"}).status_code == 200
            assert client.get("/api/labs/progress").json()["labs"]["bfla"]["status"] == "completed"
    finally:
        main.app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_password_reset_token_is_single_use_and_revokes_sessions(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'reset.db'}", connect_args={"check_same_thread": False})
    factory = sessionmaker(autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[get_db] = override_db
    sent = []
    monkeypatch.setattr(auth.settings, "SMTP_HOST", "smtp.example.test")
    monkeypatch.setattr(auth.settings, "SMTP_FROM_EMAIL", "security@example.test")
    monkeypatch.setattr(auth.settings, "SMTP_USERNAME", "")
    monkeypatch.setattr(auth.settings, "SMTP_PASSWORD", "")
    monkeypatch.setattr(auth, "send_password_reset_email", lambda recipient, url: sent.append((recipient, url)))
    try:
        with TestClient(main.app) as client:
            client.get("/register")
            client.headers["X-CSRF-Token"] = client.cookies["vsw_csrf"]
            credentials = {
                "username": "resetuser", "email": "reset@example.test",
                "password": "StrongPassword123", "confirm_password": "StrongPassword123",
            }
            assert client.post("/auth/register", json=credentials).status_code == 200
            assert client.post("/auth/login", json={"username": "resetuser", "password": credentials["password"]}).status_code == 200

            request_data = {"email": "reset@example.test"}
            assert client.post("/auth/forgot-password", json=request_data).status_code == 200
            assert len(sent) == 1
            assert sent[0][0] == credentials["email"]
            raw_token = urlsplit(sent[0][1]).fragment.removeprefix("token=")
            assert raw_token
            db = factory()
            try:
                token_row = db.query(PasswordResetToken).one()
                assert token_row.token_hash == opaque_token_hash(raw_token)
                assert token_row.token_hash != raw_token
                assert token_row.expires_at - token_row.created_at == timedelta(
                    minutes=auth.settings.PASSWORD_RESET_TOKEN_EXPIRY_MINUTES
                )
            finally:
                db.close()

            new_password = "AnotherStrongPassword789"
            reset_payload = {"token": raw_token, "password": new_password, "confirm_password": new_password}
            assert client.post("/auth/reset-password", json=reset_payload).status_code == 200
            assert client.get("/auth/me").status_code == 401
            assert client.post("/auth/reset-password", json=reset_payload).status_code == 400
            assert client.post("/auth/login", json={"username": "resetuser", "password": credentials["password"]}).status_code == 401
            assert client.post("/auth/login", json={"username": "resetuser", "password": new_password}).status_code == 200

            unknown = client.post("/auth/forgot-password", json={"email": "missing@example.test"})
            assert unknown.status_code == 200
            assert unknown.json() == {"message": "If the address is registered and email delivery is available, recovery instructions will be sent."}

            def fail_delivery(recipient, url):
                raise SMTPDeliveryError("mock transport failure")

            monkeypatch.setattr(auth, "send_password_reset_email", fail_delivery)
            failed_delivery = client.post("/auth/forgot-password", json=request_data)
            assert failed_delivery.status_code == 200
            assert failed_delivery.json() == unknown.json()
            db = factory()
            try:
                assert db.query(PasswordResetToken).filter_by(used_at=None).count() == 0
            finally:
                db.close()
    finally:
        main.app.dependency_overrides.pop(get_db, None)
        engine.dispose()
