import bcrypt
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import main
from app.database import Base, get_db
from app.models import User


@pytest.fixture
def lab_client(tmp_path):
    test_engine = create_engine(
        f"sqlite:///{tmp_path / 'labs.db'}",
        connect_args={"check_same_thread": False},
    )
    test_session_factory = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=test_engine,
    )
    Base.metadata.create_all(bind=test_engine)

    db = test_session_factory()
    db.add_all([
        User(
            username="alice",
            email="alice@localhost",
            password_hash=bcrypt.hashpw(b"alice123", bcrypt.gensalt()).decode("utf-8"),
            role="user",
        ),
        User(
            username="admin",
            email="admin@localhost",
            password_hash=bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode("utf-8"),
            role="admin",
        ),
    ])
    db.commit()
    db.close()

    def override_get_db():
        session = test_session_factory()
        try:
            yield session
        finally:
            session.close()

    main.app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(main.app) as client:
            client.get("/login")
            client.headers["X-CSRF-Token"] = client.cookies["vsw_csrf"]
            yield client
    finally:
        main.app.dependency_overrides.pop(get_db, None)
        test_engine.dispose()


def test_bfla_requires_successful_vulnerable_access_by_regular_user(lab_client):
    client = lab_client
    assert client.post(
        "/auth/login",
        json={"username": "alice", "password": "alice123"},
    ).status_code == 200

    assert client.get("/secure/admin/users").status_code == 403
    rejected = client.post("/labs/bfla/complete", json={"labId": "bfla"})
    assert rejected.json()["verified"] is False

    assert client.get("/admin/users").status_code == 200
    verified = client.post("/labs/bfla/complete", json={"labId": "bfla"})
    assert verified.json()["verified"] is True
    assert client.get("/labs/bfla/status").json()["status"] == "completed"


def test_bfla_admin_secure_access_does_not_complete(lab_client):
    client = lab_client
    assert client.post(
        "/auth/login",
        json={"username": "admin", "password": "admin123"},
    ).status_code == 200

    assert client.get("/secure/admin/users").status_code == 200
    rejected = client.post("/labs/bfla/complete", json={"labId": "bfla"})
    assert rejected.json()["verified"] is False


def test_status_endpoint_cannot_mark_lab_complete_directly(lab_client):
    assert lab_client.post(
        "/auth/login",
        json={"username": "alice", "password": "alice123"},
    ).status_code == 200
    response = lab_client.post("/labs/bola/status", json={"status": "completed"})
    assert response.status_code == 400
    assert lab_client.get("/labs/bola/status").json()["status"] == "not_started"


def test_xss_completion_requires_matching_vulnerable_request_by_authenticated_user(lab_client):
    client = lab_client
    assert client.post(
        "/auth/login",
        json={"username": "alice", "password": "alice123"},
    ).status_code == 200
    payload = '<script>parent.postMessage("xss-lab-executed","*")</script>'
    attempt_id = "run-42"
    evidence = {"payload": payload, "attempt_id": attempt_id}

    no_request = client.post("/labs/xss/complete", json={"evidence": evidence})
    assert no_request.json()["verified"] is False
    assert no_request.json()["reason"] == "conditions_not_met"

    secure = client.get(
        "/secure/xss",
        params={"username": payload, "attempt_id": attempt_id},
    )
    assert "&lt;script&gt;" in secure.text
    secure_only = client.post("/labs/xss/complete", json={"evidence": evidence})
    assert secure_only.json()["verified"] is False

    vulnerable = client.get(
        "/xss",
        params={"username": payload, "attempt_id": attempt_id},
    )
    assert payload in vulnerable.text

    wrong_attempt = client.post(
        "/labs/xss/complete",
        json={"evidence": {"payload": payload, "attempt_id": "another-run"}},
    )
    assert wrong_attempt.json()["verified"] is False
    wrong_payload = client.post(
        "/labs/xss/complete",
        json={"evidence": {"payload": "<script>alert(1)</script>", "attempt_id": attempt_id}},
    )
    assert wrong_payload.json()["verified"] is False

    verified = client.post("/labs/xss/complete", json={"evidence": evidence})
    assert verified.json()["verified"] is True
    assert client.get("/labs/xss/status").json()["status"] == "completed"


def test_xss_rejects_non_executable_reflection(lab_client):
    client = lab_client
    assert client.post(
        "/auth/login",
        json={"username": "alice", "password": "alice123"},
    ).status_code == 200
    attempt_id = "plain-text-run"
    client.get("/xss", params={"username": "ordinary text", "attempt_id": attempt_id})
    response = client.post(
        "/labs/xss/complete",
        json={"evidence": {"payload": "ordinary text", "attempt_id": attempt_id}},
    )
    assert response.json()["verified"] is False


def test_xss_response_panels_render_untrusted_markup_as_text():
    template_path = Path(__file__).resolve().parents[1] / "app" / "templates" / "xss_lab.html"
    template = template_path.read_text(encoding="utf-8")
    assert "requestInfo.innerHTML" not in template
    assert "responseInfo.innerHTML" not in template
    assert "line.textContent = message" in template
    assert template.count('sandbox="allow-scripts"') == 3
