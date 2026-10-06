import bcrypt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import main
from app.database import Base, get_db
from app.models import Record, User


@pytest.fixture
def lab_client(tmp_path):
    test_engine = create_engine(
        f"sqlite:///{tmp_path / 'lab.db'}",
        connect_args={"check_same_thread": False},
    )
    test_session_factory = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=test_engine,
    )
    Base.metadata.create_all(bind=test_engine)

    db = test_session_factory()
    alice = User(
        username="alice",
        email="alice@localhost",
        password_hash=bcrypt.hashpw(b"alice123", bcrypt.gensalt()).decode("utf-8"),
        role="user",
    )
    bob = User(
        username="bob",
        email="bob@localhost",
        password_hash=bcrypt.hashpw(b"bob123", bcrypt.gensalt()).decode("utf-8"),
        role="user",
    )
    db.add_all([alice, bob])
    db.commit()
    db.add_all([
        Record(title="Alice record", content="Alice data", owner_id=alice.id),
        Record(title="Bob record", content="Bob data", owner_id=bob.id),
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


def test_bola_completion_requires_matching_audit_record_and_updates_status(lab_client):
    client = lab_client
    login = client.post(
        "/auth/login",
        json={"username": "alice", "password": "alice123"},
    )
    assert login.status_code == 200
    client.post("/labs/bola/status", json={"status": "in_progress"})

    fabricated = client.post(
        "/labs/bola/complete",
        json={"labId": "bola", "record_id": 2, "evidence": []},
    )
    assert fabricated.status_code == 200
    assert fabricated.json()["verified"] is False
    assert fabricated.json()["reason"] == "conditions_not_met"

    assert client.get("/secure/records/2").status_code == 404
    vulnerable_access = client.get("/records/2")
    assert vulnerable_access.status_code == 200
    assert vulnerable_access.json()["owner"] == "bob"

    mismatched = client.post(
        "/labs/bola/complete",
        json={"labId": "bola", "record_id": 1},
    )
    assert mismatched.json()["verified"] is False

    verified = client.post(
        "/labs/bola/complete",
        json={"labId": "bola", "record_id": 2},
    )
    assert verified.json()["verified"] is True
    assert verified.json()["reason"] == "passed"
    assert client.get("/labs/bola/status").json()["status"] == "completed"


def test_bola_write_only_access_does_not_complete(lab_client):
    client = lab_client
    assert client.post(
        "/auth/login",
        json={"username": "alice", "password": "alice123"},
    ).status_code == 200

    assert client.put("/records/2", params={"title": "Changed by Alice"}).status_code == 200
    assert client.delete("/records/2").status_code == 200
    response = client.post(
        "/labs/bola/complete",
        json={"labId": "bola", "record_id": 2},
    )
    assert response.json()["verified"] is False
