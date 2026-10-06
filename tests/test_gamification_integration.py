import bcrypt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import main
from app.database import Base, get_db
from app.models import Record, User


@pytest.fixture
def clients(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'integration.db'}", connect_args={"check_same_thread": False})
    factory = sessionmaker(autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = factory()
    users = {}
    for username, role in (("alice", "user"), ("bob", "user"), ("admin", "admin")):
        user = User(
            username=username,
            email=f"{username}@example.test",
            password_hash=bcrypt.hashpw(b"StrongPassword123", bcrypt.gensalt(rounds=4)).decode(),
            role=role,
        )
        db.add(user)
        users[username] = user
    db.commit()
    for user in users.values():
        db.refresh(user)
    bob_record = Record(title="Bob private record", content="Synthetic data", owner_id=users["bob"].id)
    db.add(bob_record)
    db.commit()
    bob_record_id = bob_record.id
    db.close()

    def override_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    main.app.dependency_overrides[get_db] = override_db
    active_clients = []
    try:
        for username in users:
            client = TestClient(main.app)
            active_clients.append(client)
            assert client.get("/login").status_code == 200
            client.headers["X-CSRF-Token"] = client.cookies["vsw_csrf"]
            login = client.post("/auth/login", json={"username": username, "password": "StrongPassword123"})
            assert login.status_code == 200
        yield {"alice": active_clients[0], "bob": active_clients[1], "admin": active_clients[2], "bob_record_id": bob_record_id}
    finally:
        for client in active_clients:
            client.close()
        main.app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_profile_progress_xp_and_achievements_are_user_scoped(clients):
    alice, bob = clients["alice"], clients["bob"]
    anonymous = TestClient(main.app)
    try:
        assert anonymous.get("/api/operator/profile").status_code == 401
        assert anonymous.get("/api/achievements").status_code == 401
        assert alice.get("/labs").status_code == 200
        assert alice.get("/bola_lab.html").status_code == 200
        assert alice.get("/bfla_lab.html").status_code == 200
        assert alice.get("/xss_lab.html").status_code == 200
        assert alice.get("/operator/profile").status_code == 200
        assert alice.get("/settings").status_code == 200
        assert alice.get("/terminal").status_code == 200

        assert alice.get("/api/operator/profile").json()["xp"] == 0
        assert alice.get("/api/daily-contracts").json()["contracts"][0]["status"] == "available"
        assert alice.post("/api/xp/award", json={"source": "lab_completion:bola", "xp_amount": 99999}).status_code == 403
        assert alice.post("/labs/bola/status", json={"status": "completed"}).status_code == 400

        record_id = clients["bob_record_id"]
        assert alice.get(f"/records/{record_id}").status_code == 200
        assert alice.get(f"/secure/records/{record_id}").status_code == 404
        completion = alice.post("/labs/bola/complete", json={"labId": "bola", "record_id": record_id})
        assert completion.json()["verified"] is True
        award = alice.post("/api/xp/award", json={"source": "lab_completion:bola", "xp_amount": 99999})
        assert award.status_code == 200
        assert award.json()["total_xp"] == 500
        assert alice.post("/api/xp/award", json={"source": "lab_completion:bola"}).status_code == 409
        unlocked = alice.post("/api/achievements/check").json()["newly_unlocked"]
        assert "first_breach" in {item["id"] for item in unlocked}
        contract = alice.get("/api/daily-contracts").json()["contracts"][0]
        assert contract["status"] == "completed"
        claim = alice.post("/api/daily-contracts/complete_one_mission/claim")
        assert claim.status_code == 200 and claim.json()["total_xp"] == 600
        assert alice.post("/api/daily-contracts/complete_one_mission/claim").status_code == 400

        assert bob.get("/api/operator/profile").json()["xp"] == 0
        assert bob.get("/api/labs/progress").json()["labs"]["bola"]["status"] == "not_started"
        bob_achievements = bob.get("/api/achievements").json()["achievements"]
        assert not any(item["unlocked"] for item in bob_achievements)

        assert alice.post("/api/user/settings", json={"volume": 23, "theme_accent": "cyan"}).status_code == 200
        assert alice.get("/api/user/settings").json()["volume"] == 23
        assert bob.get("/api/user/settings").json()["volume"] == 50
        assert alice.post("/api/user/settings", json={"volume": 200}).status_code == 422
    finally:
        anonymous.close()


def test_secure_admin_routes_enforce_role(clients):
    assert clients["alice"].get("/secure/admin/users").status_code == 403
    assert clients["admin"].get("/secure/admin/users").status_code == 200
