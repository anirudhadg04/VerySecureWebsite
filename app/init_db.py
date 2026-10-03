"""Database initialization and seed data for the VerySecureWebsite lab.

Creates the SQLite database, tables, and synthetic test accounts.
Run once to set up the lab environment.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base, User, Record, AuditLog
from .config import settings


# Create engine and session
engine = create_engine(
    f"sqlite:///{settings.APP_NAME.lower().replace(' ', '_')}.db",
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Initialize the database and create tables + synthetic seed data."""
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    try:
        # Check if users already exist (idempotent)
        existing = db.query(User).count()
        if existing > 0:
            return  # Already initialized

        # Create synthetic test users with different roles
        # User 1: Regular user
        user1 = User(
            username="alice",
            email="alice@localhost",
            password_hash="",
            role="user",
        )
        # Password: "labtest123" hashed with bcrypt

        # User 2: Another regular user (target for BOLA/IDOR)
        user2 = User(
            username="bob",
            email="bob@localhost",
            password_hash="",
            role="user",
        )

        # User 3: Administrator user (target for BFLA)
        admin = User(
            username="admin",
            email="admin@localhost",
            password_hash="",
            role="admin",
        )

        # Hash passwords using bcrypt
        import bcrypt
        user1.password_hash = bcrypt.hashpw(b"labtest123", bcrypt.gensalt()).decode("utf-8")
        user2.password_hash = bcrypt.hashpw(b"labtest123", bcrypt.gensalt()).decode("utf-8")
        admin.password_hash = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode("utf-8")

        # Add users first, then commit to get IDs
        db.add_all([user1, user2, admin])
        db.commit()

        # Create sample records owned by different users (for BOLA/IDOR)
        # Alice owns records 1, 2; Bob owns records 3, 4
        records = [
            Record(title="Alice's Medical Record", content="Confidential medical data", owner_id=user1.id),
            Record(title="Alice's Financial Report", content="Bank statement data", owner_id=user1.id),
            Record(title="Bob's Medical Record", content="Patient notes", owner_id=user2.id),
            Record(title="Bob's Financial Report", content="Investment portfolio", owner_id=user2.id),
        ]

        # Add all records to session
        db.add_all(records)
        db.commit()

        # Create audit log entries for initialization
        audit_entries = [
            AuditLog(user_id=user1.id, action="lab_initialization", path="/init", success=True),
            AuditLog(user_id=user2.id, action="lab_initialization", path="/init", success=True),
            AuditLog(user_id=admin.id, action="lab_initialization", path="/init", success=True),
        ]
        db.add_all(audit_entries)
        db.commit()

        print(f"Database initialized with {existing + 3} users and {len(records)} records")

    finally:
        db.close()


if __name__ == "__main__":
    init_db()