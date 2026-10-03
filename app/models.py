"""Database models for the VerySecureWebsite security lab.

SQLAlchemy model definitions. All models are SQLite-compatible.
Synthetic test data is synthetic and isolated to the lab environment.
"""

from datetime import datetime, timezone
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from .config import settings

# Import Base from database module to ensure consistent metadata
from .database import Base  # noqa: F401


class User(Base):
    """User model - synthetic accounts for lab testing.

    Stores hashed passwords only. Never plaintext.
    Roles enable authorization demonstrations.
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(128), unique=True, nullable=False, index=True)
    email = Column(String(256), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    role = Column(String(32), default="user")  # 'user' or 'admin'
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def verify_password(self, plaintext: str) -> bool:
        """Verify a plaintext password against the stored hash.

        Returns True if the password matches, False otherwise.
        """
        from bcrypt import checkpw
        return checkpw(plaintext.encode("utf-8"), self.password_hash.encode("utf-8"))


class Record(Base):
    """Resource record model - target for BOLA/IDOR demonstrations.

    Each record belongs to an owner user. Access control weaknesses
    will be demonstrated in vulnerable endpoints.
    """

    __tablename__ = "records"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(256), nullable=False)
    content = Column(String, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)  # FK to users.id
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationship to owner
    owner = relationship("User", back_populates="records")


# Add back-populates inverse on User
User.records = relationship("Record", order_by=Record.id, back_populates="owner")


class AuditLog(Base):
    """Audit log model - tracks significant actions for lab progress.

    Keeps a server-side record of lab events for completion verification.
    """

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)  # NULL for system actions
    action = Column(String(128), nullable=False)
    path = Column(String(512), nullable=True)
    success = Column(Boolean, default=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))