"""Database models for the VerySecureWebsite security lab.

SQLAlchemy model definitions. All models are SQLite-compatible.
Synthetic test data is synthetic and isolated to the lab environment.
"""

from datetime import datetime, timezone
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, UniqueConstraint, Text
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
    updated_at = Column(DateTime, nullable=True, default=lambda: datetime.now(timezone.utc))

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
    record_owner_id = Column(Integer, nullable=True)  # BOLA: owner of the accessed record


class UserSession(Base):
    """Opaque, revocable server-side browser session."""

    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False, index=True)
    revoked_at = Column(DateTime, nullable=True)


class PasswordResetToken(Base):
    """Single-use reset-token hashes; raw reset tokens are never stored."""

    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False, index=True)
    used_at = Column(DateTime, nullable=True)


class LabProgress(Base):
    """Persistent completion state scoped to one user and one lab."""

    __tablename__ = "lab_progress"
    __table_args__ = (UniqueConstraint("user_id", "lab_id", name="uq_lab_progress_user_lab"),)

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    lab_id = Column(String(32), nullable=False)
    status = Column(String(24), nullable=False, default="not_started")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class AuthRateLimit(Base):
    """Persistent rate-limit bucket keyed by a one-way identifier digest."""

    __tablename__ = "auth_rate_limits"

    key_hash = Column(String(64), primary_key=True)
    attempts = Column(Integer, nullable=False, default=0)
    window_started_at = Column(DateTime, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


# ────────────────────────────────────────────────────────────────────
# Gamification Models (Operator Progression, Achievements, Contracts)
# ────────────────────────────────────────────────────────────────────

RANKS = [
    (1, "SCRIPT KIDDIE"),
    (2, "PACKET SNIFFER"),
    (3, "EXPLOIT APPRENTICE"),
    (4, "VULNERABILITY HUNTER"),
    (5, "ELITE OPERATOR"),
    (6, "CYBER PHANTOM"),
]

ACHIEVEMENTS = [
    {
        "id": "first_breach",
        "name": "FIRST BREACH",
        "description": "Complete your first mission",
        "icon": "🎯",
        "condition": "complete_first_lab",
    },
    {
        "id": "ghost_in_the_system",
        "name": "GHOST IN THE SYSTEM",
        "description": "Complete a mission without using hints",
        "icon": "👻",
        "condition": "complete_lab_no_hints",
    },
    {
        "id": "root_access",
        "name": "ROOT ACCESS",
        "description": "Complete all current missions",
        "icon": "🔓",
        "condition": "complete_all_labs",
    },
    {
        "id": "packet_goblin",
        "name": "PACKET GOBLIN",
        "description": "Inspect 50 or more HTTP requests",
        "icon": "📦",
        "condition": "inspect_50_requests",
    },
    {
        "id": "no_trace",
        "name": "NO TRACE",
        "description": "Complete a mission with zero failed attempts",
        "icon": "🕵️",
        "condition": "complete_lab_zero_errors",
    },
]


def calculate_level(xp: int) -> int:
    """Calculate level from XP. Each level requires progressively more XP."""
    if xp < 500:
        return 1
    # Quadratic progression: level n requires n * 500 + (n-1)*250*(n-1)/2 roughly
    # Simplified: level up every 500, 1000, 1750, 2750, 4000, 5500...
    level = 1
    required = 0
    while True:
        required += 500 + (level - 1) * 250
        if xp < required:
            return level
        level += 1


def calculate_xp_for_level(level: int) -> int:
    """Calculate total XP required to reach a given level."""
    if level <= 1:
        return 0
    total = 0
    for l in range(1, level):
        total += 500 + (l - 1) * 250
    return total


def get_rank_for_level(level: int) -> str:
    """Get rank name for a given level."""
    for lvl, rank in reversed(RANKS):
        if level >= lvl:
            return rank
    return RANKS[0][1]


class OperatorProfile(Base):
    """Extended operator profile with gamification stats."""

    __tablename__ = "operator_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    handle = Column(String(32), nullable=True)  # Optional operator handle
    avatar = Column(String(64), default="avatar_001")  # Avatar identifier
    theme = Column(String(32), default="default")  # Profile theme
    xp = Column(Integer, default=0, nullable=False)
    level = Column(Integer, default=1, nullable=False)
    rank = Column(String(32), default="SCRIPT KIDDIE", nullable=False)
    total_missions_completed = Column(Integer, default=0, nullable=False)
    total_attempts = Column(Integer, default=0, nullable=False)
    hints_used = Column(Integer, default=0, nullable=False)
    requests_inspected = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def recalculate_level_and_rank(self):
        """Recalculate level and rank based on current XP."""
        self.level = calculate_level(self.xp)
        self.rank = get_rank_for_level(self.level)

    def xp_for_next_level(self) -> int:
        return calculate_xp_for_level(self.level + 1)

    def xp_progress_in_level(self) -> tuple[int, int]:
        """Return (current_xp_in_level, xp_needed_for_next_level)."""
        current_level_xp = calculate_xp_for_level(self.level)
        next_level_xp = calculate_xp_for_level(self.level + 1)
        progress = self.xp - current_level_xp
        needed = next_level_xp - current_level_xp
        return (progress, needed)


class Achievement(Base):
    """User achievement tracking."""

    __tablename__ = "achievements"
    __table_args__ = (UniqueConstraint("user_id", "achievement_id", name="uq_user_achievement"),)

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    achievement_id = Column(String(64), nullable=False)  # References ACHIEVEMENTS list
    unlocked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    notified = Column(Boolean, default=False)  # For toast notifications


class DailyContract(Base):
    """Daily contract system for optional objectives."""

    __tablename__ = "daily_contracts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    contract_id = Column(String(64), nullable=False)  # e.g., "complete_one_mission", "inspect_requests_10"
    date = Column(DateTime, nullable=False)  # Date the contract is for (UTC midnight)
    status = Column(String(24), default="available", nullable=False)  # available, completed, claimed
    progress = Column(Integer, default=0, nullable=False)
    target = Column(Integer, default=1, nullable=False)
    xp_reward = Column(Integer, default=100, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    claimed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class UserSettings(Base):
    """User preferences for audio, visual effects, accessibility."""

    __tablename__ = "user_settings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    sound_enabled = Column(Boolean, default=False)
    music_enabled = Column(Boolean, default=False)
    crt_scanlines = Column(Boolean, default=True)
    reduced_motion = Column(Boolean, default=False)
    boot_sequence_enabled = Column(Boolean, default=True)
    theme_accent = Column(String(16), default="phosphor")  # phosphor, cyan, amber, magenta
    terminal_font = Column(String(32), default="vt323")  # vt323, share_tech, orbitron
    brightness = Column(Integer, default=70, nullable=False)
    contrast = Column(Integer, default=80, nullable=False)
    volume = Column(Integer, default=50, nullable=False)
    data_retention = Column(String(16), default="365", nullable=False)
    intelligence_sharing = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class XPAwardLog(Base):
    """Audit log for XP awards to prevent duplicate rewards."""

    __tablename__ = "xp_award_log"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    source = Column(String(64), nullable=False)  # e.g., "lab_completion:bola", "achievement:first_breach"
    xp_amount = Column(Integer, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Prevent duplicate awards for same source
    __table_args__ = (UniqueConstraint("user_id", "source", name="uq_xp_award_user_source"),)


# OTP Verification Model
class OTPVerification(Base):
    """Temporary OTP verification state for registration flow."""

    __tablename__ = "otp_verifications"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(256), nullable=False, index=True)
    otp_hash = Column(String(64), nullable=False)  # Hashed OTP for security
    expires_at = Column(DateTime, nullable=False, index=True)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (UniqueConstraint("email", name="uq_otp_verification_email"),)
