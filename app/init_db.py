"""Create new tables and safely add columns to an existing lab database."""

from sqlalchemy import inspect, text

from .database import Base, SessionLocal, engine
from .models import (
    AuditLog,
    LabProgress,
    PasswordResetToken,
    Record,
    User,
    UserSession,
    OperatorProfile,
    Achievement,
    DailyContract,
    UserSettings,
    XPAwardLog,
)


def init_db():
    """Initialize schema without resetting or reassigning existing data."""
    Base.metadata.create_all(bind=engine)

    inspector = inspect(engine)
    with engine.begin() as connection:
        if "audit_logs" in inspector.get_table_names():
            audit_columns = {column["name"] for column in inspector.get_columns("audit_logs")}
            if "record_owner_id" not in audit_columns:
                connection.execute(text("ALTER TABLE audit_logs ADD COLUMN record_owner_id INTEGER"))
        if "users" in inspector.get_table_names():
            user_columns = {column["name"] for column in inspector.get_columns("users")}
            if "updated_at" not in user_columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN updated_at DATETIME"))
                connection.execute(text("UPDATE users SET updated_at = created_at WHERE updated_at IS NULL"))

        if "user_settings" in inspector.get_table_names():
            settings_columns = {column["name"] for column in inspector.get_columns("user_settings")}
            settings_migrations = {
                "brightness": "INTEGER NOT NULL DEFAULT 70",
                "contrast": "INTEGER NOT NULL DEFAULT 80",
                "volume": "INTEGER NOT NULL DEFAULT 50",
                "data_retention": "VARCHAR(16) NOT NULL DEFAULT '365'",
                "intelligence_sharing": "BOOLEAN NOT NULL DEFAULT 0",
            }
            for column, sql_type in settings_migrations.items():
                if column not in settings_columns:
                    connection.execute(text(f"ALTER TABLE user_settings ADD COLUMN {column} {sql_type}"))

        if "operator_profiles" in inspector.get_table_names():
            profile_columns = {column["name"] for column in inspector.get_columns("operator_profiles")}
            profile_migrations = {
                "total_missions_completed": "INTEGER NOT NULL DEFAULT 0",
                "total_attempts": "INTEGER NOT NULL DEFAULT 0",
                "hints_used": "INTEGER NOT NULL DEFAULT 0",
                "requests_inspected": "INTEGER NOT NULL DEFAULT 0",
            }
            for column, sql_type in profile_migrations.items():
                if column not in profile_columns:
                    connection.execute(text(f"ALTER TABLE operator_profiles ADD COLUMN {column} {sql_type}"))

        # Migrate existing users to have operator profiles
        if "operator_profiles" in inspector.get_table_names() and "users" in inspector.get_table_names():
            user_columns = {column["name"] for column in inspector.get_columns("users")}
            profile_columns = {column["name"] for column in inspector.get_columns("operator_profiles")}
            if "id" in user_columns:
                # Check if any users don't have profiles
                result = connection.execute(text("""
                    SELECT u.id FROM users u
                    LEFT JOIN operator_profiles op ON u.id = op.user_id
                    WHERE op.user_id IS NULL
                """))
                for row in result:
                    connection.execute(text("""
                        INSERT INTO operator_profiles (
                            user_id, handle, avatar, theme, xp, level, rank,
                            total_missions_completed, total_attempts, hints_used, requests_inspected,
                            created_at, updated_at
                        )
                        VALUES (
                            :user_id, NULL, 'avatar_001', 'default', 0, 1, 'SCRIPT KIDDIE',
                            0, 0, 0, 0, datetime('now'), datetime('now')
                        )
                    """), {"user_id": row[0]})

        # Migrate user_settings
        if "user_settings" in inspector.get_table_names() and "users" in inspector.get_table_names():
            result = connection.execute(text("""
                SELECT u.id FROM users u
                LEFT JOIN user_settings us ON u.id = us.user_id
                WHERE us.user_id IS NULL
            """))
            for row in result:
                connection.execute(text("""
                INSERT INTO user_settings (
                    user_id, sound_enabled, music_enabled, crt_scanlines, reduced_motion,
                    boot_sequence_enabled, theme_accent, terminal_font,
                    brightness, contrast, volume, data_retention, intelligence_sharing,
                    created_at, updated_at
                )
                VALUES (
                    :user_id, 0, 0, 1, 0, 1, 'phosphor', 'vt323',
                    70, 80, 50, '365', 0, datetime('now'), datetime('now')
                )
                """), {"user_id": row[0]})


if __name__ == "__main__":
    init_db()
