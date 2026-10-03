"""SQLAlchemy database setup for the VerySecureWebsite lab."""

from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, Session as SASession, sessionmaker
from fastapi import Depends
from sqlalchemy.orm import Session

from .config import settings

# SQLite engine - file-based database for the lab
engine = create_engine(
    f"sqlite:///{settings.APP_NAME.lower().replace(' ', '_')}.db",
    connect_args={"check_same_thread": False},
    echo=False,  # Set to True for SQL debugging
)

# Session local factory - creates a new session per request
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for all SQLAlchemy models
Base = declarative_base()


def get_db() -> Session:
    """Dependency to get a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Configure SQLite for better concurrency in lab environment."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()