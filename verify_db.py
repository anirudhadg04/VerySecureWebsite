"""Verify the application works correctly."""
from app.database import engine, Base, SessionLocal
from app.models import User, Record, AuditLog

# Create tables
Base.metadata.create_all(bind=engine)

# Test basic operations
db = SessionLocal()
try:
    # Count users
    user_count = db.query(User).count()
    print(f'Users in DB: {user_count}')

    # Count records
    record_count = db.query(Record).count()
    print(f'Records in DB: {record_count}')

    # List users
    for u in db.query(User).all():
        print(f'  User: {u.username}, role: {u.role}')

    # List records
    for r in db.query(Record).all():
        print(f'  Record {r.id}: "{r.title}" owned by {r.owner.username}')
finally:
    db.close()