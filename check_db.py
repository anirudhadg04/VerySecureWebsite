"""Check database state."""
from app.database import SessionLocal, engine
from app.models import Base, User, Record

# Check current state
Base.metadata.create_all(bind=engine)

db = SessionLocal()
try:
    records = db.query(Record).all()
    print(f'Total records: {len(records)}')
    for r in records:
        print(f'  Record {r.id}: "{r.title}" owned by {r.owner.username}')
    
    users = db.query(User).all()
    print(f'\nUsers: {[(u.username, u.role) for u in users]}')
finally:
    db.close()