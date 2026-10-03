"""Quick database verification."""
from app.database import SessionLocal, engine
from app.models import Base, User, Record

# Create tables
Base.metadata.create_all(bind=engine)

db = SessionLocal()
try:
    user_count = db.query(User).count()
    record_count = db.query(Record).count()
    print(f'Users: {user_count}, Records: {record_count}')
    
    for u in db.query(User).all():
        print(f'  User: {u.username}, role: {u.role}')
    
    for r in db.query(Record).all():
        print(f'  Record {r.id}: "{r.title}" owned by {r.owner.username}')
finally:
    db.close()