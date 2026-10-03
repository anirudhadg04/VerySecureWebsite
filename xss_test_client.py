from fastapi.testclient import TestClient
from app.database import SessionLocal, engine, Base
from app.models import Base, User, Record
import bcrypt
Base.metadata.create_all(bind=engine)
db = SessionLocal()
if db.query(User).count() == 0:
    u1 = User(username='alice', email='a@l', password_hash='', role='user')
    u2 = User(username='bob', email='b@l', password_hash='', role='user')
    a = User(username='admin', email='ad@l', password_hash='', role='admin')
    u1.password_hash = bcrypt.hashpw(b'labtest123', bcrypt.gensalt()).decode()
    u2.password_hash = bcrypt.hashpw(b'labtest123', bcrypt.gensalt()).decode()
    a.password_hash = bcrypt.hashpw(b'admin123', bcrypt.gensalt()).decode()
    db.add_all([u1, u2, a])
    db.commit()
    db.add_all([Record(title='A1', content='c', owner_id=u1.id), Record(title='B1', content='c', owner_id=u2.id)])
    db.commit()
db.close()
from app.main import app
client = TestClient(app)
script = "<script>alert('XSS_PROOF')</script>"
r1 = client.get("/xss", params={"username": script})
print("VULNERABLE endpoint (/xss):")
print("  status:", r1.status_code, "content-type:", r1.headers.get("content-type"))
print("  raw <script> present:", "<script>" in r1.text)
print("  escaped &lt;script&gt; present:", "&lt;script&gt;" in r1.text)
r2 = client.get("/secure/xss", params={"username": script})
print("SECURE endpoint (/secure/xss):")
print("  status:", r2.status_code, "content-type:", r2.headers.get("content-type"))
print("  raw <script> present:", "<script>" in r2.text)
print("  escaped &lt;script&gt; present:", "&lt;script&gt;" in r2.text)
