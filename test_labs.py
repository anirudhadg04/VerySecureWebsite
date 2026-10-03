from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

# Test labs page
print("=== Testing Labs Page ===")
resp = client.get('/labs')
print(f"Labs page status: {resp.status_code}")
print()
print("Labs page content (first 2000 chars):")
print(resp.text[:2000])
print()

# Check for unwanted JavaScript fragment
if "'; verifyAndMarkComplete('xss', { action: 'xss_payload', payload }); }; &#x20;" in resp.text:
    print("ERROR: Unwanted JavaScript fragment found in labs page!")
else:
    print("OK: Unwanted JavaScript fragment not found in labs page")

# Check if XSS completion function is properly defined
if "window.demoXSSComplete" in resp.text:
    print("OK: XSS completion function is defined")
else:
    print("WARNING: XSS completion function not found")

print()