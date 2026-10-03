from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

# Test landing page
print("=== Testing Landing Page ===")
resp = client.get('/')
print(f"Landing page status: {resp.status_code}")
print()
print("Landing page content (first 1000 chars):")
print(resp.text[:1000])
print()

# Check if unwanted JavaScript fragment is in the landing page
if "verifyAndMarkComplete('xss'" in resp.text:
    print("ERROR: Unwanted JavaScript fragment found in landing page!")
else:
    print("OK: Unwanted JavaScript fragment not found in landing page")

# Check if features section is hidden in landing page
if 'features' in resp.text.lower() and 'display: none' in resp.text:
    print("OK: Features section is hidden in landing page")
else:
    print("WARNING: Features section might still be visible in landing page")
print()