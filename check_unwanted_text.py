from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

# Get the labs page content
print("=== Testing /labs page ===")
resp = client.get('/labs')
content = resp.text

print(f"Status: {resp.status_code}")
print(f"Content length: {len(content)}")

# Look for the specific text the user mentioned
unwanted_text = "'; verifyAndMarkComplete('xss', { action: 'xss_payload', payload }); }; &#x20;'"
if unwanted_text in content:
    print("\\nFOUND: Unwanted text found in labs page!")
    index = content.find(unwanted_text)
    print("Context around the unwanted text:")
    print(content[max(0, index-100):min(len(content), index+200)])
else:
    print("\\nNOT FOUND: Unwanted text not found in labs page")

# Let's check what JavaScript code is actually in the template
if "window.demoXSSComplete = function()" in content:
    print("\\nXSS demo function found in template")
    
if "verifyAndMarkComplete('xss'" in content:
    print("verifyAndMarkComplete function reference found")

# Let's search for similar problematic text
problematic_patterns = [
    "verifyAndMarkComplete('xss'",
    "xss_payload",
    "demoXSSComplete"
]

for pattern in problematic_patterns:
    if pattern in content:
        print(f"\\nFound pattern: {pattern}")
