"""BOLA/IDOR and BFLA vulnerability validation tests."""
import requests
import json

BASE = "http://127.0.0.1:8000"

# First, login as alice
print("=== Test 1: Login as Alice ===")
resp = requests.post(f"{BASE}/auth/login", data={"username": "alice", "password": "labtest123"}, allow_redirects=False)
print(f"Login status: {resp.status_code}")
alice_cookie = resp.headers.get('set-cookie', '')
print(f"Session cookie: {alice_cookie[:50]}..." if alice_cookie else "No cookie")

# Login as bob
print("\n=== Test 2: Login as Bob ===")
resp = requests.post(f"{BASE}/auth/login", data={"username": "bob", "password": "labtest123"}, allow_redirects=False)
print(f"Login status: {resp.status_code}")
bob_cookie = resp.headers.get('set-cookie', '')
print(f"Session cookie: {bob_cookie[:50]}..." if bob_cookie else "No cookie")

# TEST BOLA/IDOR: Alice accessing Bob's records
print("\n=== TEST BOLA/IDOR ===")
print("Alice attempting to access Bob's record (ID 3)...")
alice_cookie_full = alice_cookie or ""
headers = {"Cookie": alice_cookie_full} if alice_cookie_full else {}

# Try to GET /records/3 (Bob's medical record) as Alice
resp = requests.get(f"{BASE}/records/3", headers=headers)
print(f"GET /records/3 as Alice: status={resp.status_code}")
if resp.status_code == 200:
    data = resp.json()
    print(f"  VULNERABLE: Alice can access Bob's record!")
    print(f"  Record title: {data.get('title')}")
    print(f"  Record owner: {data.get('owner')}")
    print(f"  Record content: {data.get('content')}")
else:
    print(f"  SECURE: Alice denied access to Bob's record")

# Try to GET /records/1 (Alice's record) as Alice - should work
print("\nAlice accessing her own record (ID 1)...")
resp = requests.get(f"{BASE}/records/1", headers=headers)
print(f"GET /records/1 as Alice: status={resp.status_code}")
if resp.status_code == 200:
    data = resp.json()
    print(f"  OK: Alice can access her own record: {data.get('title')}")

# TEST BFLA: Alice accessing admin endpoints
print("\n=== TEST BFLA ===")
print("Alice attempting to access /admin/users...")
headers_alice = {"Cookie": alice_cookie_full} if alice_cookie_full else {}
resp = requests.get(f"{BASE}/admin/users", headers=headers_alice)
print(f"GET /admin/users as Alice: status={resp.status_code}")
if resp.status_code == 200:
    data = resp.json()
    print(f"  VULNERABLE: Alice can access admin users list!")
    print(f"  Users: {len(data)} users found")
    for u in data:
        print(f"    - {u['username']} ({u['role']})")
else:
    print(f"  SECURE: Alice denied access to admin users")

# TEST: Alice accessing /admin/debug
print("\nAlice attempting to access /admin/debug...")
resp = requests.get(f"{BASE}/admin/debug", headers=headers_alice)
print(f"GET /admin/debug as Alice: status={resp.status_code}")
if resp.status_code == 200:
    data = resp.json()
    print(f"  VULNERABLE: Alice can access debug info!")
    print(f"  Debug keys: {list(data.keys())}")
    # Check if cookie security settings are disclosed
    if 'cookie_secure' in data:
        print(f"  Cookie secure flag: {data['cookie_secure']}")
else:
    print(f"  SECURE: Alice denied access to debug endpoint")

# TEST API records endpoint
print("\n=== TEST API /api/records ===")
print("Alice accessing /api/records...")
headers_alice = {"Cookie": alice_cookie_full} if alice_cookie_full else {}
resp = requests.get(f"{BASE}/api/records", headers=headers_alice)
print(f"GET /api/records as Alice: status={resp.status_code}")
if resp.status_code == 200:
    data = resp.json()
    print(f"  Returned {len(data)} records")
    for r in data:
        print(f"    - Record {r['id']}: {r['title']} (owner: {r['owner']})")

# Test list all records (no ownership filter)
print("\n=== TEST GET /records (list) ===")
resp = requests.get(f"{BASE}/records", headers=headers_alice)
print(f"GET /records as Alice: status={resp.status_code}")
if resp.status_code == 200:
    data = resp.json()
    print(f"  Returned {len(data)} records (ALL records, no ownership filter)")
    for r in data:
        print(f"    - Record {r['id']}: {r['title']} (owner: {r['owner']})")