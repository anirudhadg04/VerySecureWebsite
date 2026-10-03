"""Validation test using running server with httpx."""
import subprocess
import time
import json
import httpx
import sys
import os

# Start the server
proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8001"],
    cwd=os.path.dirname(os.path.abspath(".")),
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

# Wait for server to start
time.sleep(3)

BASE = "http://127.0.0.1:8001"
errors = []

try:
    with httpx.Client(base_url=BASE, timeout=10.0) as client:
        # Test 1: Login as Alice
        print("=== Test 1: Login as Alice ===")
        resp = client.post("/auth/login", data={"username": "alice", "password": "labtest123"})
        print(f"Login status: {resp.status_code}")
        if resp.status_code == 302:
            print(f"Login redirect: {resp.headers.get('location')}")
        elif resp.status_code == 200:
            print(f"Login success")
        else:
            print(f"Login failed: {resp.text}")
            errors.append("Login failed")
        
        # Get session cookie
        session_cookie = resp.cookies.get("session_id", "")
        headers = {"Cookie": session_cookie} if session_cookie else {}
        
        # Test 2: BOLA/IDOR - Alice accessing Bob's record
        print("\n=== Test 2: BOLA/IDOR - Alice accessing Bob's record (ID 3) ===")
        resp = client.get("/records/3", headers=headers)
        print(f"GET /records/3 as Alice: status={resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            print(f"  Record title: {data.get('title')}")
            print(f"  Record owner: {data.get('owner')}")
            if data.get("owner") == "bob":
                print("  VULNERABLE: Alice can access Bob's record!")
                errors.append("BOLA/IDOR vulnerability: Alice can access Bob's record")
            else:
                print("  SECURE: Alice cannot access Bob's record")
        else:
            print(f"  Response: {resp.text}")
        
        # Test 3: Alice accessing her own record
        print("\n=== Test 3: Alice accessing her own record (ID 1) ===")
        resp = client.get("/records/1", headers=headers)
        print(f"GET /records/1 as Alice: status={resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            print(f"  Record title: {data.get('title')}")
            print(f"  Record owner: {data.get('owner')}")
            if data.get("owner") == "alice":
                print("  OK: Alice can access her own record")
            else:
                print("  UNEXPECTED: Alice's record has different owner")
        
        # Test 4: BFLA - Alice accessing admin/users
        print("\n=== Test 4: BFLA - Alice accessing /admin/users ===")
        resp = client.get("/admin/users", headers=headers)
        print(f"GET /admin/users as Alice: status={resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            print(f"  Users count: {len(data)}")
            usernames = [u["username"] for u in data]
            print(f"  Usernames: {usernames}")
            if "alice" in usernames and "bob" in usernames:
                print("  VULNERABLE: Alice (regular user) can access admin functions!")
                errors.append("BFLA vulnerability: regular user can access admin users endpoint")
            else:
                print("  SECURE: Alice denied access to admin users")
        else:
            print(f"  Response: {resp.text}")
        
        # Test 5: Alice accessing /admin/debug
        print("\n=== Test 5: Alice accessing /admin/debug ===")
        resp = client.get("/admin/debug", headers=headers)
        print(f"GET /admin/debug as Alice: status={resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            print(f"  App name: {data.get('app_name')}")
            print(f"  Debug info keys: {list(data.keys())}")
            if "cookie_secure" in data or "database_url" in data:
                print("  VULNERABLE: Information disclosure to regular user!")
                errors.append("BFLA/info-disclosure: admin debug info exposed to regular user")
            else:
                print("  OK: No sensitive info disclosed (or endpoint behavior)")
        else:
            print(f"  Response: {resp.text}")
        
        # Test 6: API records
        print("\n=== Test 6: API /api/records as Alice ===")
        resp = client.get("/api/records", headers=headers)
        print(f"GET /api/records as Alice: status={resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            record_ids = [r["id"] for r in data]
            print(f"  Records returned: {record_ids}")
            # Alice should only see her own records (1, 2)
            if all(r_id in [1, 2] for r_id in record_ids):
                print("  OK: API returns only Alice's records")
            else:
                print("  ISSUE: API returning unexpected records")
        
        # Test 7: Login/logout
        print("\n=== Test 7: Login/logout ===")
        resp = client.post("/auth/login", data={"username": "alice", "password": "labtest123"})
        session_cookie = resp.cookies.get("session_id", "")
        headers = {"Cookie": session_cookie} if session_cookie else {}
        
        resp = client.post("/auth/logout", headers=headers)
        print(f"Logout status: {resp.status_code}")
        
        # Access /auth/me after logout
        resp = client.get("/auth/me", headers=headers)
        print(f"/auth/me after logout: status={resp.status_code}")
        if resp.status_code == 401:
            print("  OK: Not authenticated after logout")
        else:
            print("  ISSUE: Still authenticated after logout")
        
        # Test 8: Registration
        print("\n=== Test 8: Registration ===")
        resp = client.post("/auth/register", data={"username": "newuser", "email": "new@test.com", "password": "testpass123"})
        print(f"Register status: {resp.status_code}")
        if resp.status_code in (200, 302):
            print("  OK: Registration works")
        else:
            print(f"  Response: {resp.text}")
        
finally:
    # Stop the server
    proc.terminate()
    proc.wait()
    print("\n=== Server stopped ===")

if errors:
    print(f"\n=== VALIDATION FAILURES ({len(errors)}): ===")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
else:
    print("\n=== ALL VALIDATIONS PASSED ===")
    sys.exit(0)