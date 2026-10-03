"""Verify authentication endpoints work correctly."""
import requests
import json

BASE = "http://127.0.0.1:8000"

# Register a new user
print("=== Testing Registration ===")
resp = requests.post(f"{BASE}/auth/register", json={"username": "testuser", "email": "test@test.com", "password": "testpass123"})
print(f"Status: {resp.status_code}")
print(f"Response: {resp.json() if resp.status_code == 200 else resp.text}")

# Try registering same user again
print("\n=== Testing Duplicate Registration ===")
resp = requests.post(f"{BASE}/auth/register", json={"username": "testuser", "email": "test@test.com", "password": "testpass123"})
print(f"Status: {resp.status_code}")
print(f"Response: {resp.text}")

# Login
print("\n=== Testing Login ===")
resp = requests.post(f"{BASE}/auth/login", data={"username": "alice", "password": "labtest123"}, allow_redirects=False)
print(f"Login Status: {resp.status_code}")
print(f"Set-Cookie: {resp.headers.get('set-cookie', 'none')}")

# Access /auth/me
print("\n=== Testing /auth/me ===")
resp = requests.get(f"{BASE}/auth/me", cookies={"session_id": "alice:12345"})
print(f"Status: {resp.status_code}")
print(f"Response: {resp.json() if resp.status_code == 200 else resp.text}")

# Test login with wrong password
print("\n=== Testing Wrong Password ===")
resp = requests.post(f"{BASE}/auth/login", data={"username": "alice", "password": "wrongpass"}, allow_redirects=False)
print(f"Status: {resp.status_code}")
print(f"Response: {resp.text}")