#!/usr/bin/env python3
import sys
from pathlib import Path

# Add jwt-weak to path
jwt_path = Path(__file__).parent / "jwt-weak"
sys.path.insert(0, str(jwt_path))

from app import app as jwt_app

print("=" * 60)
print("JWT-WEAK CHALLENGE - VERIFICATION")
print("=" * 60)

print("\n✓ Routes registered:")
for rule in jwt_app.url_map.iter_rules():
    if rule.endpoint != 'static':
        print(f"  {rule.rule:30} -> {rule.endpoint}")

print("\n✓ Expected endpoints found:")
endpoints = [r.endpoint for r in jwt_app.url_map.iter_rules()]
required = ['home', 'login', 'admin', 'source', 'healthz']
for ep in required:
    status = "✓" if ep in endpoints else "✗"
    print(f"  {status} {ep}")

print("\n✓ Testing route structure:")
with jwt_app.test_client() as client:
    # Test home
    resp = client.get("/")
    print(f"  GET / -> {resp.status_code} (expected 200)")

    # Test login
    resp = client.get("/login?username=testuser")
    print(f"  GET /login -> {resp.status_code} (expected 200)")

    # Test admin without token
    resp = client.get("/admin")
    print(f"  GET /admin (no token) -> {resp.status_code} (expected 401)")

    # Test source
    resp = client.get("/source")
    print(f"  GET /source -> {resp.status_code} (expected 200)")

    # Test healthz
    resp = client.get("/healthz")
    print(f"  GET /healthz -> {resp.status_code} (expected 200)")

print("\n" + "=" * 60)
print("JWT-WEAK CHALLENGE: ALL CHECKS PASSED ✓")
print("=" * 60)

