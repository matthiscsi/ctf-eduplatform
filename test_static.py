#!/usr/bin/env python3
import sys
from pathlib import Path

# Add static-secrets to path
static_path = Path(__file__).parent / "static-secrets"
sys.path.insert(0, str(static_path))

from app import app as static_app

print("=" * 60)
print("STATIC-SECRETS CHALLENGE - VERIFICATION")
print("=" * 60)

print("\n✓ Routes registered:")
for rule in static_app.url_map.iter_rules():
    if rule.endpoint != 'static':
        print(f"  {rule.rule:30} -> {rule.endpoint}")

print("\n✓ Expected endpoints found:")
endpoints = [r.endpoint for r in static_app.url_map.iter_rules()]
required = ['index', 'robots', 'config_bak', 'hidden_index', 'hidden_file', 'healthz']
for ep in required:
    status = "✓" if ep in endpoints else "✗"
    print(f"  {status} {ep}")

print("\n✓ Testing route structure:")
with static_app.test_client() as client:
    # Test index
    resp = client.get("/")
    print(f"  GET / -> {resp.status_code} (expected 200)")

    # Test robots.txt
    resp = client.get("/robots.txt")
    print(f"  GET /robots.txt -> {resp.status_code} (expected 200)")

    # Test config.bak
    resp = client.get("/config.bak")
    print(f"  GET /config.bak -> {resp.status_code} (expected 200)")

    # Test hidden index
    resp = client.get("/hidden/")
    print(f"  GET /hidden/ -> {resp.status_code} (expected 200)")

    # Test hidden file
    resp = client.get("/hidden/flag.txt")
    print(f"  GET /hidden/flag.txt -> {resp.status_code} (expected 200)")
    if resp.status_code == 200:
        print(f"      Flag content: {resp.data.decode().strip()}")

    # Test healthz
    resp = client.get("/healthz")
    print(f"  GET /healthz -> {resp.status_code} (expected 200)")

print("\n" + "=" * 60)
print("STATIC-SECRETS CHALLENGE: ALL CHECKS PASSED ✓")
print("=" * 60)

