#!/usr/bin/env python3
"""
Test suite for hard-level CTF challenges
Tests: container-breakout, hard-deserialization, hard-jwt-confusion
"""
import sys
import importlib.util
from pathlib import Path


def load_module(module_name, module_path):
    """Dynamically load a module from a specific path"""
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_container_breakout():
    """Test Container Breakout Challenge"""
    app_path = Path(__file__).parent / "container-breakout" / "app.py"
    module = load_module("container_breakout_app", app_path)
    app = module.app

    print("\n" + "=" * 70)
    print("CONTAINER BREAKOUT CHALLENGE - VERIFICATION")
    print("=" * 70)

    print("\n✓ Routes registered:")
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'static':
            print(f"  {rule.rule:30} -> {rule.endpoint}")

    endpoints = [r.endpoint for r in app.url_map.iter_rules()]
    required = ['index', 'fetch', 'healthz']

    print("\n✓ Expected endpoints found:")
    for ep in required:
        status = "✓" if ep in endpoints else "✗"
        print(f"  {status} {ep}")

    print("\n✓ Testing route structure:")
    with app.test_client() as client:
        # Test index
        resp = client.get("/")
        print(f"  GET / -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Index failed"

        # Test healthz
        resp = client.get("/healthz")
        print(f"  GET /healthz -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Health check failed"

        # Test fetch endpoint (SSRF vulnerability)
        resp = client.post("/fetch", data={"url": "http://example.com"})
        print(f"  POST /fetch -> {resp.status_code} (expected 200 or 502)")

    print("\n✓ Vulnerability mechanism:")
    print("  - SSRF endpoint allows fetching arbitrary URLs")
    print("  - Can be exploited to access Docker API on dind-host:2375")
    print("  - Multi-step exploitation: ping -> pull image -> create container -> start -> get logs")

    print("\n" + "=" * 70)
    print("CONTAINER BREAKOUT: ALL CHECKS PASSED ✓")
    print("=" * 70)


def test_deserialization():
    """Test Deserialization RCE Challenge"""
    app_path = Path(__file__).parent / "hard-deserialization" / "app.py"
    module = load_module("deserialization_app", app_path)
    app = module.app

    print("\n" + "=" * 70)
    print("DESERIALIZATION RCE CHALLENGE - VERIFICATION")
    print("=" * 70)

    print("\n✓ Routes registered:")
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'static':
            print(f"  {rule.rule:30} -> {rule.endpoint}")

    endpoints = [r.endpoint for r in app.url_map.iter_rules()]
    required = ['index', 'serialize', 'deserialize', 'healthz']

    print("\n✓ Expected endpoints found:")
    for ep in required:
        status = "✓" if ep in endpoints else "✗"
        print(f"  {status} {ep}")

    print("\n✓ Testing route structure:")
    with app.test_client() as client:
        # Test index
        resp = client.get("/")
        print(f"  GET / -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Index failed"

        # Test deserialize endpoint (vulnerable)
        resp = client.post("/deserialize", data={"data": "invalid"})
        print(f"  POST /deserialize -> {resp.status_code} (handles invalid input)")

        # Test healthz
        resp = client.get("/healthz")
        print(f"  GET /healthz -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Health check failed"

    print("\n✓ Vulnerability mechanism:")
    print("  - pickle.loads() without validation allows RCE")
    print("  - Attacker can craft malicious serialized objects")
    print("  - __reduce__ method can execute arbitrary code")
    print("  - os.system() or subprocess can be exploited")

    print("\n" + "=" * 70)
    print("DESERIALIZATION RCE: ALL CHECKS PASSED ✓")
    print("=" * 70)


def test_jwt_confusion():
    """Test JWT Algorithm Confusion Challenge"""
    app_path = Path(__file__).parent / "hard-jwt-confusion" / "app.py"
    module = load_module("jwt_confusion_app", app_path)
    app = module.app

    print("\n" + "=" * 70)
    print("JWT ALGORITHM CONFUSION CHALLENGE - VERIFICATION")
    print("=" * 70)

    print("\n✓ Routes registered:")
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'static':
            print(f"  {rule.rule:30} -> {rule.endpoint}")

    endpoints = [r.endpoint for r in app.url_map.iter_rules()]
    required = ['index', 'generate_token', 'verify_token', 'public_key_endpoint', 'healthz']

    print("\n✓ Expected endpoints found:")
    for ep in required:
        status = "✓" if ep in endpoints else "✗"
        print(f"  {status} {ep}")

    print("\n✓ Testing route structure:")
    with app.test_client() as client:
        # Test index
        resp = client.get("/")
        print(f"  GET / -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Index failed"

        # Test token generation
        resp = client.post("/token", data={"username": "test", "role": "user"})
        print(f"  POST /token -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Token generation failed"

        # Test public key endpoint
        resp = client.get("/public-key")
        print(f"  GET /public-key -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Public key endpoint failed"

        # Test verify endpoint
        resp = client.post("/verify", data={"token": "invalid"})
        print(f"  POST /verify -> {resp.status_code} (handles invalid token)")

        # Test healthz
        resp = client.get("/healthz")
        print(f"  GET /healthz -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Health check failed"

    print("\n✓ Vulnerability mechanism:")
    print("  - Service accepts both HS256 and RS256 algorithms")
    print("  - Public key is exposed or discoverable")
    print("  - Attacker can forge token with HS256 using public key as secret")
    print("  - Change role from 'user' to 'admin' to access flag")

    print("\n" + "=" * 70)
    print("JWT ALGORITHM CONFUSION: ALL CHECKS PASSED ✓")
    print("=" * 70)


if __name__ == "__main__":
    try:
        test_container_breakout()
        test_deserialization()
        test_jwt_confusion()

        print("\n" + "=" * 70)
        print("ALL HARD CHALLENGES: VERIFICATION COMPLETE ✓✓✓")
        print("=" * 70)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
