#!/usr/bin/env python3
"""
Test suite for medium-level CTF challenges
Tests: command-injection, ssrf-internal, xxe-injection
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


def test_command_injection():
    """Test Command Injection Challenge"""
    cmd_app_path = Path(__file__).parent / "command-injection" / "app.py"
    cmd_module = load_module("cmd_injection_app", cmd_app_path)
    cmd_app = cmd_module.app

    print("\n" + "=" * 70)
    print("COMMAND INJECTION CHALLENGE - VERIFICATION")
    print("=" * 70)

    print("\n✓ Routes registered:")
    for rule in cmd_app.url_map.iter_rules():
        if rule.endpoint != 'static':
            print(f"  {rule.rule:30} -> {rule.endpoint}")

    print("\n✓ Testing route structure:")
    with cmd_app.test_client() as client:
        # Test home page
        resp = client.get("/")
        print(f"  GET / -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Home page failed"
        assert b"Ping" in resp.data, "Ping form not found"

        # Test POST with valid host
        resp = client.post("/", data={"host": "127.0.0.1"})
        print(f"  POST / (valid host) -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "POST request failed"

        # Test healthz
        resp = client.get("/healthz")
        print(f"  GET /healthz -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Health check failed"

    print("\n✓ Vulnerability mechanism:")
    print("  - Shell command: ping -c 2 {host}")
    print("  - Vulnerable to: Command chaining with ; or &&")
    print("  - Example payload: 8.8.8.8 && cat /flag.txt")

    print("\n" + "=" * 70)
    print("COMMAND INJECTION: ALL CHECKS PASSED ✓")
    print("=" * 70)


def test_ssrf_internal():
    """Test SSRF Internal Challenge"""
    ssrf_app_path = Path(__file__).parent / "ssrf-internal" / "app.py"
    ssrf_module = load_module("ssrf_internal_app", ssrf_app_path)
    ssrf_app = ssrf_module.app

    print("\n" + "=" * 70)
    print("SSRF INTERNAL CHALLENGE - VERIFICATION")
    print("=" * 70)

    print("\n✓ Routes registered:")
    for rule in ssrf_app.url_map.iter_rules():
        if rule.endpoint != 'static':
            print(f"  {rule.rule:30} -> {rule.endpoint}")

    endpoints = [r.endpoint for r in ssrf_app.url_map.iter_rules()]
    required = ['index', 'api_endpoints', 'internal_status', 'internal_admin', 'flag_direct', 'healthz']

    print("\n✓ Expected endpoints found:")
    for ep in required:
        status = "✓" if ep in endpoints else "✗"
        print(f"  {status} {ep}")

    print("\n✓ Testing route structure:")
    with ssrf_app.test_client() as client:
        # Test index
        resp = client.get("/")
        print(f"  GET / -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Index failed"

        # Test public API endpoints
        resp = client.get("/api/endpoints")
        print(f"  GET /api/endpoints -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "API endpoints failed"

        # Test internal status
        resp = client.get("/internal/status")
        print(f"  GET /internal/status -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Internal status failed"

        # Test internal admin
        resp = client.get("/internal/admin")
        print(f"  GET /internal/admin -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Internal admin failed"

        # Test flag endpoint
        resp = client.get("/flag")
        print(f"  GET /flag -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Flag endpoint failed"

        # Test healthz
        resp = client.get("/healthz")
        print(f"  GET /healthz -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Health check failed"

        # Test SSRF via URL form
        resp = client.post("/", data={"url": "http://localhost:5000/flag"})
        print(f"  POST / (SSRF localhost) -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "SSRF POST failed"

    print("\n✓ Vulnerability mechanism:")
    print("  - No URL validation on user input")
    print("  - User can request internal endpoints via URL form")
    print("  - Example payload: http://localhost:5000/flag")

    print("\n" + "=" * 70)
    print("SSRF INTERNAL: ALL CHECKS PASSED ✓")
    print("=" * 70)


def test_xxe_injection():
    """Test XXE Injection Challenge"""
    xxe_app_path = Path(__file__).parent / "xxe-injection" / "app.py"
    xxe_module = load_module("xxe_injection_app", xxe_app_path)
    xxe_app = xxe_module.app

    print("\n" + "=" * 70)
    print("XXE INJECTION CHALLENGE - VERIFICATION")
    print("=" * 70)

    print("\n✓ Routes registered:")
    for rule in xxe_app.url_map.iter_rules():
        if rule.endpoint != 'static':
            print(f"  {rule.rule:30} -> {rule.endpoint}")

    endpoints = [r.endpoint for r in xxe_app.url_map.iter_rules()]
    required = ['index', 'api_import', 'healthz']

    print("\n✓ Expected endpoints found:")
    for ep in required:
        status = "✓" if ep in endpoints else "✗"
        print(f"  {status} {ep}")

    print("\n✓ Testing route structure:")
    with xxe_app.test_client() as client:
        # Test index
        resp = client.get("/")
        print(f"  GET / -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Index failed"
        assert b"XML" in resp.data, "XML content not found"

        # Test POST with valid XML
        valid_xml = "<user><name>John</name><email>john@example.com</email><role>user</role></user>"
        resp = client.post("/", data={"xml": valid_xml})
        print(f"  POST / (valid XML) -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "POST request failed"

        # Test API import endpoint
        resp = client.post("/api/import", data=valid_xml, content_type='application/xml')
        print(f"  POST /api/import -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "API import failed"

        # Test healthz
        resp = client.get("/healthz")
        print(f"  GET /healthz -> {resp.status_code} (expected 200)")
        assert resp.status_code == 200, "Health check failed"

    print("\n✓ Vulnerability mechanism:")
    print("  - XML parser allows external entities")
    print("  - resolve_entities=True enables XXE")
    print("  - Can be exploited to read files")
    print("  - Example: DOCTYPE with SYSTEM entity pointing to /flag.txt")

    print("\n" + "=" * 70)
    print("XXE INJECTION: ALL CHECKS PASSED ✓")
    print("=" * 70)


if __name__ == "__main__":
    try:
        test_command_injection()
        test_ssrf_internal()
        test_xxe_injection()

        print("\n" + "=" * 70)
        print("ALL MEDIUM CHALLENGES: VERIFICATION COMPLETE ✓✓✓")
        print("=" * 70)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
