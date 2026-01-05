"""
SSRF Internal CTF Challenge (Medium)
Vulnerability: Server-Side Request Forgery to access internal endpoints
"""
from flask import Flask, request, render_template_string, jsonify
import requests
import os

app = Flask(__name__)
FLAG = os.getenv("FLAG", "CTF{ssrf_metadata_leak}")

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>URL Preview Service</title>
    <style>
        :root { color-scheme: light dark; }
        body { font-family: system-ui, sans-serif; max-width: 700px; margin: 2rem auto; padding: 0 1rem; }
        h1 { color: #2563eb; }
        form { margin: 1.5rem 0; }
        input[type="text"] { padding: 0.6rem 0.7rem; width: 420px; border: 1px solid #cbd5e1; border-radius: 8px; }
        input[type="text"]:focus-visible, button:focus-visible { outline: 3px solid #93c5fd; outline-offset: 2px; }
        button { padding: 0.6rem 1rem; background: #2563eb; color: white; border: 1px solid #1d4ed8; border-radius: 8px; cursor: pointer; font-weight:600; }
        button:hover { background: #1d4ed8; }
        .result { background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 8px; margin-top: 1rem; overflow-x: auto; }
        .result pre { margin: 0; white-space: pre-wrap; }
        .error { background: #fef2f2; color: #991b1b; padding: 1rem; border-radius: 8px; border: 1px solid #fecaca; }
        .hint { color: #6b7280; font-size: 0.9rem; margin-top: 1rem; }
        a.back { color:#2563eb; text-decoration:none; }
        a.back:hover { text-decoration:underline; }
        @media (prefers-color-scheme: dark) {
            body { background: #0f172a; color: #e2e8f0; }
            h1 { color: #60a5fa; }
            input { background: #1e293b; color: #e2e8f0; border-color: #334155; }
            .error { background: #450a0a; color: #fecaca; border-color: #7f1d1d; }
        }
    </style>
</head>
<body>
    <p><a class="back" href="{{ portal_url }}">← Terug naar portaal</a></p>
    <h1>🔗 URL Preview Service</h1>
    <p>Enter a URL to fetch and preview its content:</p>
    <form method="POST">
        <input type="text" name="url" placeholder="https://example.com" value="{{ url or '' }}" required>
        <button type="submit">Fetch</button>
    </form>
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
    {% if content %}
    <div class="result">
        <strong>Response from {{ url }}:</strong>
        <pre>{{ content }}</pre>
    </div>
    {% endif %}
    <p class="hint">💡 Hint: What internal services might be running on this server?</p>
    <p class="hint">📖 Try: <code>/api/endpoints</code> to see available API routes.</p>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    content = None
    error = None
    url = None
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme or "http")
    forwarded_host = request.headers.get("X-Forwarded-Host")
    raw_host = (forwarded_host.split(",")[0].strip() if forwarded_host else request.host)
    portal_host = raw_host.split(":")[0]
    portal_url = f"{scheme}://{portal_host}/"
    if request.method == "POST":
        url = request.form.get("url", "")
        if url:
            try:
                # VULNERABLE: No URL validation or blocklist for internal IPs
                resp = requests.get(url, timeout=5, allow_redirects=True)
                content = resp.text[:5000]  # Limit output size
            except requests.exceptions.RequestException as e:
                error = f"Failed to fetch URL: {e}"
    return render_template_string(HTML_TEMPLATE, content=content, error=error, url=url, portal_url=portal_url)


@app.route("/api/endpoints")
def api_endpoints():
    """Public endpoint listing available APIs"""
    return jsonify({
        "public": ["/", "/api/endpoints", "/healthz"],
        "internal": ["This service also has internal endpoints not meant for public access..."]
    })


@app.route("/internal/status")
def internal_status():
    """Internal status endpoint - should not be accessible from outside"""
    return jsonify({
        "status": "running",
        "internal": True,
        "hint": "You found an internal endpoint! Can you find the flag?"
    })


@app.route("/internal/admin")
def internal_admin():
    """Internal admin endpoint with the flag"""
    # Check if request comes from localhost (SSRF would bypass this conceptually,
    # but we're simulating the "internal only" nature by just having it exist)
    return jsonify({
        "admin": True,
        "flag": FLAG,
        "message": "Congratulations! You accessed the internal admin panel via SSRF!"
    })


@app.route("/flag")
def flag_direct():
    """Direct flag endpoint - only accessible via SSRF from localhost"""
    # In a real scenario, this would check for internal IPs
    # For the CTF, we allow it to demonstrate the concept
    return jsonify({"flag": FLAG})


@app.route("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
