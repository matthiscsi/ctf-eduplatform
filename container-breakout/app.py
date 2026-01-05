"""
Container Breakout CTF Challenge (Hard/Hacking God)
Vulnerability: SSRF + Docker API exploitation
Objective: Use SSRF to access Docker API and break out of container via bind-mount
"""
from flask import Flask, request, jsonify
import os
import requests
from pathlib import Path

app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))

FLAG = os.getenv("FLAG", "CTF{host_root_pwn}")
DIND_HOST = os.getenv("DIND_HOST", "http://dind-host:2375")


@app.get("/")
def index():
    # Return simple HTML response instead of using templates for testing
    html = f"""
    <!doctype html>
    <html>
    <head><title>Container Breakout</title></head>
    <body>
        <h1>Container Breakout Challenge</h1>
        <p>Docker API endpoint: {DIND_HOST}</p>
        <form method="post" action="/fetch">
            <input type="text" name="url" placeholder="http://dind-host:2375/_ping" required>
            <button>Fetch</button>
        </form>
    </body>
    </html>
    """
    return html


@app.route("/fetch", methods=["GET", "POST"])
def fetch():
    """
    VULNERABLE: SSRF endpoint that fetches arbitrary URLs
    Used to interact with the Docker API on the internal DIND host
    """
    url = request.values.get("url", "").strip()
    method = (request.values.get("method", "GET") or "GET").upper()
    headers = {}
    if request.values.get("content_type") == "json":
        headers["Content-Type"] = "application/json"
    body = request.values.get("body")

    if not url:
        return jsonify({"error": "missing url"}), 400

    try:
        if method == "POST":
            resp = requests.post(url, data=body, headers=headers, timeout=10)
        elif method == "PUT":
            resp = requests.put(url, data=body, headers=headers, timeout=10)
        elif method == "DELETE":
            resp = requests.delete(url, headers=headers, timeout=10)
        else:
            resp = requests.get(url, headers=headers, timeout=10)
    except Exception as e:
        return jsonify({"error": str(e)}), 502

    content = resp.text
    return (
        content,
        resp.status_code,
        {"Content-Type": resp.headers.get("Content-Type", "text/plain; charset=utf-8")},
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
