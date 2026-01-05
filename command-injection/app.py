"""
Command Injection CTF Challenge (Medium)
Vulnerability: OS command injection via unsanitized ping input
"""
from flask import Flask, request, render_template_string
import subprocess
import os

app = Flask(__name__)
FLAG = os.getenv("FLAG", "CTF{rce_through_ping}")

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Network Diagnostic Tool</title>
    <style>
        :root { color-scheme: light dark; }
        body { font-family: system-ui, sans-serif; max-width: 700px; margin: 2rem auto; padding: 0 1rem; }
        h1 { color: #2563eb; }
        form { margin: 1.5rem 0; }
        input[type="text"] { padding: 0.6rem 0.7rem; width: 320px; border: 1px solid #cbd5e1; border-radius: 8px; }
        input[type="text"]:focus-visible, button:focus-visible { outline: 3px solid #93c5fd; outline-offset: 2px; }
        button { padding: 0.6rem 1rem; background: #2563eb; color: white; border: 1px solid #1d4ed8; border-radius: 8px; cursor: pointer; font-weight:600; }
        button:hover { background: #1d4ed8; }
        pre { background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; }
        .hint { color: #6b7280; font-size: 0.9rem; margin-top: 1rem; }
        a.back { color:#2563eb; text-decoration:none; }
        a.back:hover { text-decoration:underline; }
        @media (prefers-color-scheme: dark) {
            body { background: #0f172a; color: #e2e8f0; }
            h1 { color: #60a5fa; }
            input { background: #1e293b; color: #e2e8f0; border-color: #334155; }
        }
    </style>
</head>
<body>
    <p><a class="back" href="{{ portal_url }}">← Terug naar portaal</a></p>
    <h1>🔧 Network Diagnostic Tool</h1>
    <p>Enter a hostname or IP address to ping:</p>
    <form method="POST">
        <input type="text" name="host" placeholder="e.g., 8.8.8.8" value="{{ host or '' }}" required>
        <button type="submit">Ping</button>
    </form>
    {% if output %}
    <h3>Result:</h3>
    <pre>{{ output }}</pre>
    {% endif %}
    <p class="hint">💡 Hint: Network admins often chain commands together...</p>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    output = None
    host = None
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme or "http")
    forwarded_host = request.headers.get("X-Forwarded-Host")
    raw_host = (forwarded_host.split(",")[0].strip() if forwarded_host else request.host)
    portal_host = raw_host.split(":")[0]
    portal_url = f"{scheme}://{portal_host}/"
    if request.method == "POST":
        host = request.form.get("host", "")
        if host:
            # VULNERABLE: Direct shell command execution with user input
            # In real apps, NEVER do this!
            try:
                # Using shell=True makes this exploitable
                result = subprocess.run(
                    f"ping -c 2 {host}",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                output = result.stdout + result.stderr
            except subprocess.TimeoutExpired:
                output = "Command timed out"
            except Exception as e:
                output = f"Error: {e}"
    return render_template_string(HTML_TEMPLATE, output=output, host=host, portal_url=portal_url)


@app.route("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    # Write flag to /flag.txt for the challenge
    with open("/flag.txt", "w") as f:
        f.write(FLAG)
    app.run(host="0.0.0.0", port=5000, debug=False)
