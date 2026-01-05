"""
Deserialization RCE CTF Challenge (Hard)
Vulnerability: Python pickle deserialization leading to Remote Code Execution
Objective: Craft a malicious serialized object to execute arbitrary code
"""
from flask import Flask, request, jsonify
import pickle
import base64
import os

app = Flask(__name__)

FLAG = os.getenv("FLAG", "CTF{pickle_rce_pwn}")

# Intentionally vulnerable pickle deserialization
class UserProfile:
    def __init__(self, username, email):
        self.username = username
        self.email = email


@app.get("/")
def index():
    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>User Profile Serializer</title>
        <style>
            :root { color-scheme: light dark; }
            body { font-family: system-ui, sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
            h1 { color: #2563eb; }
            .card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 1.5rem; background: #ffffff; margin: 1rem 0; }
            @media (prefers-color-scheme: dark) {
                body { background: #0f172a; color: #e5e7eb; }
                h1 { color: #60a5fa; }
                .card { background: #111827; border-color: #263247; }
            }
            input, textarea { width: 100%; padding: 0.6rem 0.7rem; margin: 0.5rem 0 1rem 0; border: 1px solid #cbd5e1; border-radius: 8px; }
            button { padding: 0.6rem 1rem; background: #2563eb; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; }
            button:hover { background: #1e40af; }
            code { background: #f3f4f6; color: #111827; padding: 0.2rem 0.4rem; border-radius: 4px; }
            @media (prefers-color-scheme: dark) { code { background: #1e293b; color: #e2e8f0; } }
            pre { background: #0f172a; color: #e2e8f0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
            .hint { color: #6b7280; font-size: 0.9rem; margin: 1rem 0; }
        </style>
    </head>
    <body>
        <h1>🔐 User Profile Serializer</h1>
        
        <div class="card">
            <h2>Serialize User Profile</h2>
            <form method="post" action="/serialize">
                <label>Username:</label>
                <input type="text" name="username" placeholder="john_doe" required>
                
                <label>Email:</label>
                <input type="text" name="email" placeholder="john@example.com" required>
                
                <button type="submit">Serialize</button>
            </form>
        </div>

        <div class="card">
            <h2>Deserialize User Profile</h2>
            <p class="hint">⚠️ Paste a base64-encoded serialized object to deserialize:</p>
            <form method="post" action="/deserialize">
                <label>Base64 Serialized Data:</label>
                <textarea name="data" placeholder="gANdcQAoWAQAAAB1c2VyIHE..." required></textarea>
                
                <button type="submit">Deserialize</button>
            </form>
        </div>

        <div class="card">
            <h2>Attack Hints</h2>
            <p class="hint">
                💡 Hint 1: Python's <code>pickle</code> module can deserialize arbitrary objects<br>
                💡 Hint 2: The <code>__reduce__</code> method controls how objects are pickled<br>
                💡 Hint 3: You can craft payloads using pickle or ysoserial<br>
                💡 Hint 4: The flag is at <code>/flag.txt</code>
            </p>
        </div>
    </body>
    </html>
    """
    return html


@app.route("/serialize", methods=["POST"])
def serialize():
    """
    Endpoint to serialize user profiles
    Demonstrates how pickle serialization works
    """
    username = request.form.get("username", "")
    email = request.form.get("email", "")

    if not username or not email:
        return jsonify({"error": "Missing username or email"}), 400

    try:
        # Create and serialize a user profile
        profile = UserProfile(username, email)
        serialized = pickle.dumps(profile)
        encoded = base64.b64encode(serialized).decode()

        return jsonify({
            "status": "serialized",
            "data": encoded,
            "size": len(encoded)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/deserialize", methods=["POST"])
def deserialize():
    """
    VULNERABLE: Deserializes untrusted pickle data
    Attacker can craft malicious serialized objects to achieve RCE
    """
    data = request.form.get("data", "").strip()

    if not data:
        return jsonify({"error": "Missing serialized data"}), 400

    try:
        # VULNERABLE: Deserializing untrusted data with pickle
        decoded = base64.b64decode(data)
        obj = pickle.loads(decoded)  # This can execute arbitrary code!

        # Try to extract username/email if it's a valid UserProfile
        if isinstance(obj, UserProfile):
            return jsonify({
                "status": "deserialized",
                "username": obj.username,
                "email": obj.email
            })
        else:
            return jsonify({
                "status": "deserialized",
                "type": type(obj).__name__,
                "message": "Object deserialized successfully"
            })
    except Exception as e:
        return jsonify({
            "error": str(e),
            "message": "Deserialization failed"
        }), 500


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    # Write flag to file
    with open("/flag.txt", "w") as f:
        f.write(FLAG)
    app.run(host="0.0.0.0", port=5000, debug=False)
