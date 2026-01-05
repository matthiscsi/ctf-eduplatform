"""
JWT Algorithm Confusion CTF Challenge (Hard)
Vulnerability: Algorithm confusion / key confusion attack on JWT tokens
Objective: Forge a JWT token by exploiting algorithm confusion (HS256 vs RS256)
"""
from flask import Flask, request, jsonify
import jwt
import os
from datetime import datetime, timedelta

app = Flask(__name__)

# The public key (which is also the HS256 secret - this is the vulnerability)
PUBLIC_KEY = os.getenv("PUBLIC_KEY", "very-secret-symmetric-key-9999")
FLAG = os.getenv("FLAG", "CTF{algorithm_confusion_wins}")

# JWT secret that should be used
JWT_SECRET = PUBLIC_KEY


@app.get("/")
def index():
    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>JWT Token Service</title>
        <style>
            :root { color-scheme: light dark; }
            body { font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1f2937; }
            @media (prefers-color-scheme: dark) { body { color: #e5e7eb; background: #0b1220; } }
            h1 { color: #2563eb; }
            @media (prefers-color-scheme: dark) { h1 { color: #60a5fa; } }
            .card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 1.5rem; background: #ffffff; margin: 1rem 0; }
            @media (prefers-color-scheme: dark) { .card { background: #111827; border-color: #263247; } }
            input, textarea, select { width: 100%; padding: 0.6rem 0.7rem; margin: 0.5rem 0 1rem 0; border: 1px solid #cbd5e1; border-radius: 8px; font-family: inherit; }
            @media (prefers-color-scheme: dark) { input, textarea, select { background: #1e293b; color: #e2e8f0; border-color: #334155; } }
            button { padding: 0.6rem 1rem; background: #2563eb; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; }
            button:hover { background: #1e40af; }
            code { background: #f3f4f6; color: #111827; padding: 0.2rem 0.4rem; border-radius: 4px; }
            @media (prefers-color-scheme: dark) { code { background: #1e293b; color: #e2e8f0; } }
            pre { background: #0f172a; color: #e2e8f0; padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: 0.85rem; }
            .hint { color: #6b7280; font-size: 0.9rem; margin: 1rem 0; }
        </style>
    </head>
    <body>
        <h1>🔐 JWT Token Service</h1>
        
        <div class="card">
            <h2>1. Generate JWT Token</h2>
            <p class="hint">Generate a regular user token:</p>
            <form method="post" action="/token">
                <label>Username:</label>
                <input type="text" name="username" placeholder="john_doe" required>
                
                <label>Role:</label>
                <select name="role">
                    <option>user</option>
                    <option>admin</option>
                </select>
                
                <button type="submit">Generate Token</button>
            </form>
        </div>

        <div class="card">
            <h2>2. Verify JWT Token</h2>
            <p class="hint">Paste a JWT token to verify it and access admin functionality:</p>
            <form method="post" action="/verify">
                <label>JWT Token:</label>
                <textarea name="token" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." required></textarea>
                
                <button type="submit">Verify & Access Admin</button>
            </form>
        </div>

        <div class="card">
            <h2>3. Attack: Algorithm Confusion</h2>
            <p class="hint">
                ⚠️ <strong>Vulnerability:</strong> Service accepts both HS256 and RS256 algorithms<br>
                🎯 <strong>Goal:</strong> Forge a token with role=admin using HS256 and public key as secret<br>
                💡 <strong>Hint:</strong> The public key is exposed at /public-key
            </p>
        </div>
    </body>
    </html>
    """
    return html


@app.route("/token", methods=["POST"])
def generate_token():
    """
    Generate a JWT token with user role
    Uses HS256 algorithm
    """
    username = request.form.get("username", "guest")
    role = request.form.get("role", "user")

    payload = {
        "sub": username,
        "role": role,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=24)
    }

    # Sign with HS256
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    return jsonify({
        "status": "success",
        "token": token,
        "payload": {
            "username": username,
            "role": role,
            "message": "Use this token to access admin endpoints"
        }
    })


@app.route("/verify", methods=["POST"])
def verify_token():
    """
    VULNERABLE: Verifies JWT token but accepts both HS256 and RS256
    This allows algorithm confusion attack
    """
    token = request.form.get("token", "").strip()

    if not token:
        return jsonify({"error": "Missing token"}), 400

    try:
        # VULNERABLE: Try to decode with both algorithms
        # In production, should ONLY accept one algorithm
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256", "RS256"])

        # Check role
        role = data.get("role", "user")

        if role == "admin":
            return jsonify({
                "status": "verified",
                "username": data.get("sub"),
                "role": role,
                "flag": FLAG,
                "message": "Welcome admin! Here's your flag."
            })
        else:
            return jsonify({
                "status": "verified",
                "username": data.get("sub"),
                "role": role,
                "message": "You need admin role to access the flag"
            })

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidSignatureError:
        return jsonify({"error": "Invalid token signature"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 401


@app.get("/public-key")
def public_key_endpoint():
    """
    Endpoint that exposes the public key
    In real scenarios, attackers might find this through source code or similar
    """
    return jsonify({
        "public_key": PUBLIC_KEY,
        "algorithm": "RS256",
        "message": "This key is used to verify JWT tokens"
    })


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    with open("/flag.txt", "w") as f:
        f.write(FLAG)
    app.run(host="0.0.0.0", port=5000, debug=False)
