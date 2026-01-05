from flask import Flask, request, jsonify
import os
import jwt
from datetime import datetime, timedelta
from pathlib import Path

app = Flask(__name__)

SECRET = os.getenv("JWT_SECRET", "secret")
FLAG = os.getenv("FLAG", "CTF{jwt_role_escalation}")


@app.get("/")
def home():
    return jsonify({
        "message": "JWT Zwak Geheim Uitdaging",
        "routes": {
            "GET /login?username=naam": "Ontvang een token voor een gebruiker (rol=user)",
            "GET /admin (Authorization: Bearer <token>)": "Toegang tot admin-vlag met rol=admin",
            "GET /source": "Bekijk de broncode om de app te begrijpen"
        }
    })


@app.get("/login")
def login():
    username = request.args.get("username", "guest")
    payload = {
        "sub": username,
        "role": "user",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=30),
    }
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    return jsonify({"token": token})


@app.get("/admin")
def admin():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Ontbrekende Bearer-token"}), 401
    token = auth.split(" ", 1)[1]
    try:
        data = jwt.decode(token, SECRET, algorithms=["HS256"])
    except Exception as e:
        return jsonify({"error": str(e)}), 401

    if data.get("role") == "admin":
        return jsonify({"flag": FLAG})
    return jsonify({"error": "Alleen beheerders"}), 403


@app.get("/source")
def source():
    code = Path(__file__).read_text(encoding="utf-8")
    return app.response_class(code, mimetype="text/plain")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
