from flask import Flask, request, render_template, redirect, make_response, abort
import os
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "users.db"
FLAG = os.getenv("FLAG", "CTF{pwned_admin_via_sqli}")

app = Flask(__name__)


def get_portal_url() -> str:
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme or "http")
    forwarded_host = request.headers.get("X-Forwarded-Host")
    raw_host = (forwarded_host.split(",")[0].strip() if forwarded_host else request.host)
    portal_host = raw_host.split(":")[0]
    return f"{scheme}://{portal_host}/"


def init_db():
    if DB_PATH.exists():
        return
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT)")
    # Intentionally weak: plaintext passwords, for CTF demo only
    cur.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
    cur.execute("INSERT INTO users (username, password) VALUES ('guest', 'guest')")
    con.commit()
    con.close()


# Initialize database at import-time for compatibility with Flask 3.x
init_db()


@app.get("/")
def home():
    return redirect("/login")


@app.get("/login")
def login_form():
    return render_template("login.html", error=None, portal_url=get_portal_url())


@app.post("/login")
def login_post():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Intentionally vulnerable to SQL injection; do NOT use this in real apps
    query = f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}'"
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    try:
        cur.execute(query)
        row = cur.fetchone()
    except sqlite3.Error:
        row = None
    finally:
        con.close()

    if row:
        resp = make_response(redirect("/flag"))
        resp.set_cookie("user", row[0], httponly=False)
        return resp
    else:
        return render_template("login.html", error="Ongeldige inloggegevens", portal_url=get_portal_url()), 401


@app.get("/flag")
def flag():
    user = request.cookies.get("user")
    if user == "admin":
        return render_template("flag.html", flag=FLAG, portal_url=get_portal_url())
    abort(403)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
