from flask import Flask, render_template, request, session, flash, redirect, url_for
import os
from urllib.parse import urlparse

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-me")

LOGIN_URL = os.getenv("LOGIN_URL")
JWT_URL = os.getenv("JWT_URL")
STATIC_URL = os.getenv("STATIC_URL")
CMD_INJECTION_URL = os.getenv("CMD_INJECTION_URL")
SSRF_URL = os.getenv("SSRF_URL")
XXE_URL = os.getenv("XXE_URL")
BREAKOUT_URL = os.getenv("BREAKOUT_URL")
DESERIALIZATION_URL = os.getenv("DESERIALIZATION_URL")
JWT_CONFUSION_URL = os.getenv("JWT_CONFUSION_URL")

# Expected flags (can be overridden via environment)
EXPECTED_LOGIN_FLAG = os.getenv("EXPECTED_LOGIN_FLAG", "CTF{pwned_admin_via_sqli}")
EXPECTED_JWT_FLAG = os.getenv("EXPECTED_JWT_FLAG", "CTF{jwt_role_escalation}")
EXPECTED_STATIC_FLAG = os.getenv("EXPECTED_STATIC_FLAG", "CTF{follow_the_robots}")
EXPECTED_CMD_INJECTION_FLAG = os.getenv("EXPECTED_CMD_INJECTION_FLAG", "CTF{rce_through_ping}")
EXPECTED_SSRF_FLAG = os.getenv("EXPECTED_SSRF_FLAG", "CTF{ssrf_metadata_leak}")
EXPECTED_XXE_FLAG = os.getenv("EXPECTED_XXE_FLAG", "CTF{xxe_file_disclosure}")
EXPECTED_SSH_FLAG = os.getenv("EXPECTED_SSH_FLAG", "CTF{brute_force_victory}")
EXPECTED_BREAKOUT_FLAG = os.getenv("EXPECTED_BREAKOUT_FLAG", "CTF{host_root_pwn}")
EXPECTED_DESERIALIZATION_FLAG = os.getenv("EXPECTED_DESERIALIZATION_FLAG", "CTF{pickle_rce_pwn}")
EXPECTED_JWT_CONFUSION_FLAG = os.getenv("EXPECTED_JWT_CONFUSION_FLAG", "CTF{algorithm_confusion_wins}")

CHALLENGES = [
    # Beginner
    {"id": "login-sqli", "name": "Onveilige login (SQLi)", "flag": EXPECTED_LOGIN_FLAG, "level": "beginner"},
    {"id": "jwt-weak", "name": "Zwakke JWT", "flag": EXPECTED_JWT_FLAG, "level": "beginner"},
    {"id": "static-secrets", "name": "Statische geheimen", "flag": EXPECTED_STATIC_FLAG, "level": "beginner"},
    # Medium
    {"id": "command-injection", "name": "Command Injection", "flag": EXPECTED_CMD_INJECTION_FLAG, "level": "medium"},
    {"id": "ssrf-internal", "name": "SSRF Internal", "flag": EXPECTED_SSRF_FLAG, "level": "medium"},
    {"id": "xxe-injection", "name": "XML XXE", "flag": EXPECTED_XXE_FLAG, "level": "medium"},
    {"id": "brute-ssh", "name": "SSH Brute Force", "flag": EXPECTED_SSH_FLAG, "level": "medium"},
    # Hard
    {"id": "container-breakout", "name": "Container Breakout", "flag": EXPECTED_BREAKOUT_FLAG, "level": "hard"},
    {"id": "hard-deserialization", "name": "Pickle Deserialization RCE", "flag": EXPECTED_DESERIALIZATION_FLAG, "level": "hard"},
    {"id": "hard-jwt-confusion", "name": "JWT Algorithm Confusion", "flag": EXPECTED_JWT_CONFUSION_FLAG, "level": "hard"},
]


@app.route("/", methods=["GET", "POST"])
def index():
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme or "http")
    parsed = urlparse(request.host_url)
    host = parsed.hostname or request.host.split(":")[0]

    login_url = LOGIN_URL or f"{scheme}://{host}:8001"
    jwt_url = JWT_URL or f"{scheme}://{host}:8002"
    static_url = STATIC_URL or f"{scheme}://{host}:8003"
    cmd_injection_url = CMD_INJECTION_URL or f"{scheme}://{host}:8004"
    ssrf_url = SSRF_URL or f"{scheme}://{host}:8005"
    xxe_url = XXE_URL or f"{scheme}://{host}:8006"
    breakout_url = BREAKOUT_URL or f"{scheme}://{host}:8007"
    deserialization_url = DESERIALIZATION_URL or f"{scheme}://{host}:8008"
    jwt_confusion_url = JWT_CONFUSION_URL or f"{scheme}://{host}:8009"
    ssh_info = f"{host}"  # SSH connection info

    solved = set(session.get("solved", []))

    if request.method == "POST":
        submitted = (request.form.get("flag") or "").strip()
        if submitted:
            matched = next((c for c in CHALLENGES if submitted == c["flag"]), None)
            if matched:
                solved.add(matched["id"])
                session["solved"] = list(solved)
                flash(f"Proficiat! Je hebt '{matched['name']}' opgelost.", "ok")
            else:
                flash("Helaas, deze key is niet correct. Probeer opnieuw.", "fail")
        return redirect(url_for("index"))

    return render_template(
        "home.html",
        login_url=login_url,
        jwt_url=jwt_url,
        static_url=static_url,
        cmd_injection_url=cmd_injection_url,
        ssrf_url=ssrf_url,
        xxe_url=xxe_url,
        breakout_url=breakout_url,
        deserialization_url=deserialization_url,
        jwt_confusion_url=jwt_confusion_url,
        ssh_info=ssh_info,
        solved=solved,
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/solutions")
def solutions():
    return render_template("solutions.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
