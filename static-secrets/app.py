from flask import Flask, send_from_directory, render_template, request
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
FLAG = os.getenv("FLAG", "CTF{follow_the_robots}")

app = Flask(__name__, static_folder=str(STATIC_DIR))


def get_portal_url() -> str:
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme or "http")
    forwarded_host = request.headers.get("X-Forwarded-Host")
    raw_host = (forwarded_host.split(",")[0].strip() if forwarded_host else request.host)
    portal_host = raw_host.split(":")[0]
    return f"{scheme}://{portal_host}/"


@app.get("/")
def index():
    return render_template("index.html", portal_url=get_portal_url())


@app.get("/robots.txt")
def robots():
    return send_from_directory(app.static_folder, "robots.txt")


@app.get("/config.bak")
def config_bak():
    return send_from_directory(app.static_folder, "config.bak")


@app.get("/hidden/")
def hidden_index():
    hidden_dir = Path(app.static_folder) / "hidden"
    if not hidden_dir.exists():
        return "Not found", 404
    files = sorted([p.name for p in hidden_dir.iterdir() if p.is_file()])
    items = "\n".join(f'<li><a href="/hidden/{name}">{name}</a></li>' for name in files)
    html = f"""<!doctype html><html lang=\"nl\"><head><meta charset=\"utf-8\"><title>Index of /hidden/</title></head>
    <body><h1>Index of /hidden/</h1><ul>{items}</ul></body></html>"""
    return html


@app.get("/hidden/<path:filename>")
def hidden_file(filename: str):
    return send_from_directory(Path(app.static_folder) / "hidden", filename)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


# Expose a dynamic endpoint to show the current FLAG value for test purposes (commented out)
# @app.get("/debug-flag")
# def debug_flag():
#     return {"flag": FLAG}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
