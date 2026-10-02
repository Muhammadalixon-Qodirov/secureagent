# Semgrep rule tests for rules/flask-taint.yaml (synthetic, project-authored).
# `ruleid:` = the next line must be reported, `ok:` = it must not.
# These fixtures are for rule development only and are never used in evaluation.
import os
import sqlite3
import subprocess

from flask import Flask, request, send_file, send_from_directory
from markupsafe import Markup
from sqlalchemy import text
from werkzeug.utils import secure_filename

app = Flask(__name__)
db = sqlite3.connect(":memory:")


@app.get("/notes")
def notes():
    q = request.args.get("q", "")
    # ruleid: flask-sqli-string-built-query
    db.execute(f"SELECT id FROM notes WHERE title = '{q}'")
    # ok: flask-sqli-string-built-query
    db.execute("SELECT id FROM notes WHERE title = ?", (q,))
    # ok: flask-sqli-string-built-query
    db.execute("SELECT id FROM notes WHERE title LIKE ?", (f"%{q}%",))
    return "ok"


@app.get("/notes/<note_id>")
def note(note_id):
    # ruleid: flask-sqli-string-built-query
    db.execute("SELECT * FROM notes WHERE id = " + note_id)
    # ok: flask-sqli-string-built-query
    db.execute("SELECT * FROM notes WHERE id = %d" % int(note_id))
    return "ok"


@app.get("/search")
def search(session):
    order = request.args.get("order", "")
    # ruleid: flask-sqli-string-built-query
    session.execute(text("SELECT * FROM notes ORDER BY " + order))
    # ok: flask-sqli-string-built-query
    session.execute(text("SELECT * FROM notes WHERE id = :id"), {"id": request.args["id"]})
    return "ok"


@app.get("/reports/<path:name>")
def report(name):
    # ruleid: flask-path-traversal-file-access
    return send_file(os.path.join("/srv/reports", name))


@app.get("/reports2/<path:name>")
def report2(name):
    # ok: flask-path-traversal-file-access
    return send_from_directory("/srv/reports", name)


@app.post("/upload")
def upload():
    f = request.files["file"]
    # ruleid: flask-path-traversal-file-access
    with open(os.path.join("/srv/uploads", f.filename), "wb") as out:
        out.write(f.read())
    # ok: flask-path-traversal-file-access
    with open(os.path.join("/srv/uploads", secure_filename(f.filename)), "wb") as out:
        out.write(f.read())
    return "ok"


@app.post("/ping")
def ping():
    host = request.form["host"]
    # ruleid: flask-command-injection-shell
    subprocess.run(f"ping -c 1 {host}", shell=True)
    # ok: flask-command-injection-shell
    subprocess.run(["ping", "-c", "1", "--", host])
    # ruleid: flask-command-injection-shell
    os.system("ping -c 1 " + host)
    return "ok"


@app.get("/hello")
def hello():
    name = request.args.get("name", "")
    # ruleid: flask-xss-markup-on-request-data
    banner = Markup("<b>" + name + "</b>")
    # ok: flask-xss-markup-on-request-data
    title = Markup("<b>Welcome</b>")
    return str(banner) + str(title)
