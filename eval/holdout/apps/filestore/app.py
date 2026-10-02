import os
from pathlib import Path

from flask import Flask, abort, request, send_file
from werkzeug.security import safe_join
from werkzeug.utils import secure_filename

app = Flask(__name__)
STORAGE = Path("/srv/files/storage")
TEMPLATES_DIR = "/srv/files/templates"
ARCHIVE_DIR = "/srv/files/archive"


@app.post("/upload")
def upload():
    f = request.files["file"]
    target = STORAGE / secure_filename(f.filename)
    f.save(target)
    return {"saved": target.name}


@app.get("/template")
def template():
    name = request.args.get("name", "")
    path = safe_join(TEMPLATES_DIR, name)
    if path is None or not os.path.isfile(path):
        abort(404)
    return send_file(path)


@app.get("/preview")
def preview():
    name = request.args.get("name", "")
    return (STORAGE / name).read_text(encoding="utf-8")


@app.delete("/files/<path:name>")
def delete(name):
    full = os.path.normpath(os.path.join(STORAGE, name))
    os.remove(full)
    return "", 204


@app.get("/archive/<path:name>")
def archive(name):
    base = os.path.realpath(ARCHIVE_DIR)
    full = os.path.realpath(os.path.join(base, name))
    if not full.startswith(base):
        abort(403)
    return send_file(full)
