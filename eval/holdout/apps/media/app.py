import os
import sqlite3

from flask import Flask, abort, g, request, send_file, send_from_directory, session

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
MEDIA = "/srv/media"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect("media.db")
    return g.db


@app.before_request
def require_login():
    if request.endpoint != "health" and "uid" not in session:
        abort(401)


def media_row(media_id):
    return get_db().execute("SELECT id, owner_id, filename FROM media WHERE id = ?", (media_id,)).fetchone()


@app.get("/media/<int:media_id>/download")
def download(media_id):
    row = media_row(media_id)
    if row is None or row[1] != session["uid"]:
        abort(404)
    return send_from_directory(MEDIA, row[2])


@app.get("/media/<int:media_id>/thumb")
def thumb(media_id):
    row = media_row(media_id)
    if row is None:
        abort(404)
    return send_file(os.path.join(MEDIA, "thumbs", f"{row[0]}.jpg"))


@app.get("/media/raw")
def raw():
    name = request.args["name"]
    return send_file(os.path.join(MEDIA, name))


@app.get("/health")
def health():
    return "ok"
