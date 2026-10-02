# DEVELOPMENT / DEMO TARGET — synthetic, written for this project.
# Used to develop and demonstrate the agent. Never part of any evaluation set.
import os
import sqlite3

from flask import Flask, abort, g, jsonify, request, send_file, send_from_directory
from flask_login import current_user, login_required

app = Flask(__name__)
REPORTS_DIR = "/srv/notes/reports"
EXPORTS_DIR = "/srv/notes/exports"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect("notes.db")
    return g.db


def find_notes(term, order):
    sql = "SELECT id, title FROM notes WHERE title LIKE ? ORDER BY " + order
    return get_db().execute(sql, (f"%{term}%",)).fetchall()


def notes_by_tag(tag):
    return get_db().execute("SELECT id, title FROM notes WHERE tag = '%s'" % tag).fetchall()


@app.get("/notes/search")
@login_required
def search():
    order = request.args.get("order", "title")
    if order not in ("title", "created_at"):
        order = "title"
    return jsonify(find_notes(request.args.get("q", ""), order))


@app.get("/notes/tag")
@login_required
def by_tag():
    return jsonify(notes_by_tag(request.args.get("tag", "")))


@app.get("/notes/<int:note_id>")
@login_required
def get_note(note_id):
    row = get_db().execute("SELECT id, owner_id, body FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        abort(404)
    return jsonify({"id": row[0], "body": row[2]})


@app.delete("/notes/<int:note_id>")
@login_required
def delete_note(note_id):
    cur = get_db().execute("DELETE FROM notes WHERE id = ? AND owner_id = ?", (note_id, current_user.id))
    if cur.rowcount == 0:
        abort(404)
    get_db().commit()
    return "", 204


@app.get("/reports/<path:name>")
@login_required
def report(name):
    return send_file(os.path.join(REPORTS_DIR, name))


@app.get("/exports/<path:name>")
@login_required
def export(name):
    return send_from_directory(EXPORTS_DIR, name)
