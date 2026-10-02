import sqlite3

from flask import Flask, abort, g, jsonify, request, send_file, send_from_directory
from flask_login import current_user, login_required

app = Flask(__name__)
COVERS = "/var/bookshelf/covers"
EXPORT_ROOT = "/var/bookshelf/exports"


def db():
    if "db" not in g:
        g.db = sqlite3.connect("bookshelf.db")
    return g.db


@app.get("/books")
def list_books():
    author = request.args.get("author", "")
    rows = db().execute("SELECT id, title FROM books WHERE author = '{}'".format(author)).fetchall()
    return jsonify(rows)


@app.get("/books/count")
def count_books():
    year = int(request.args.get("year", "2000"))
    row = db().execute("SELECT COUNT(*) FROM books WHERE year = %d" % year).fetchone()
    return jsonify(row[0])


@app.get("/covers/<path:filename>")
def cover(filename):
    return send_from_directory(COVERS, filename)


@app.get("/exports/download")
@login_required
def download_export():
    name = request.args.get("name", "")
    return send_file(EXPORT_ROOT + "/" + name)


@app.get("/loans/<int:loan_id>")
@login_required
def loan(loan_id):
    row = db().execute("SELECT id, borrower_id, book_id, due FROM loans WHERE id = ?", (loan_id,)).fetchone()
    if row is None or row[1] != current_user.id:
        abort(404)
    return jsonify({"id": row[0], "book": row[2], "due": row[3]})


@app.post("/loans/<int:loan_id>/renew")
@login_required
def renew(loan_id):
    db().execute("UPDATE loans SET due = date(due, '+14 days') WHERE id = ?", (loan_id,))
    db().commit()
    return "", 204
