import os
import sqlite3
from functools import wraps

from flask import Flask, abort, g, jsonify, request, session

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]


def conn():
    if "conn" not in g:
        g.conn = sqlite3.connect("tickets.db")
    return g.conn


def current_user_id():
    uid = session.get("uid")
    if uid is None:
        abort(401)
    return uid


def ticket_owner_required(view):
    @wraps(view)
    def wrapper(ticket_id, *args, **kwargs):
        row = conn().execute("SELECT owner_id FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if row is None or row[0] != current_user_id():
            abort(404)
        return view(ticket_id, *args, **kwargs)
    return wrapper


@app.get("/tickets/<int:ticket_id>")
@ticket_owner_required
def ticket(ticket_id):
    row = conn().execute("SELECT id, title, body FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    return jsonify({"id": row[0], "title": row[1], "body": row[2]})


@app.post("/tickets/<int:ticket_id>/close")
def close_ticket(ticket_id):
    current_user_id()
    conn().execute("UPDATE tickets SET status = 'closed' WHERE id = ?", (ticket_id,))
    conn().commit()
    return "", 204


@app.get("/tickets/by-user")
def tickets_by_user():
    current_user_id()
    uid = request.args.get("user_id")
    rows = conn().execute("SELECT id, title FROM tickets WHERE owner_id = ?", (uid,)).fetchall()
    return jsonify(rows)


@app.get("/tickets/search")
def search():
    uid = current_user_id()
    q = request.args.get("q", "")
    rows = conn().execute(
        "SELECT id, title FROM tickets WHERE owner_id = ? AND title LIKE '%" + q + "%'", (uid,)
    ).fetchall()
    return jsonify(rows)


@app.get("/tickets/stats")
def stats():
    uid = current_user_id()
    states = request.args.getlist("state")
    marks = ",".join("?" * len(states))
    rows = conn().execute(
        f"SELECT state, COUNT(*) FROM tickets WHERE owner_id = ? AND state IN ({marks}) GROUP BY state",
        (uid, *states),
    ).fetchall()
    return jsonify(rows)
