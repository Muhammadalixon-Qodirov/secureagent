import sqlite3

from flask import Blueprint, Flask, abort, jsonify, request
from flask_login import current_user, login_required

bp = Blueprint("reports", __name__, url_prefix="/orgs/<int:org_id>")


def conn():
    return sqlite3.connect("reports.db")


def is_member(org_id, user_id):
    row = conn().execute(
        "SELECT 1 FROM members WHERE org_id = ? AND user_id = ?", (org_id, user_id)
    ).fetchone()
    return row is not None


@bp.get("/reports")
@login_required
def org_reports(org_id):
    if not is_member(org_id, current_user.id):
        abort(403)
    order = request.args.get("order", "created")
    rows = conn().execute(
        "SELECT id, title FROM reports WHERE org_id = ? ORDER BY " + order, (org_id,)
    ).fetchall()
    return jsonify(rows)


@bp.get("/reports/<int:report_id>")
@login_required
def org_report(org_id, report_id):
    if not is_member(org_id, current_user.id):
        abort(403)
    row = conn().execute("SELECT id, title, body FROM reports WHERE id = ?", (report_id,)).fetchone()
    if row is None:
        abort(404)
    return jsonify({"id": row[0], "title": row[1], "body": row[2]})


@bp.post("/reports/<int:report_id>/archive")
@login_required
def archive(org_id, report_id):
    if not is_member(org_id, current_user.id):
        abort(403)
    c = conn()
    c.execute("UPDATE reports SET archived = 1 WHERE id = ? AND org_id = ?", (report_id, org_id))
    c.commit()
    return "", 204


app = Flask(__name__)
app.register_blueprint(bp)
