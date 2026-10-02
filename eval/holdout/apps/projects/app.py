from flask import Flask, abort, jsonify, request
from flask_login import current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__)
db = SQLAlchemy(app)


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(120))
    budget = db.Column(db.Integer)
    status = db.Column(db.String(20))


SORTABLE = {"name": Project.name, "budget": Project.budget}


@app.get("/projects")
@login_required
def projects():
    column = SORTABLE.get(request.args.get("sort"), Project.name)
    rows = Project.query.filter_by(owner_id=current_user.id).order_by(column).all()
    return jsonify([p.name for p in rows])


@app.get("/projects/report")
@login_required
def report():
    status = request.args.get("status", "open")
    stmt = text(f"SELECT name, budget FROM project WHERE status = '{status}' AND owner_id = :uid")
    rows = db.session.execute(stmt, {"uid": current_user.id}).fetchall()
    return jsonify([list(r) for r in rows])


@app.get("/projects/<int:pid>")
@login_required
def project(pid):
    p = db.session.get(Project, pid)
    if p is None:
        abort(404)
    return jsonify({"name": p.name, "budget": p.budget})


@app.patch("/projects/<int:pid>")
@login_required
def rename(pid):
    p = Project.query.filter_by(id=pid, owner_id=current_user.id).first_or_404()
    p.name = request.json["name"]
    db.session.commit()
    return "", 204
