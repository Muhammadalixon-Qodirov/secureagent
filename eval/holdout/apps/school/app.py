from flask import Flask, abort, jsonify, request, send_from_directory
from flask_login import current_user, login_required
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy(app)
ATTACHMENTS = "/srv/school/attachments"


class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    phone = db.Column(db.String(30))
    address = db.Column(db.String(200))


class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, nullable=False)


class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"))
    course = db.relationship(Course)
    student_id = db.Column(db.Integer)
    score = db.Column(db.Integer)


ORDERABLE = {"name": Student.name, "id": Student.id}


@app.get("/students")
@login_required
def students():
    column = ORDERABLE.get(request.args.get("order", "name"), Student.name)
    return jsonify([s.name for s in Student.query.order_by(column).all()])


@app.get("/grades/<int:student_id>")
@login_required
def grades(student_id):
    if current_user.role != "teacher" and current_user.id != student_id:
        abort(403)
    rows = Assignment.query.filter_by(student_id=student_id).all()
    return jsonify([{"id": a.id, "score": a.score} for a in rows])


@app.get("/students/<int:student_id>/contact")
@login_required
def contact(student_id):
    s = db.get_or_404(Student, student_id)
    return jsonify({"phone": s.phone, "address": s.address})


@app.post("/assignments/<int:aid>/grade")
@login_required
def grade(aid):
    a = db.get_or_404(Assignment, aid)
    if current_user.role != "teacher" or a.course.teacher_id != current_user.id:
        abort(403)
    a.score = int(request.form["score"])
    db.session.commit()
    return "", 204


@app.get("/attachments/<path:name>")
@login_required
def attachment(name):
    return send_from_directory(ATTACHMENTS, name)
