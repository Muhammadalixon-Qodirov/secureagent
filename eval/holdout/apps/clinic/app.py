from flask import Flask, abort, jsonify, request
from flask_login import current_user, login_required

import queries

app = Flask(__name__)


@app.get("/wards/<ward>/patients")
@login_required
def ward_patients(ward):
    return jsonify(queries.patients_by_ward(ward))


@app.get("/patients/search")
@login_required
def search():
    return jsonify(queries.search_patients(request.args.get("q", "")))


@app.get("/patients/<int:patient_id>")
@login_required
def patient(patient_id):
    p = queries.patient_by_id(patient_id)
    if p is None:
        abort(404)
    return jsonify({"id": p[0], "name": p[1], "notes": p[3]})


@app.get("/patients/<int:patient_id>/summary")
@login_required
def patient_summary(patient_id):
    p = queries.patient_by_id(patient_id)
    if p is None or p[2] != current_user.id:
        abort(404)
    return jsonify({"id": p[0], "name": p[1]})
