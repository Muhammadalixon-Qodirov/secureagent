from database import get_conn


def patients_by_ward(ward):
    sql = f"SELECT id, name FROM patients WHERE ward = '{ward}'"
    return get_conn().execute(sql).fetchall()


def patient_by_id(patient_id):
    return get_conn().execute(
        "SELECT id, name, doctor_id, notes FROM patients WHERE id = ?", (patient_id,)
    ).fetchone()


def search_patients(term):
    return get_conn().execute(
        "SELECT id, name FROM patients WHERE name LIKE ?", ("%" + term + "%",)
    ).fetchall()
