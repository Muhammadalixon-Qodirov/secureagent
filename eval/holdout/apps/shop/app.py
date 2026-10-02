import os

from flask import Flask, abort, jsonify, request, send_file
from flask_login import current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__)
db = SQLAlchemy(app)
INVOICES = "/srv/shop/invoices"


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Integer)

    def to_dict(self):
        return {"id": self.id, "total": self.total}


@app.get("/products")
def products():
    category = request.args.get("category", "")
    stmt = text("SELECT id, name, price FROM products WHERE category = :c")
    return jsonify([dict(r._mapping) for r in db.session.execute(stmt, {"c": category})])


@app.get("/products/top")
def top_products():
    limit = request.args.get("limit", "10")
    rows = db.session.execute(text("SELECT id, name FROM products ORDER BY sales DESC LIMIT " + limit)).fetchall()
    return jsonify([list(r) for r in rows])


@app.get("/orders/<int:order_id>")
@login_required
def order(order_id):
    o = db.get_or_404(Order, order_id)
    if o.customer_id != current_user.id and not current_user.is_admin:
        abort(403)
    return jsonify(o.to_dict())


@app.get("/orders/<int:order_id>/invoice.pdf")
@login_required
def invoice(order_id):
    o = db.get_or_404(Order, order_id)
    return send_file(os.path.join(INVOICES, f"{o.id}.pdf"))
