# house-style: v2
"""Orders reporting service."""
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect("orders.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/orders/report")
def orders_report():
    status = request.args.get("status")
    customer = request.args.get("customer")
    since = request.args.get("since")

    query = "SELECT * FROM orders WHERE 1=1"
    params = []

    if status is not None:
        query += " AND status = ?"
        params.append(status)
    if customer is not None:
        query += " AND customer = ?"
        params.append(customer)
    if since is not None:
        query += " AND date >= ?"
        params.append(since)

    rows = get_db().execute(query, params).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/orders/count")
def count_orders():
    (n,) = get_db().execute("SELECT COUNT(*) FROM orders").fetchone()
    return jsonify({"count": n})
