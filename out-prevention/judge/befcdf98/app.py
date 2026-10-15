import re
import sqlite3
from flask import Flask, request, jsonify
app = Flask(__name__)

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect('orders.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/orders/report')
def orders_report():
    status = request.args.get('status')
    customer = request.args.get('customer')
    since = request.args.get('since')
    if since is not None and (not re.fullmatch('\\d{4}-\\d{2}-\\d{2}', since)):
        return (jsonify({'error': "Invalid 'since' value; expected YYYY-MM-DD"}), 400)
    conditions: list[str] = []
    params: list[object] = []
    if status is not None:
        conditions.append('status = ?')
        params.append(status)
    if customer is not None:
        conditions.append('customer = ?')
        params.append(customer)
    if since is not None:
        conditions.append('date >= ?')
        params.append(since)
    query = 'SELECT * FROM orders'
    if conditions:
        query += ' WHERE ' + ' AND '.join(conditions)
    rows = get_db().execute(query, params).fetchall()
    return jsonify([dict(row) for row in rows])

@app.route('/orders/count')
def count_orders():
    n, = get_db().execute('SELECT COUNT(*) FROM orders').fetchone()
    return jsonify({'count': n})
