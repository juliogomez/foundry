import sqlite3
from datetime import date
from flask import Flask, request, jsonify
app = Flask(__name__)

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect('orders.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/orders/count')
def count_orders():
    n, = get_db().execute('SELECT COUNT(*) FROM orders').fetchone()
    return jsonify({'count': n})

@app.route('/orders/report')
def orders_report():
    status = request.args.get('status')
    customer = request.args.get('customer')
    since = request.args.get('since')
    if since is not None:
        try:
            date.fromisoformat(since)
        except ValueError:
            return (jsonify({'error': "Invalid 'since' date; expected YYYY-MM-DD"}), 400)
    conditions = []
    params = []
    if status is not None:
        conditions.append('status = ?')
        params.append(status)
    if customer is not None:
        conditions.append('customer = ?')
        params.append(customer)
    if since is not None:
        conditions.append('date >= ?')
        params.append(since)
    sql = 'SELECT * FROM orders'
    if conditions:
        sql += ' WHERE ' + ' AND '.join(conditions)
    rows = get_db().execute(sql, params).fetchall()
    return jsonify([dict(row) for row in rows])
