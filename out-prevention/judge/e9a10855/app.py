import sqlite3
from flask import Flask, request, jsonify
app = Flask(__name__)

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn
_ALLOWED_SORT_COLUMNS = {'name', 'created_at', 'email'}

@app.route('/users/search')
def search_users():
    name = request.args.get('name', '')
    sort = request.args.get('sort', 'name')
    if sort not in _ALLOWED_SORT_COLUMNS:
        return (jsonify({'error': 'Invalid sort column'}), 400)
    rows = get_db().execute(f'SELECT * FROM users WHERE name LIKE ? ORDER BY {sort}', (f'%{name}%',)).fetchall()
    return jsonify([dict(row) for row in rows])

@app.route('/users/<int:user_id>')
def get_user(user_id: int):
    row = get_db().execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    return jsonify(dict(row) if row else {})
