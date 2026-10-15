# house-style: v2
"""User directory service."""
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

# Allowlist of columns permitted for ORDER BY to prevent SQL injection.
# Dynamic column names cannot be parameterized, so we validate against
# this set before interpolating into the query (codeguard-0-input-validation-injection).
ALLOWED_SORT_COLUMNS = {"name", "created_at", "email"}


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/users/search")
def search_users():
    name = request.args.get("name", "")
    sort = request.args.get("sort", "name")

    if sort not in ALLOWED_SORT_COLUMNS:
        return jsonify(
            {"error": f"Invalid sort column. Allowed values: {', '.join(sorted(ALLOWED_SORT_COLUMNS))}"}
        ), 400

    # The LIKE pattern uses a parameterized placeholder (?) so the name value
    # is never interpolated into the SQL string (prevents SQL injection).
    # The sort column is safe because it has been validated against the allowlist above.
    rows = get_db().execute(
        f"SELECT * FROM users WHERE name LIKE ? ORDER BY {sort}",
        (f"%{name}%",),
    ).fetchall()

    return jsonify([dict(row) for row in rows])


@app.route("/users/<int:user_id>")
def get_user(user_id: int):
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(dict(row) if row else {})
