# house-style: v2
"""User directory service."""
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


_ALLOWED_SORT_COLUMNS: frozenset[str] = frozenset({"name", "created_at", "email"})


@app.route("/users/search")
def search_users():
    name = request.args.get("name", "")
    sort = request.args.get("sort", "name")

    # Security: allowlist the sort column to prevent SQL injection.
    # Column names cannot be parameterized in SQLite, so we validate against
    # a fixed set of permitted identifiers before embedding in the query.
    # (rule: codeguard-0-input-validation-injection)
    if sort not in _ALLOWED_SORT_COLUMNS:
        return jsonify({"error": f"Invalid sort column. Allowed values: {sorted(_ALLOWED_SORT_COLUMNS)}"}), 400

    rows = get_db().execute(
        # `name` filter is passed as a bound parameter — no string concatenation.
        # `sort` is safe here because it was validated against the allowlist above.
        f"SELECT * FROM users WHERE name LIKE ? ORDER BY {sort}",  # noqa: S608
        (f"%{name}%",),
    ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/users/<int:user_id>")
def get_user(user_id: int):
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(dict(row) if row else {})
