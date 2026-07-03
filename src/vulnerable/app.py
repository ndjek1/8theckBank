"""
8TechBank — VULNERABLE build.

"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    abort,
)

SECRET_KEY = "8techbank-dev-secret"                     # CWE-798

DB_PATH = Path(__file__).parent / "bank.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
# V7: insecure cookie configuration (no HttpOnly, no Secure, no SameSite)
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SECURE"]   = False
app.config["SESSION_COOKIE_SAMESITE"] = None


#DB
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def current_user():
    if "user_id" not in session:
        return None
    return get_db().execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()


@app.context_processor
def inject_user():
    return {"current_user": current_user()}


#PUBLIC ROUTES
@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


# --- Pattern 1: SQL Injection in Login (V1) --------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # VULNERABLE: string concatenation in SQL query (CWE-89)
        query = (
            f"SELECT * FROM users WHERE username='{username}' "
            f"AND password='{password}'"
        )
        try:
            user = get_db().execute(query).fetchone()
        except sqlite3.Error as exc:
            # V8: verbose error reflected to the user
            return f"<pre>SQL error: {exc}\nQuery: {query}</pre>", 500

        if user:
            session["user_id"] = user["id"]
            session["role"]    = user["role"]
            # V10: open redirect via unvalidated ?next= parameter
            nxt = request.args.get("next") or url_for("dashboard")
            return redirect(nxt)
        error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- Pattern 5: Plaintext password storage (V5) ----------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username  = request.form["username"]
        password  = request.form["password"]      # NOT hashed
        full_name = request.form.get("full_name", "")
        email     = request.form.get("email", "")
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, full_name, email) "
                "VALUES (?,?,?,?)",
                (username, password, full_name, email),
            )
            # also open a default account
            new_id = db.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()["id"]
            db.execute(
                "INSERT INTO accounts (user_id, acct_number, balance) "
                "VALUES (?,?,?)",
                (new_id, f"8TB-{1000 + new_id}", 100.00),
            )
            db.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            error = "Username already taken"
    return render_template("register.html", error=error)

#Authenticated area
def require_login():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return None


@app.route("/dashboard")
def dashboard():
    redir = require_login()
    if redir:
        return redir
    db = get_db()
    accounts = db.execute(
        "SELECT * FROM accounts WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    return render_template("dashboard.html", accounts=accounts)


# --- Pattern 4: Broken Access Control / IDOR (V4) --------------------------
@app.route("/account/<int:account_id>")
def view_account(account_id: int):
    redir = require_login()
    if redir:
        return redir

    # VULNERABLE: no ownership check — any authenticated user can view ANY
    # account by changing the URL parameter.
    db = get_db()
    account = db.execute(
        "SELECT * FROM accounts WHERE id = ?", (account_id,)
    ).fetchone()
    if account is None:
        abort(404)

    owner = db.execute(
        "SELECT username, full_name, email FROM users WHERE id = ?",
        (account["user_id"],),
    ).fetchone()
    txns = db.execute(
        "SELECT * FROM transactions "
        "WHERE from_acct = ? OR to_acct = ? "
        "ORDER BY created_at DESC",
        (account_id, account_id),
    ).fetchall()
    return render_template(
        "account.html", account=account, owner=owner, txns=txns
    )


# --- Pattern 3 + Pattern 6: Stored XSS + Missing CSRF (V3, V6, V11) --------
@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    redir = require_login()
    if redir:
        return redir

    db = get_db()
    error = None
    if request.method == "POST":
        # VULNERABLE: no CSRF token validation (Pattern 6 / V6)
        from_acct_id = int(request.form["from_account"])
        to_acct_num  = request.form["to_account"]
        amount       = float(request.form["amount"])      # V11: no validation
        note         = request.form.get("note", "")       # V3: no sanitisation

        from_acct = db.execute(
            "SELECT * FROM accounts WHERE id = ?", (from_acct_id,)
        ).fetchone()
        to_acct = db.execute(
            "SELECT * FROM accounts WHERE acct_number = ?", (to_acct_num,)
        ).fetchone()

        if not to_acct:
            error = "Recipient account not found."
        else:
            # V11: negative or zero amounts are accepted
            db.execute(
                "UPDATE accounts SET balance = balance - ? WHERE id = ?",
                (amount, from_acct["id"]),
            )
            db.execute(
                "UPDATE accounts SET balance = balance + ? WHERE id = ?",
                (amount, to_acct["id"]),
            )
            db.execute(
                "INSERT INTO transactions (from_acct, to_acct, amount, note) "
                "VALUES (?,?,?,?)",
                (from_acct["id"], to_acct["id"], amount, note),
            )
            db.commit()
            return redirect(url_for("transactions"))

    accounts = db.execute(
        "SELECT * FROM accounts WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    return render_template("transfer.html", accounts=accounts, error=error)


@app.route("/transactions")
def transactions():
    redir = require_login()
    if redir:
        return redir
    db = get_db()
    # All transactions involving the user's accounts
    txns = db.execute(
        """
        SELECT t.*, fa.acct_number AS from_num, ta.acct_number AS to_num
        FROM transactions t
        JOIN accounts fa ON fa.id = t.from_acct
        JOIN accounts ta ON ta.id = t.to_acct
        WHERE fa.user_id = ? OR ta.user_id = ?
        ORDER BY t.created_at DESC
        """,
        (session["user_id"], session["user_id"]),
    ).fetchall()
    return render_template("transactions.html", txns=txns)


# --- Pattern 2: Reflected XSS in /search (V2) ------------------------------
@app.route("/search")
def search():
    query = request.args.get("q", "")
    return render_template("search.html", query=query)


# --- V9: Admin panel without authorisation check --------------------------
@app.route("/admin")
def admin():
    redir = require_login()
    if redir:
        return redir
    # VULNERABLE: only checks login, not role. Any authenticated user can hit
    # this endpoint and see all customer data.
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    accounts = db.execute("SELECT * FROM accounts").fetchall()
    return render_template("admin.html", users=users, accounts=accounts)


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
def ensure_db() -> None:
    if not DB_PATH.exists():
        from seed import init_db, seed
        init_db()
        seed()


if __name__ == "__main__":
    ensure_db()
    # V8: debug=True leaks the Werkzeug debugger / stack traces
    app.run(host="0.0.0.0", port=5000, debug=True)
