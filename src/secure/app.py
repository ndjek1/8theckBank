"""
8TechBank — SECURE build.

Implements every fix required by Task 3 of the BSE 4202 Practical Assignment:

  Fix 1: Parameterised SQL queries (no string concatenation)
  Fix 2: Output encoding (Jinja2 autoescape) + Content-Security-Policy
  Fix 3: CSRF tokens on all state-changing forms
  Fix 4: Authorisation (login + ownership/role checks)
  Fix 5: bcrypt password hashing (>=12 rounds)
  Fix 6: Security headers + hardened session cookies (HttpOnly/Secure/
         SameSite=Strict + 15 min idle timeout)

Plus, for Task 4, see api.py (mounted on /api/...): JWT auth, RBAC, rate
limiting, Pydantic input validation.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import bcrypt
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from security import (
    add_security_headers,
    configure_secure_session,
    install_csrf,
    login_required,
    own_account_required,
    role_required,
    safe_next_url,
)


DB_PATH = Path(os.environ.get("BANK_DB_PATH", Path(__file__).parent / "bank.db"))


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
def create_app() -> Flask:
    app = Flask(__name__)

    # Fix 7: secret comes from environment, never hard-coded. Falls back to
    # a randomly-generated value for local development.
    app.config["SECRET_KEY"] = os.environ.get(
        "SECRET_KEY", os.urandom(32).hex()
    )

    # Fix 6: hardened cookies + 15 min session timeout
    configure_secure_session(app)

    # During development over plain HTTP we relax SESSION_COOKIE_SECURE so
    # that the browser still sends the cookie. PRODUCTION must always be HTTPS.
    if os.environ.get("FLASK_ENV", "development") == "development":
        app.config["SESSION_COOKIE_SECURE"] = False

    # Fix 3: CSRF protection
    install_csrf(app)

    # Fix 2 + Fix 6: response headers
    app.after_request(add_security_headers)

    # Mitigate brute-force on login (also covered for the JSON API in api.py)
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per hour"],
        storage_uri="memory://",
    )

    # Mount JSON API blueprint (Task 4)
    from api import api_bp, init_api_limiter
    app.register_blueprint(api_bp)
    init_api_limiter(limiter, app)

    register_routes(app, limiter)
    return app


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def current_user():
    if "user_id" not in session:
        return None
    return get_db().execute(
        "SELECT id, username, full_name, email, role FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
def register_routes(app: Flask, limiter: Limiter) -> None:

    app.teardown_appcontext(close_db)

    @app.context_processor
    def inject_user():
        return {"current_user": current_user()}

    @app.route("/")
    def index():
        if current_user():
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    # ----- Fix 1 + Fix 5: parameterised query + bcrypt verify ---------------
    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])  # brute-force defence
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")

            # FIX 1: parameterised query — no concatenation, no SQLi.
            row = get_db().execute(
                "SELECT id, password_hash, role FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            ok = False
            if row is not None:
                # FIX 5: bcrypt verify (constant-time)
                ok = bcrypt.checkpw(
                    password.encode("utf-8"),
                    row["password_hash"].encode("utf-8"),
                )
            if ok:
                session.clear()
                session.permanent = True              # apply 15min lifetime
                session["user_id"] = row["id"]
                session["role"]    = row["role"]
                # FIX: validate the post-login redirect target (no open redir)
                return redirect(
                    safe_next_url(request.args.get("next"), url_for("dashboard"))
                )
            error = "Invalid username or password."
        return render_template("login.html", error=error)

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ----- Fix 5: registration with bcrypt hashing --------------------------
    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("10 per hour", methods=["POST"])
    def register():
        error = None
        if request.method == "POST":
            username  = (request.form.get("username") or "").strip()
            password  = request.form.get("password") or ""
            full_name = (request.form.get("full_name") or "").strip()
            email     = (request.form.get("email") or "").strip()

            # Lightweight server-side validation (FIX: input validation)
            if not (3 <= len(username) <= 32) or not username.isidentifier():
                error = "Username must be 3-32 chars, letters/digits/underscore."
            elif len(password) < 10:
                error = "Password must be at least 10 characters."
            else:
                pw_hash = bcrypt.hashpw(
                    password.encode("utf-8"),
                    bcrypt.gensalt(rounds=12),
                ).decode("utf-8")

                db = get_db()
                try:
                    db.execute(
                        "INSERT INTO users (username, password_hash, full_name, email) "
                        "VALUES (?,?,?,?)",
                        (username, pw_hash, full_name, email),
                    )
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
                    error = "Username already taken."

        return render_template("register.html", error=error)

    @app.route("/dashboard")
    @login_required
    def dashboard():
        accounts = get_db().execute(
            "SELECT * FROM accounts WHERE user_id = ?", (session["user_id"],)
        ).fetchall()
        return render_template("dashboard.html", accounts=accounts)

    # ----- Fix 4: ownership-based access control on account view -----------
    @app.route("/account/<int:account_id>")
    @login_required
    def view_account(account_id: int):
        db = get_db()
        account = db.execute(
            "SELECT * FROM accounts WHERE id = ?", (account_id,)
        ).fetchone()
        if account is None:
            abort(404)

        # FIX 4: only owners (or admins) may view this account
        own_account_required(account["user_id"])

        owner = db.execute(
            "SELECT username, full_name, email FROM users WHERE id = ?",
            (account["user_id"],),
        ).fetchone()
        txns = db.execute(
            "SELECT * FROM transactions WHERE from_acct = ? OR to_acct = ? "
            "ORDER BY created_at DESC",
            (account_id, account_id),
        ).fetchall()
        return render_template(
            "account.html", account=account, owner=owner, txns=txns
        )

    # ----- Fix 1 + 3 + 4 + 11: secure transfer ------------------------------
    @app.route("/transfer", methods=["GET", "POST"])
    @login_required
    @limiter.limit("30 per minute", methods=["POST"])
    def transfer():
        db = get_db()
        error = None
        if request.method == "POST":
            try:
                from_acct_id = int(request.form["from_account"])
            except (KeyError, ValueError):
                abort(400)
            to_acct_num = (request.form.get("to_account") or "").strip()
            note        = (request.form.get("note") or "").strip()

            # FIX 11: strict numeric + range validation
            try:
                amount = float(request.form["amount"])
            except (KeyError, ValueError):
                abort(400)
            if amount <= 0 or amount > 10_000_000:
                error = "Amount must be a positive number up to 10,000,000."
            elif len(note) > 200:
                error = "Note too long."
            else:
                from_acct = db.execute(
                    "SELECT * FROM accounts WHERE id = ?", (from_acct_id,)
                ).fetchone()
                # FIX 4: caller must own the source account
                if from_acct is None or from_acct["user_id"] != session["user_id"]:
                    abort(403)

                to_acct = db.execute(
                    "SELECT * FROM accounts WHERE acct_number = ?", (to_acct_num,)
                ).fetchone()
                if to_acct is None:
                    error = "Recipient account not found."
                elif to_acct["id"] == from_acct["id"]:
                    error = "Cannot transfer to the same account."
                elif from_acct["balance"] < amount:
                    error = "Insufficient funds."
                else:
                    # All-or-nothing: SQLite implicit transaction
                    try:
                        db.execute(
                            "UPDATE accounts SET balance = balance - ? "
                            "WHERE id = ? AND balance >= ?",
                            (amount, from_acct["id"], amount),
                        )
                        db.execute(
                            "UPDATE accounts SET balance = balance + ? WHERE id = ?",
                            (amount, to_acct["id"]),
                        )
                        db.execute(
                            "INSERT INTO transactions "
                            "(from_acct, to_acct, amount, note) "
                            "VALUES (?,?,?,?)",
                            (from_acct["id"], to_acct["id"], amount, note),
                        )
                        db.commit()
                        flash("Transfer successful.")
                        return redirect(url_for("transactions"))
                    except sqlite3.Error:
                        db.rollback()
                        error = "Transfer failed; please try again."

        accounts = db.execute(
            "SELECT * FROM accounts WHERE user_id = ?", (session["user_id"],)
        ).fetchall()
        return render_template("transfer.html", accounts=accounts, error=error)

    @app.route("/transactions")
    @login_required
    def transactions():
        txns = get_db().execute(
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

    # ----- Fix 2: search renders via Jinja autoescape ----------------------
    @app.route("/search")
    @login_required
    def search():
        query = request.args.get("q", "")
        # Jinja autoescape neutralises any HTML/JS in the input.
        return render_template("search.html", query=query)

    # ----- Fix 4: admin requires role='admin' -------------------------------
    @app.route("/admin")
    @login_required
    @role_required("admin")
    def admin():
        db = get_db()
        users = db.execute(
            "SELECT id, username, full_name, email, role FROM users"
        ).fetchall()  # never expose password_hash
        accounts = db.execute("SELECT * FROM accounts").fetchall()
        return render_template("admin.html", users=users, accounts=accounts)

    # ----- Generic error handlers (no stack traces leaked) -----------------
    @app.errorhandler(403)
    def _forbidden(e):
        return render_template("error.html",
                               code=403, message="Forbidden"), 403

    @app.errorhandler(404)
    def _not_found(e):
        return render_template("error.html",
                               code=404, message="Not Found"), 404

    @app.errorhandler(429)
    def _rate_limited(e):
        return render_template(
            "error.html", code=429,
            message="Too many requests. Please wait and try again.",
        ), 429

    @app.errorhandler(500)
    def _server_error(e):
        return render_template("error.html",
                               code=500, message="Internal server error"), 500


def ensure_db() -> None:
    if not DB_PATH.exists():
        from seed import init_db, seed
        init_db()
        seed()


app = create_app()

if __name__ == "__main__":
    ensure_db()
    # debug must NEVER be True in any non-development environment.
    app.run(host="127.0.0.1", port=5001, debug=False)
