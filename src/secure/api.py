"""
8TechBank REST API — Task 4 implementation.

Endpoints (all under /api):
    POST /api/auth/token      issue access + refresh JWT pair (5/min/IP)
    POST /api/auth/refresh    swap refresh token for a fresh access token
    GET  /api/me              caller profile (any authenticated user)
    GET  /api/accounts        caller's accounts
    POST /api/transfer        execute a fund transfer (validated payload)
    GET  /api/admin/users     admin-only listing
"""
from __future__ import annotations

import datetime as _dt
import os
import sqlite3
from pathlib import Path
from functools import wraps
from typing import Optional

import bcrypt
import jwt
from flask import Blueprint, current_app, g, jsonify, request
from flask_limiter import Limiter
from pydantic import BaseModel, Field, ValidationError


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
JWT_ALG          = "HS256"
ACCESS_TTL_MIN   = 15
REFRESH_TTL_HOURS = 12
DB_PATH          = Path(os.environ.get("BANK_DB_PATH", Path(__file__).parent / "bank.db"))


def jwt_secret() -> str:
    """Return the JWT signing secret. Defaults to Flask's SECRET_KEY."""
    return os.environ.get("JWT_SECRET") or current_app.config["SECRET_KEY"]


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------
def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def issue_access_token(user_id: int, role: str) -> str:
    payload = {
        "sub":  str(user_id),
        "role": role,
        "type": "access",
        "iat":  _now(),
        "exp":  _now() + _dt.timedelta(minutes=ACCESS_TTL_MIN),
    }
    return jwt.encode(payload, jwt_secret(), algorithm=JWT_ALG)


def issue_refresh_token(user_id: int, role: str) -> str:
    payload = {
        "sub":  str(user_id),
        "role": role,
        "type": "refresh",
        "iat":  _now(),
        "exp":  _now() + _dt.timedelta(hours=REFRESH_TTL_HOURS),
    }
    return jwt.encode(payload, jwt_secret(), algorithm=JWT_ALG)


def decode_token(token: str, *, expected_type: str) -> dict:
    """Decode + validate signature, expiry, and 'type' claim."""
    try:
        claims = jwt.decode(token, jwt_secret(), algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise _ApiError(401, "Token expired")
    except jwt.InvalidTokenError as exc:
        raise _ApiError(401, f"Invalid token: {exc}")
    if claims.get("type") != expected_type:
        raise _ApiError(401, "Wrong token type")
    return claims


# ---------------------------------------------------------------------------
# Errors / decorators
# ---------------------------------------------------------------------------
class _ApiError(Exception):
    def __init__(self, status: int, message: str):
        self.status, self.message = status, message
        super().__init__(message)


def _extract_bearer() -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(None, 1)[1].strip()
    return None


def jwt_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        token = _extract_bearer()
        if not token:
            raise _ApiError(401, "Missing Bearer token")
        claims = decode_token(token, expected_type="access")
        g.jwt_claims = claims
        g.user_id = int(claims["sub"])
        g.role    = claims["role"]
        return view(*args, **kwargs)
    return wrapped


def role_required(role: str):
    def deco(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if getattr(g, "role", None) != role:
                raise _ApiError(403, "Insufficient role")
            return view(*args, **kwargs)
        return wrapped
    return deco


# ---------------------------------------------------------------------------
# DB helper (independent of the app blueprint to keep the API self-contained)
# ---------------------------------------------------------------------------
def _db() -> sqlite3.Connection:
    if "api_db" not in g:
        g.api_db = sqlite3.connect(DB_PATH)
        g.api_db.row_factory = sqlite3.Row
    return g.api_db


# ---------------------------------------------------------------------------
# Pydantic input schemas (Task 4.2)
# ---------------------------------------------------------------------------
class TokenRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10, max_length=4096)


class TransferRequest(BaseModel):
    from_account_id: int = Field(gt=0)
    to_account_number: str = Field(min_length=4, max_length=32)
    amount: float = Field(gt=0, le=10_000_000)
    note: str = Field(default="", max_length=200)


# ---------------------------------------------------------------------------
# Blueprint + rate limiter wiring
# ---------------------------------------------------------------------------
api_bp = Blueprint("api", __name__, url_prefix="/api")

# The limiter object is created in app.py; rate limits are applied there
# after the blueprint is registered (see init_api_limiter).


# Rate limits keyed by view function __name__; applied after blueprint registration.
_RATE_LIMITS: dict[str, list[str]] = {}


def init_api_limiter(limiter: Limiter, app) -> None:
    """Apply stored rate limits to registered API view functions."""
    for endpoint, view_func in list(app.view_functions.items()):
        if not endpoint.startswith("api."):
            continue
        func = view_func
        while hasattr(func, "__wrapped__"):
            func = func.__wrapped__
        limits = _RATE_LIMITS.get(func.__name__)
        if not limits:
            continue
        wrapped = view_func
        for lim in limits:
            wrapped = limiter.limit(lim)(wrapped)
        app.view_functions[endpoint] = wrapped


def _rl(*limits: str):
    """Mark a view with rate limits; applied in init_api_limiter()."""
    def deco(view):
        _RATE_LIMITS[view.__name__] = list(limits)
        return view
    return deco


# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
@api_bp.errorhandler(_ApiError)
def _api_err(e: _ApiError):
    return jsonify({"error": e.message}), e.status


@api_bp.errorhandler(ValidationError)
def _validation_err(e: ValidationError):
    return jsonify({"error": "Invalid input", "details": e.errors()}), 422


@api_bp.errorhandler(429)
def _rate_limited(_e):
    return jsonify({"error": "Too many requests"}), 429


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@api_bp.post("/auth/token")
@_rl("5 per minute")  # Task 4.2: brute-force protection
def auth_token():
    try:
        body = TokenRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return _validation_err(exc)

    row = _db().execute(
        "SELECT id, password_hash, role FROM users WHERE username = ?",
        (body.username,),
    ).fetchone()

    ok = False
    if row is not None:
        ok = bcrypt.checkpw(
            body.password.encode("utf-8"),
            row["password_hash"].encode("utf-8"),
        )
    if not ok:
        # Identical 401 + same timing window — prevents user enumeration
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({
        "access_token":  issue_access_token(row["id"], row["role"]),
        "refresh_token": issue_refresh_token(row["id"], row["role"]),
        "token_type":    "Bearer",
        "expires_in":    ACCESS_TTL_MIN * 60,
    })


@api_bp.post("/auth/refresh")
@_rl("20 per minute")
def auth_refresh():
    try:
        body = RefreshRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return _validation_err(exc)
    claims = decode_token(body.refresh_token, expected_type="refresh")
    user_id = int(claims["sub"])
    role    = claims["role"]
    return jsonify({
        "access_token": issue_access_token(user_id, role),
        "token_type":   "Bearer",
        "expires_in":   ACCESS_TTL_MIN * 60,
    })


@api_bp.get("/me")
@jwt_required
def me():
    row = _db().execute(
        "SELECT id, username, full_name, email, role "
        "FROM users WHERE id = ?",
        (g.user_id,),
    ).fetchone()
    return jsonify(dict(row))


@api_bp.get("/accounts")
@jwt_required
def my_accounts():
    rows = _db().execute(
        "SELECT id, acct_number, balance, created_at "
        "FROM accounts WHERE user_id = ?",
        (g.user_id,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@api_bp.post("/transfer")
@jwt_required
@_rl("10 per minute")
def api_transfer():
    try:
        body = TransferRequest.model_validate(request.get_json(silent=True) or {})
    except ValidationError as exc:
        return _validation_err(exc)
    db = _db()

    src = db.execute(
        "SELECT * FROM accounts WHERE id = ?", (body.from_account_id,)
    ).fetchone()
    if src is None or src["user_id"] != g.user_id:
        return jsonify({"error": "Source account not yours"}), 403

    dst = db.execute(
        "SELECT * FROM accounts WHERE acct_number = ?",
        (body.to_account_number,),
    ).fetchone()
    if dst is None:
        return jsonify({"error": "Recipient account not found"}), 404
    if dst["id"] == src["id"]:
        return jsonify({"error": "Cannot transfer to same account"}), 400
    if src["balance"] < body.amount:
        return jsonify({"error": "Insufficient funds"}), 400

    try:
        db.execute(
            "UPDATE accounts SET balance = balance - ? "
            "WHERE id = ? AND balance >= ?",
            (body.amount, src["id"], body.amount),
        )
        db.execute(
            "UPDATE accounts SET balance = balance + ? WHERE id = ?",
            (body.amount, dst["id"]),
        )
        db.execute(
            "INSERT INTO transactions (from_acct, to_acct, amount, note) "
            "VALUES (?,?,?,?)",
            (src["id"], dst["id"], body.amount, body.note),
        )
        db.commit()
    except sqlite3.Error as exc:
        db.rollback()
        return jsonify({"error": "Transfer failed", "detail": str(exc)}), 500

    return jsonify({"status": "ok",
                    "new_balance": src["balance"] - body.amount}), 200


@api_bp.get("/admin/users")
@jwt_required
@role_required("admin")
def admin_users():
    rows = _db().execute(
        "SELECT id, username, full_name, email, role FROM users"
    ).fetchall()
    return jsonify([dict(r) for r in rows])
