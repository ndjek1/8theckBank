"""Cross-cutting security helpers for the SECURE build.

Covers Task 3 fixes:
  * Fix 2: Content-Security-Policy + other output-encoding helpers
  * Fix 3: CSRF token generation + double-submit / synchroniser-token validation
  * Fix 4: login_required + role_required decorators
  * Fix 6: security headers + hardened session cookie configuration
"""
from __future__ import annotations

import hmac
import secrets
from functools import wraps
from typing import Callable

from flask import (
    abort,
    current_app,
    g,
    redirect,
    request,
    session,
    url_for,
)


# ---------------------------------------------------------------------------
# Fix 6: hardened session cookie + security response headers
# ---------------------------------------------------------------------------
def configure_secure_session(app) -> None:
    """Apply hardened session-cookie flags and global session timeout.

    HttpOnly  -> cookie inaccessible to JavaScript (mitigates XSS theft)
    Secure    -> cookie only sent over HTTPS (mitigates MITM)
    SameSite=Strict -> mitigates CSRF
    PERMANENT_SESSION_LIFETIME -> 15 min idle timeout
    """
    from datetime import timedelta

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,        # set False locally if not on HTTPS
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    )


# Default CSP. Disallows inline scripts -> neutralises typical XSS payloads
# even if encoding ever fails. `nonce-XXXX` would allow legitimate inline
# script if you need it; we don't, so we stick to 'self'.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


def add_security_headers(response):
    """Attach defence-in-depth response headers (Fix 2 + Fix 6)."""
    response.headers.setdefault("Content-Security-Policy", _CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains",
    )
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=()",
    )
    # Avoid caching authenticated pages
    response.headers.setdefault("Cache-Control", "no-store")
    return response


# ---------------------------------------------------------------------------
# Fix 3: CSRF (synchroniser-token pattern)
# ---------------------------------------------------------------------------
_CSRF_SESSION_KEY = "_csrf_token"


def generate_csrf_token() -> str:
    """Return a per-session CSRF token, generating one lazily."""
    if _CSRF_SESSION_KEY not in session:
        session[_CSRF_SESSION_KEY] = secrets.token_urlsafe(32)
    return session[_CSRF_SESSION_KEY]


def validate_csrf_token() -> None:
    """Validate the CSRF token on every unsafe request.

    Token may be sent either in the form field `csrf_token` or in the
    `X-CSRF-Token` HTTP header (for AJAX). Compared with hmac.compare_digest
    to avoid timing leaks.
    """
    if request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
        return
    # Skip API endpoints — they use JWT (stateless) instead of cookies, so
    # they aren't subject to browser-driven CSRF.
    if request.path.startswith("/api/"):
        return

    expected = session.get(_CSRF_SESSION_KEY, "")
    submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    if not expected or not submitted or not hmac.compare_digest(expected, submitted):
        current_app.logger.warning(
            "CSRF validation failed for %s %s from %s",
            request.method, request.path, request.remote_addr,
        )
        abort(403, description="CSRF token missing or invalid.")


def install_csrf(app) -> None:
    """Wire CSRF validation to every request and expose token to Jinja."""
    app.before_request(validate_csrf_token)

    @app.context_processor
    def _inject():
        return {"csrf_token": generate_csrf_token}


# ---------------------------------------------------------------------------
# Fix 4: authentication + authorisation decorators
# ---------------------------------------------------------------------------
def login_required(view: Callable) -> Callable:
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def role_required(role: str) -> Callable:
    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login", next=request.path))
            if session.get("role") != role:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def own_account_required(account_owner_id: int) -> None:
    """Raise 403 if the logged-in user is not the owner of the account.
    Admin role bypasses the check (read-only audit access)."""
    if session.get("role") == "admin":
        return
    if session.get("user_id") != account_owner_id:
        abort(403)


# ---------------------------------------------------------------------------
# Safe redirect helper — fixes V10 (open redirect)
# ---------------------------------------------------------------------------
def safe_next_url(target: str | None, default: str) -> str:
    """Only allow redirects to relative paths within this application."""
    if not target:
        return default
    # Reject absolute URLs and protocol-relative URLs
    if target.startswith(("http://", "https://", "//", "javascript:")):
        return default
    if not target.startswith("/"):
        return default
    return target
