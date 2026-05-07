# 8TechBank — Secure Build

This is the post-remediation 8TechBank application implementing every
required fix from Task 3 plus the JWT API + sandboxing for Task 4.

## Quick start (local)

```bash
cd src/secure
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python seed.py
python app.py                # http://127.0.0.1:5001
```

> Note: in development we relax `SESSION_COOKIE_SECURE` so cookies still
> work over HTTP. In production (behind Caddy/HTTPS) the flag is on.

## Sample logins

| Username | Password   | Role  |
| -------- | ---------- | ----- |
| alice    | alice123   | user  |
| bob      | bobpass    | user  |
| carol    | carolpw    | user  |
| admin    | admin123   | admin |

(Stored as bcrypt hashes — see Fix 5.)

## Fixes implemented (Task 3)

| Fix | Mapping                                               | Where to look                                 |
| --- | ----------------------------------------------------- | --------------------------------------------- |
| 1   | Parameterised SQL queries                             | `app.py` (`?` placeholders everywhere)        |
| 2   | Output encoding + Content-Security-Policy             | `security.py` `_CSP`, templates without `\|safe` |
| 3   | CSRF synchroniser-token validation                    | `security.py` `install_csrf`, `validate_csrf_token` |
| 4   | login_required, role_required, own_account_required   | `security.py`, `app.py` `/account`, `/admin`  |
| 5   | bcrypt password hashing (rounds=12)                   | `seed.py`, `app.py` register/login            |
| 6   | Security headers + cookie hardening + 15min timeout   | `security.py` `add_security_headers`, `configure_secure_session` |

## REST API (Task 4)

| Method | Path                  | Auth        | Notes                                |
| ------ | --------------------- | ----------- | ------------------------------------ |
| POST   | /api/auth/token       | none        | issues JWT pair, **5/min/IP**        |
| POST   | /api/auth/refresh     | refresh JWT | rotate access token                  |
| GET    | /api/me               | access JWT  | caller profile                       |
| GET    | /api/accounts         | access JWT  | caller's accounts                    |
| POST   | /api/transfer         | access JWT  | Pydantic-validated body              |
| GET    | /api/admin/users      | admin JWT   | RBAC                                 |

```bash
# Get a token
curl -X POST http://127.0.0.1:5001/api/auth/token \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"alice123"}'

# Use it
TOKEN=...
curl http://127.0.0.1:5001/api/me -H "Authorization: Bearer $TOKEN"
```

## Sandboxed Docker deployment (Task 4.3)

```bash
cd src/secure
cp .env.example .env             # then fill in strong secrets
docker compose up --build
```

Hardening applied:

* Multi-stage build, runs as non-root uid 10001
* Read-only root filesystem, writable only on `/tmp` (tmpfs) and
  `/app/var` (DB volume on `data-net`)
* All Linux capabilities dropped (`cap_drop: ALL`), `no-new-privileges`
* CPU + memory + pids limits applied
* `app` container is on a `data-net` with `internal: true` — no
  outbound internet access, only the database volume is reachable
* Public traffic only enters via the `proxy` (Caddy) container, which
  terminates TLS and applies HSTS/CSP/X-Frame-Options
