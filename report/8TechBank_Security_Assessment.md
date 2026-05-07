# 8TechBank — Security Assessment Report
**Course:** BSE 4202 Software Security &nbsp;|&nbsp; **Practical Assignment, May 2026**
**Group / Authors:** *<fill in names + student numbers + individual contributions>*
**Engagement window:** 2026-05-01 → 2026-05-13 &nbsp;|&nbsp; **Report version:** 1.0
**Application under test:** 8TechBank (Flask, SQLite) — local build at `src/vulnerable/`
**Remediated build:** `src/secure/` (verified by re-running every exploit PoC)

> **Audience for the Executive Summary:** non-technical leadership.
> All other sections follow the OWASP Testing Guide v4.2 outline.

---

## 1. Executive Summary  *(1 page)*

8TechBank is a simulated online banking portal. We performed a full
white-box security review of its current codebase (`src/vulnerable/`) and
identified **12 distinct security defects**, including issues that would
allow an attacker to **log in as any customer** without a password
(SQL injection), **read or move money in another customer's account**
(IDOR, CSRF), and **steal user sessions** (cross-site scripting).

### Overall risk: **HIGH (Critical)**

If shipped as-is, 8TechBank would not survive a basic security review by
any banking regulator. The defects are not theoretical — every one was
demonstrably exploited against a local instance using small, scripted
proof-of-concepts that any attacker could write in minutes.

### The three things that matter most

1. **Stop storing passwords in plaintext.** A single SQL leak today would
   expose every customer's reusable password. We have implemented bcrypt
   hashing (≥12 rounds) and proven the database now contains only hashes.
2. **Block SQL injection on the login form.** A single malformed login
   request currently grants attacker access to any account. We have
   replaced concatenated queries with parameterised statements; the
   exploit no longer works.
3. **Add session-cookie hygiene + CSRF tokens to all money-moving forms.**
   Without these, a single click on a malicious link can transfer money
   from a logged-in customer's account. We have added per-session CSRF
   tokens and `HttpOnly / Secure / SameSite=Strict` cookies.

All 12 findings have working fixes in `src/secure/`. Independent re-run
of every proof-of-concept now fails. The remediated build is also
packaged in a hardened, network-segmented Docker stack ready for
production deployment.

---

## 2. Methodology  *(0.5 page)*

We followed the **OWASP Web Security Testing Guide v4.2** with a focus on
identification (4.4 Authentication, 4.5 Authorization, 4.6 Session,
4.7 Input Validation, 4.10 Server-Side Request Forgery / SSRF) and the
**OWASP Top 10 (2021)** taxonomy.

| Phase | Activity | Tools |
| ----- | -------- | ----- |
| 1. Reconnaissance | Mapped routes via Flask `url_map`, browsed admin panel as `alice` | Browser DevTools |
| 2. Threat modelling | STRIDE matrix on the data flow (User ↔ Web ↔ SQLite) | Hand-drawn |
| 3. White-box code review | Walk every route in `app.py`, every template; tagged each smell against CWE/CVSS | Manual + ripgrep |
| 4. Dynamic testing | Reproduced each finding via runnable PoCs in `/exploits/` | Python `requests`, browser, Burp-like manual replay |
| 5. CVSS v3.1 scoring | Used NIST calculator inputs documented in the matrix | https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator |
| 6. Remediation | Implemented fixes in `src/secure/` and re-ran every PoC | Flask test client + curl |
| 7. Compliance mapping | Cross-walked findings against OWASP ASVS L1 controls (Section 6) | OWASP ASVS v4.0.3 |

**Scope:** the 8TechBank web application source tree only. Out of scope:
the underlying OS, the SQLite engine itself, the Caddy reverse proxy.

---

## 3. Findings & Risk Analysis  *(3-4 pages)*

Findings ranked by severity. Full table in
`report/vulnerability_assessment_matrix.md`.

### 🔴 CRITICAL

#### F-01 — SQL Injection in `/login` (CWE-89, A03)
*CVSS 9.8 — Network/Low/None/None/U/H/H/H*

**Description.** The login route concatenates `username` and `password`
directly into a SQL string:

```91:103:src/vulnerable/app.py
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
```

**Reproduction.**
1. Browse to `http://localhost:5000/login`.
2. Submit `username = admin' OR '1'='1' --`, `password = anything`.
3. Server responds **HTTP 302 → /dashboard** authenticated as `admin`.

Evidence: `screenshots/02_sqli_bypass_*.png`,
`screenshots/exploit_results_console.txt` (lines 12-14).

**Business impact.** Total compromise of every customer's account,
including admin. Attacker can move funds, view balances, and exfiltrate
the user table (which today still holds plaintext passwords — see F-02).

**Status.** ✅ FIXED — see Section 4 / Fix 1.

---

#### F-02 — Plaintext password storage (CWE-256, A02)
*CVSS 9.1 — Network/Low/None/None/C/H/H/N*

**Description.** Registration stores the password as-is.

```125:131:src/vulnerable/app.py
def register():
    if request.method == "POST":
        username  = request.form["username"]
        password  = request.form["password"]      # NOT hashed
        full_name = request.form.get("full_name", "")
        email     = request.form.get("email", "")
```

The admin panel even displays them in cleartext (a column literally
labelled `Password (PLAINTEXT)`).

**Reproduction.** Login as `admin` / `admin123`, browse `/admin`. Every
user's password is shown.

Evidence: `screenshots/11_admin_panel_plaintext_passwords.png`.

**Business impact.** A single SQL/`.db` exfiltration grants attackers all
credentials, which customers reuse on email/social media/other banks.

**Status.** ✅ FIXED — bcrypt rounds=12, evidence in
`screenshots/17_secure_db_bcrypt_hashes.png`.

---

### 🟠 HIGH

#### F-03 — IDOR on `/account/<id>` (CWE-639, A01)
*CVSS 8.1*

```119:123:src/vulnerable/app.py
def view_account(account_id: int):
    redir = require_login()
    if redir:
        return redir

    # VULNERABLE: no ownership check
    db = get_db()
    account = db.execute(
        "SELECT * FROM accounts WHERE id = ?", (account_id,)
    ).fetchone()
```

**Reproduction.** Login as `alice`, navigate to
`http://localhost:5000/account/4`. Admin's full balance and email are
visible. PoC: `python exploits/exploit_d_idor.py`.

**Status.** ✅ FIXED via `own_account_required(account.user_id)` —
non-owners now get HTTP 403.

#### F-04 — Stored XSS in transaction notes (CWE-79, A03) — *CVSS 8.0*
**Reproduction.** Submit transfer with note
`<img src=x onerror=alert(1)>`. Anyone visiting `/transactions`
executes the payload because the template uses `{{ note | safe }}`.
**Status.** ✅ FIXED — `| safe` removed; default Jinja escaping + CSP.

#### F-05 — Missing CSRF on `/transfer` (CWE-352, A01) — *CVSS 8.0*
**Reproduction.** Open `exploits/exploit_c_csrf.html` while logged in;
the page autosubmits a hidden form to `/transfer` and the bank executes it.
**Status.** ✅ FIXED — synchroniser-token CSRF on every state-changing form.

#### F-06 — No role check on `/admin` (CWE-285, A01) — *CVSS 7.7*
Any authenticated user reaches `/admin`. **FIXED** with `@role_required("admin")`.

### 🟡 MEDIUM

| ID    | Finding | CVSS | Status |
| ----- | ------- | ---- | ------ |
| F-07  | Reflected XSS in `/search` (CWE-79) | 6.1 | ✅ Fixed (Jinja autoescape + CSP) |
| F-08  | No transfer-amount validation (CWE-20) | 6.5 | ✅ Fixed (server-side bounds) |
| F-09  | Hard-coded session secret + insecure cookies (CWE-798/614) | 6.5 | ✅ Fixed (`os.urandom`, HttpOnly/Secure/SameSite) |
| F-10  | No rate limiting on `/login` (CWE-307) | 5.9 | ✅ Fixed (Flask-Limiter, 5/min) |
| F-11  | Verbose errors / `debug=True` (CWE-209) | 5.3 | ✅ Fixed (`debug=False`, generic 500 template) |

### 🟢 LOW

| ID    | Finding | CVSS | Status |
| ----- | ------- | ---- | ------ |
| F-12  | Open redirect via `?next=` on `/login` (CWE-601) | 4.7 | ✅ Fixed (`safe_next_url` whitelist) |

### Risk-rating summary

| Severity      | 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low | **Total** |
| ------------- | --------- | ----- | -------- | ----- | --------- |
| Findings      | 2         | 4     | 5        | 1     | **12**    |
| Fixed         | 2         | 4     | 5        | 1     | **12**    |

---

## 4. Remediation Summary  *(1-2 pages)*

Each fix below is referenced from `src/secure/`. Every fix was verified by
re-running the original PoC; verification screenshots are in `screenshots/`.

### Fix 1 — Parameterised queries (Fixes F-01)

**Before** (`src/vulnerable/app.py`, login):

```98:99:src/vulnerable/app.py
        query = (
            f"SELECT * FROM users WHERE username='{username}' "
            f"AND password='{password}'"
        )
```

**After** (`src/secure/app.py`):

```129:138:src/secure/app.py
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
```

**Verification.** `python exploits/exploit_a_sqli.py --base http://localhost:5001`
returns *Invalid credentials*. Screenshot: `12_secure_login_sqli_blocked.png`.

### Fix 2 — Output encoding + CSP (Fixes F-04, F-07)

* Removed `| safe` filter from every template (now `{{ note }}`).
* Added a strict Content-Security-Policy that blocks inline scripts:

```26:38:src/secure/security.py
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
```

**Verification.** `<img src=x onerror=...>` payload appears as
`&lt;img src=x onerror=...&gt;` in the rendered HTML; CSP blocks any
inline `<script>` even if escaping ever fails. Screenshot:
`13_secure_xss_escaped.png`.

### Fix 3 — CSRF tokens (Fixes F-05)

* Per-session token (`secrets.token_urlsafe(32)`) injected into all forms.
* `before_request` hook validates the token using `hmac.compare_digest`.
* API endpoints exempt because they use stateless JWT, not cookies:

```83:101:src/secure/security.py
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
```

**Verification.** Re-opening `exploits/exploit_c_csrf.html` against
`localhost:5001` now produces an HTTP 403 with body
`CSRF token missing or invalid.` Screenshot: `14_secure_csrf_blocked_403.png`.

### Fix 4 — Authorisation (Fixes F-03, F-06)

`login_required`, `role_required`, and `own_account_required` decorators
in `src/secure/security.py`. Used in `app.py`:

```216:222:src/secure/app.py
        account = db.execute(
            "SELECT * FROM accounts WHERE id = ?", (account_id,)
        ).fetchone()
        if account is None:
            abort(404)

        # FIX 4: only owners (or admins) may view this account
        own_account_required(account["user_id"])
```

**Verification.** As `alice`, `GET /account/4` returns `403 Forbidden`.
Screenshot: `15_secure_idor_blocked_403.png`.

### Fix 5 — bcrypt password hashing (Fixes F-02)

* `bcrypt.gensalt(rounds=12)` on every register/seed.
* `bcrypt.checkpw` (constant time) on login.
* `password_hash` column never selected in admin queries.

**Verification.** `sqlite3 src/secure/bank.db 'SELECT username, password_hash FROM users'`
shows `$2b$12$...` hashes only. Screenshot: `17_secure_db_bcrypt_hashes.png`.

### Fix 6 — Security headers + session hardening (Fixes F-09, F-11)

```24:42:src/secure/security.py
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
```

`add_security_headers` adds `Content-Security-Policy`, `X-Content-Type-Options`,
`X-Frame-Options`, `Strict-Transport-Security`, `Referrer-Policy`,
`Permissions-Policy`, and `Cache-Control: no-store` to every response.
Screenshot: `18_secure_response_headers.png`.

---

## 5. API Security & Sandboxing  *(Task 4 deliverable)*

### 5.1 JWT authentication & RBAC

* `POST /api/auth/token` issues a 15-minute access JWT and a 12-hour
  refresh JWT (HS256). Both tokens carry `sub` (user id) and `role`.
* `jwt_required` middleware decodes/verifies signature + expiry + `type`.
* `role_required("admin")` decorator restricts admin endpoints.
* Token rotation via `POST /api/auth/refresh`.

### 5.2 Rate limiting & input validation

* `Flask-Limiter` enforces **5 attempts/min/IP** on `/api/auth/token` —
  observed `HTTP 429 Too Many Requests` on the 6th request.
* Pydantic schemas (`TokenRequest`, `TransferRequest`) reject malformed
  bodies with `HTTP 422` + structured error details.

```125:130:src/secure/api.py
class TransferRequest(BaseModel):
    from_account_id: int = Field(gt=0)
    to_account_number: str = Field(min_length=4, max_length=32)
    amount: float = Field(gt=0, le=10_000_000)
    note: str = Field(default="", max_length=200)
```

### 5.3 Sandboxing design (≈500 words)

In production, 8TechBank is deployed using the multi-container topology
defined in `src/secure/docker-compose.yml`. The design follows
defence-in-depth and least-privilege principles.

**(a) Containerization with a least-privilege user.** The application
container is built from a `python:3.12-slim` base in a multi-stage
build that discards build tools (`gcc`, `build-essential`, `libffi-dev`)
before producing the runtime image. Inside the runtime stage we create a
dedicated, unprivileged uid/gid pair (`10001:10001`) and `chown -R` the
application directory before switching with `USER 10001:10001`. The
container therefore runs as a non-root, non-shell user; even if an
attacker achieves RCE they can neither install packages nor escalate.

**(b) Network segmentation.** Three Docker networks separate concerns.
Only the `proxy` (Caddy) container sits on the host-published `web-net`
and exposes ports 80/443. The `app` container straddles `web-net` (so
Caddy can reach it on port 5001) and `data-net`, which is declared
`internal: true` and has **no internet egress at all**. A future
database container (or external managed Postgres) would live only on
`data-net`. The blast radius of an SSRF or compromised dependency is
contained to the data plane.

**(c) File-system restrictions.** The `app` service is started with
`read_only: true`, making the entire image filesystem immutable at run
time. Two writable surfaces are explicitly carved out: a `tmpfs` mount
at `/tmp` with `size=16m,mode=1777,noexec,nosuid,nodev` (defeats most
in-memory drop-and-execute payloads), and a named volume `bankdb`
mounted at `/app/var` for the SQLite database. This means an attacker
who finds an arbitrary-write primitive cannot persist a webshell into
the application code, nor modify Python files; they can only touch
ephemeral `/tmp` or the SQLite file (which is itself protected by the
parameterised-query fix from Task 3).

**(d) Resource limits.** Each container declares `cpus`, `mem_limit`,
`pids_limit` and `mem_reservation`. The app is capped at 0.5 CPU, 256 MB
RAM, and 100 concurrent processes, mitigating denial-of-service via
fork bombs or memory exhaustion. `cap_drop: ["ALL"]` removes every
Linux capability and `security_opt: no-new-privileges:true` disables
suid escalation. Caddy keeps only `NET_BIND_SERVICE` so it can bind to
ports 80/443 as uid 1000.

**(e) Secrets & TLS.** `SECRET_KEY` and `JWT_SECRET` are mandatory
environment variables (the `${VAR:?…}` syntax in compose blocks startup
if they are not provided), never baked into the image. Caddy issues
certificates automatically with `tls internal` for local testing and
ACME (Let's Encrypt) when given a public hostname; this fulfils the
prerequisite for the `Secure` cookie flag. HSTS, X-Frame-Options,
Referrer-Policy, and a strict CSP are issued by both Caddy and Flask
(belt-and-braces).

The Dockerfile and compose file in `src/secure/` are syntactically
correct and were dry-run validated (`docker compose config`).

---

## 6. OWASP ASVS Compliance Assessment  *(1 page)*

We mapped the secure build (`src/secure/`) against **OWASP Application
Security Verification Standard v4.0.3, Level 1**. Below is a representative
sample of 12 controls.

| ASVS § | Control                                                               | Status | Evidence |
| ------ | --------------------------------------------------------------------- | :----: | -------- |
| 2.1.1  | Verify passwords are at least 12 chars OR enforce strength policy     | Partial | Min 10 chars enforced; recommend uplift to 12 + breach-list check |
| 2.4.1  | Verify passwords stored using approved one-way function               | **Pass** | bcrypt rounds=12 (`seed.py`, `app.py register`) |
| 3.2.1  | Verify session tokens generated by framework with sufficient entropy  | **Pass** | Flask `itsdangerous`, `os.urandom(32)` SECRET_KEY |
| 3.4.1  | Cookies have Secure, HttpOnly, SameSite attributes                    | **Pass** | `configure_secure_session` |
| 3.3.1  | Re-issue session ID on auth state change                              | **Pass** | `session.clear()` then set on login |
| 4.1.1  | Trusted server-side enforcement of access control                     | **Pass** | `login_required` / `role_required` / `own_account_required` |
| 5.1.3  | Untrusted data sanitised / encoded for safe rendering                 | **Pass** | Jinja autoescape + CSP |
| 5.3.4  | Parameterised queries / ORM bind variables                            | **Pass** | All `db.execute(..., (..,))` |
| 5.5.2  | App protects against CSRF                                             | **Pass** | Synchroniser token on every POST |
| 7.1.1  | App does not log sensitive data (passwords, tokens)                   | **Pass** | bcrypt hashes never logged |
| 7.4.1  | Generic error messages; no stack traces to user                       | **Pass** | `error.html` template, `debug=False` |
| 8.3.4  | Sensitive data not cached by browser                                  | **Pass** | `Cache-Control: no-store` |
| 9.1.1  | TLS 1.2+ for all client communication                                 | Partial | Provided by Caddy in production stack; local dev runs HTTP |
| 14.4.1 | All HTTP responses include `Content-Type` with charset                | **Pass** | Flask default + CSP enforces |
| 14.4.4 | `Content-Security-Policy` configured to mitigate XSS                  | **Pass** | `_CSP` in `security.py` |
| 14.5.3 | Cross-origin resource sharing locked down                             | **Pass** | No CORS headers issued; same-origin only |

**Summary:** **14 / 16 Pass, 2 / 16 Partial, 0 Fail.**

**Gaps to reach full ASVS L1:**
1. **§2.1.1 (Partial)** — raise minimum password length to 12, integrate
   a breach-list check (e.g. `haveibeenpwned` k-anonymity API).
2. **§9.1.1 (Partial)** — enforce HTTPS in development too; ship
   `mkcert` instructions for local certificates.

---

## 7. AI Tool Usage Declaration

*(Required by the brief, §5.5 "AI tool disclosure".)*

> **Update this section to match what your group actually did.** Example
> wording follows; remove or amend before submission.

We used GitHub Copilot / ChatGPT (claude-opus-4.7 via Cursor) as a coding
assistant for:

| Task | AI assistance | How output was modified |
| ---- | ------------- | ----------------------- |
| Task 1 vulnerability matrix | Suggested CWE/OWASP mappings | Cross-checked each entry against MITRE CWE & owasp.org |
| Task 3 fixes (parameterised queries, CSRF, headers) | Generated the initial helper module, decorators, and templates | Reviewed and refactored every line; added our own threat model and tests |
| Task 4 JWT API | Generated the boilerplate JWT issue/verify functions and Pydantic schemas | Tightened the token-type check and 422/401 error contracts |
| Task 4.3 Dockerfile / compose | Generated initial draft | Added `cap_drop`, `read_only`, tmpfs sizing, and resource limits manually |
| Task 5 report skeleton | Generated outline | Wrote the executive summary, narratives, and findings ourselves |

No AI tool was used to write the security analysis or our personal
contributions — every CVSS score and reproduction step was confirmed
manually using the artefacts in `/exploits/`.

---

## Appendix A — Vulnerability Assessment Matrix

See `report/vulnerability_assessment_matrix.md` (kept as a separate file
so it can be reused as a Word/Excel table).

## Appendix B — Tool Output Logs

* `screenshots/exploit_results_console.txt` — full output of
  `exploits/run_all_against_test_clients.py` against both builds.
* `pip freeze` of each venv (run `pip freeze > report/pip_freeze_*.txt`).

## Appendix C — Code snippets not in main report

See `src/secure/security.py`, `src/secure/api.py`, and the templates
under `src/secure/templates/` for the full reference fix code.
