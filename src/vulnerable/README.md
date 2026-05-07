# 8TechBank — Vulnerable Build

> ⚠️ **DO NOT DEPLOY.** This build deliberately ships every vulnerability listed in
> Task 1 of the BSE 4202 assignment. Run only on `localhost`.

## Setup

```bash
cd src/vulnerable
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python seed.py                     # creates bank.db with sample users
python app.py                      # http://localhost:5000
```

## Sample logins

| Username | Password   | Role  |
| -------- | ---------- | ----- |
| alice    | alice123   | user  |
| bob      | bobpass    | user  |
| carol    | carolpw    | user  |
| admin    | admin123   | admin |

## Vulnerabilities present

See `../../report/vulnerability_assessment_matrix.md` for the full matrix
(CWE, OWASP, CVSS) and `../../exploits/` for working PoCs.

| ID  | Pattern                                | File / line                |
| --- | -------------------------------------- | -------------------------- |
| V1  | SQL Injection in `/login`              | `app.py` `login()`         |
| V2  | Reflected XSS in `/search`             | `app.py` `search()`        |
| V3  | Stored XSS in transaction notes        | `transactions.html` `\|safe`|
| V4  | IDOR on `/account/<id>`                | `app.py` `view_account()`  |
| V5  | Plaintext password storage             | `app.py` `register()`      |
| V6  | Missing CSRF on `/transfer`            | `app.py` `transfer()`      |
| V7  | Hard-coded secret + insecure cookies   | `app.py` config            |
| V8  | Verbose errors / `debug=True`          | `app.py` `__main__`        |
| V9  | No authorisation on `/admin`           | `app.py` `admin()`         |
| V10 | Open redirect via `?next=`             | `app.py` `login()`         |
| V11 | Missing input validation on amount     | `app.py` `transfer()`      |
| V12 | No rate limiting on `/login`           | `app.py` `login()`         |

## Docker

```bash
docker build -t 8techbank-vuln .
docker run --rm -p 5000:5000 8techbank-vuln
```
