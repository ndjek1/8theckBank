# 8TechBank — BSE 4202 Software Security Practical Assignment

> Build · Break · Fix — a deliberately-vulnerable banking app, a portfolio
> of working exploits against it, a hardened production build with full
> defence-in-depth, a sandboxed Docker stack, and a security assessment
> report.

## Repository layout

```
8TechBank/
├── README.md                              ← this file
├── BSE 4202_..._Assignment.pdf            ← original brief
├── src/
│   ├── vulnerable/                        ← Task 1 deliverable (deliberately broken)
│   │   ├── app.py, schema.sql, seed.py
│   │   ├── templates/, static/
│   │   ├── requirements.txt, README.md
│   │   ├── Dockerfile, docker-compose.yml
│   │   └── bank.db (gen'd by seed.py)
│   └── secure/                            ← Tasks 3 & 4 deliverable (hardened)
│       ├── app.py, api.py, security.py
│       ├── schema.sql, seed.py
│       ├── templates/, static/
│       ├── requirements.txt, README.md
│       ├── Dockerfile, Caddyfile,
│       │   docker-compose.yml, .env.example
│       └── bank.db (gen'd by seed.py)
├── exploits/                              ← Task 2 deliverable
│   ├── exploit_a_sqli.py
│   ├── exploit_b_xss.py
│   ├── exploit_c_csrf.html
│   ├── exploit_d_idor.py
│   ├── run_all_against_test_clients.py    ← regression harness
│   └── README.md
├── screenshots/                           ← evidence (place your PNGs here)
│   ├── README.md (naming convention)
│   └── exploit_results_console.txt        ← textual evidence
└── report/
    ├── 8TechBank_Security_Assessment.md   ← main 8–12 page report (Task 5)
    ├── vulnerability_assessment_matrix.md ← Task 1 matrix (Appendix A)
    └── README.md                          ← Markdown→PDF instructions
```

## Quick start

### Vulnerable build (port 5000)

```bash
cd src/vulnerable
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python seed.py        # creates bank.db with sample users
python app.py         # http://localhost:5000
```

### Secure build (port 5001)

```bash
cd src/secure
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python seed.py
python app.py         # http://127.0.0.1:5001
```

### Sample logins (both builds)

| Username | Password   | Role  |
| -------- | ---------- | ----- |
| alice    | alice123   | user  |
| bob      | bobpass    | user  |
| carol    | carolpw    | user  |
| admin    | admin123   | admin |

### Run all exploits against both builds (regression test)

```bash
# from repo root, in the secure venv (it has all deps)
. src/secure/.venv/bin/activate
python exploits/run_all_against_test_clients.py
```

### Sandboxed Docker stack (Task 4.3)

```bash
cd src/secure
cp .env.example .env && $EDITOR .env       # set strong SECRET_KEY + JWT_SECRET
docker compose up --build
# Caddy listens on 8080 (HTTP redirect) and 8443 (HTTPS)
```

## Ethical use notice

This codebase contains intentional vulnerabilities. **Run only on your
own localhost.** Using these techniques against any system you do not
own and have written permission to test is a criminal offence under
Uganda's Computer Misuse Act, 2011.
