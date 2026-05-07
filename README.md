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

## How this maps to the assignment

| Task | Deliverable | Where |
| ---- | ----------- | ----- |
| Task 1 | Build vulnerable app + 8+ findings + matrix | `src/vulnerable/`, `report/vulnerability_assessment_matrix.md` |
| Task 2 | Working PoC exploits A-D | `exploits/`, `screenshots/exploit_results_console.txt` |
| Task 3 | Six fixes with before/after | `src/secure/` + Section 4 of the report |
| Task 4 | JWT API + rate limit + sandboxing | `src/secure/api.py`, `Dockerfile`, `docker-compose.yml`, `Caddyfile` |
| Task 5 | 8-12 page assessment report | `report/8TechBank_Security_Assessment.md` |

## Submission checklist (per the brief)

* [ ] Replace `<your group / name(s)>` placeholders in:
    * `report/8TechBank_Security_Assessment.md` (header)
    * `report/vulnerability_assessment_matrix.md` (assessor line)
* [ ] Capture screenshots referenced in the report (see
      `screenshots/README.md` for the suggested naming).
* [ ] Update **§7 AI Tool Usage Declaration** to match what your group
      actually did. Default text reflects use of an AI coding assistant
      for boilerplate; edit before submission.
* [ ] Convert `report/8TechBank_Security_Assessment.md` to PDF
      (see `report/README.md`).
* [ ] Re-run `python exploits/run_all_against_test_clients.py` and re-seed
      both DBs (`python src/{vulnerable,secure}/seed.py`).
* [ ] Delete the `.venv/` folders before zipping (they aren't needed).
* [ ] Zip as `StudentID_CSC4207_Assignment.zip` (per §1 Submission
      Requirements). Note: the brief says `CSC4207`, which is likely a
      typo — verify with the lecturer; code is BSE 4202.
* [ ] Upload to MUELE before **13 May 2026, 23:59 EAT**.

## Ethical use notice

This codebase contains intentional vulnerabilities. **Run only on your
own localhost.** Using these techniques against any system you do not
own and have written permission to test is a criminal offence under
Uganda's Computer Misuse Act, 2011.
