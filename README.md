# 8TechBank

A deliberately vulnerable online banking application developed for the **BSE 4202: Software Security** practical assignment. This repository includes the vulnerable application, exploit demonstrations, remediated secure version, API security enhancements, Docker sandboxing, and the final security assessment report.

## Project Structure

```
src/
├── vulnerable/    # Vulnerable application (Task 1 and Task 2)
└── secure/        # Secure application (Tasks 3 & 4)

exploits/          # Exploit demonstrations (Task 2)

report/            # Security assessment report (Task 5)
```

## Running the Vulnerable Application

```bash
cd src/vulnerable

python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows

pip install -r requirements.txt

python seed.py
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Running the Secure Application

```bash
cd src/secure

python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows

pip install -r requirements.txt

python seed.py
python app.py
```

Open:

```text
http://127.0.0.1:5001
```

## Sample Accounts

| Username | Password |
|----------|----------|
| alice | alice123 |
| bob | bobpass |
| carol | carolpw |
| admin | admin123 |

## Docker Deployment

```bash
cd src/secure

cp .env.example .env
docker compose up --build
```


## Ethical Use

This project contains intentionally vulnerable code for educational purposes. Run it only in a controlled local environment and only on systems you own or have explicit permission to test.
