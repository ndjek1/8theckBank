"""Seed the vulnerable 8TechBank database with sample users, accounts, and a
few transactions. Run once after schema initialisation:

    python seed.py
"""
import sqlite3
from pathlib import Path

DB = Path(__file__).parent / "bank.db"
SCHEMA = Path(__file__).parent / "schema.sql"


def init_db() -> None:
    conn = sqlite3.connect(DB)
    conn.executescript(SCHEMA.read_text())
    conn.commit()
    conn.close()


def seed() -> None:
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # --- Users (plaintext passwords on purpose for the vulnerable build) ---
    users = [
        ("alice",  "alice123",   "Alice Mukasa",   "alice@8techbank.local",   "user"),
        ("bob",    "bobpass",    "Bob Okello",     "bob@8techbank.local",     "user"),
        ("carol",  "carolpw",    "Carol Nansubuga","carol@8techbank.local",   "user"),
        ("admin",  "admin123",   "System Admin",   "admin@8techbank.local",   "admin"),
    ]
    cur.executemany(
        "INSERT INTO users (username, password, full_name, email, role) VALUES (?,?,?,?,?)",
        users,
    )

    # --- Accounts ---
    accounts = [
        (1, "8TB-1001",  5_000.00),
        (2, "8TB-1002",  2_300.50),
        (3, "8TB-1003",    750.00),
        (4, "8TB-9001", 50_000.00),
    ]
    cur.executemany(
        "INSERT INTO accounts (user_id, acct_number, balance) VALUES (?,?,?)",
        accounts,
    )

    # --- A couple of opening transactions ---
    txns = [
        (1, 2, 100.00, "Lunch refund"),
        (2, 3,  50.00, "Boda fare"),
        (1, 3, 200.00, "School fees contribution"),
    ]
    cur.executemany(
        "INSERT INTO transactions (from_acct, to_acct, amount, note) VALUES (?,?,?,?)",
        txns,
    )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    if DB.exists():
        DB.unlink()
    init_db()
    seed()
    print(f"[+] Seeded {DB}")
    print("    Logins:")
    print("      alice / alice123   (user)")
    print("      bob   / bobpass    (user)")
    print("      carol / carolpw    (user)")
    print("      admin / admin123   (admin)")
