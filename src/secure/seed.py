"""Seed the SECURE 8TechBank database. All passwords are bcrypt-hashed
(>=12 rounds) before being stored — see Fix 5."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import bcrypt

DB = Path(os.environ.get("BANK_DB_PATH", Path(__file__).parent / "bank.db"))
SCHEMA = Path(__file__).parent / "schema.sql"

BCRYPT_ROUNDS = 12  # >= 12 per assignment Fix 5


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"),
                         bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("utf-8")


def init_db() -> None:
    conn = sqlite3.connect(DB)
    conn.executescript(SCHEMA.read_text())
    conn.commit()
    conn.close()


def seed() -> None:
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    users = [
        ("alice", hash_password("alice123"), "Alice Mukasa",   "alice@8techbank.local", "user"),
        ("bob",   hash_password("bobpass"),  "Bob Okello",     "bob@8techbank.local",   "user"),
        ("carol", hash_password("carolpw"),  "Carol Nansubuga","carol@8techbank.local", "user"),
        ("admin", hash_password("admin123"), "System Admin",   "admin@8techbank.local", "admin"),
    ]
    cur.executemany(
        "INSERT INTO users (username, password_hash, full_name, email, role) "
        "VALUES (?,?,?,?,?)",
        users,
    )

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

    txns = [
        (1, 2, 100.00, "Lunch refund"),
        (2, 3,  50.00, "Boda fare"),
        (1, 3, 200.00, "School fees contribution"),
    ]
    cur.executemany(
        "INSERT INTO transactions (from_acct, to_acct, amount, note) "
        "VALUES (?,?,?,?)",
        txns,
    )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    if DB.exists():
        DB.unlink()
    init_db()
    seed()
    print(f"[+] Seeded {DB} with bcrypt-hashed passwords (rounds={BCRYPT_ROUNDS})")
    print("    Logins:")
    print("      alice / alice123   (user)")
    print("      bob   / bobpass    (user)")
    print("      carol / carolpw    (user)")
    print("      admin / admin123   (admin)")
