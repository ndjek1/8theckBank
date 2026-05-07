-- 8TechBank database schema (SECURE build)
-- Differences vs the vulnerable schema:
--   * password column now stores a bcrypt hash, not plaintext.
--   * (No structural difference for the rest; defence-in-depth happens in
--     application code: parameterised queries, ownership checks, CSRF, etc.)

DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,                 -- bcrypt hash, $2b$12$...
    full_name     TEXT,
    email         TEXT,
    role          TEXT NOT NULL DEFAULT 'user',  -- 'user' | 'admin'
    failed_logins INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE accounts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    acct_number TEXT UNIQUE NOT NULL,
    balance     REAL NOT NULL DEFAULT 0.0,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE transactions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    from_acct  INTEGER NOT NULL,
    to_acct    INTEGER NOT NULL,
    amount     REAL NOT NULL CHECK (amount > 0),
    note       TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (from_acct) REFERENCES accounts(id),
    FOREIGN KEY (to_acct)   REFERENCES accounts(id)
);
