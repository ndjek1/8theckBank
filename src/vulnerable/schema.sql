-- 8TechBank database schema (vulnerable build)
-- Note: deliberately simple. Passwords are stored in plaintext to demonstrate
-- the plaintext-password vulnerability (Pattern 5).

DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,           -- plaintext (vulnerable)
    full_name   TEXT,
    email       TEXT,
    role        TEXT NOT NULL DEFAULT 'user',  -- 'user' or 'admin'
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    amount     REAL NOT NULL,
    note       TEXT,                     -- user-supplied, unsanitised (vulnerable)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (from_acct) REFERENCES accounts(id),
    FOREIGN KEY (to_acct)   REFERENCES accounts(id)
);
