# init_db.py
import sqlite3
import os
from datetime import datetime

DB_FILE = "voting.db"

schema = """
CREATE TABLE IF NOT EXISTS voters (
    cnic TEXT PRIMARY KEY,
    name TEXT,
    email TEXT,
    password_hash TEXT,
    totp_secret TEXT,
    has_voted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    party TEXT,
    votes INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    cnic TEXT,
    otp TEXT,
    used INTEGER DEFAULT 0,
    expiry INTEGER
);

CREATE TABLE IF NOT EXISTS votes_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vote_hash TEXT,
    prev_hash TEXT,
    candidate_id INTEGER,
    timestamp TEXT,
    signature TEXT
);

CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT,
    actor TEXT,
    timestamp TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""

def init_db():
    if os.path.exists(DB_FILE):
        print("Database exists:", DB_FILE)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.executescript(schema)
    # Insert sample candidates if none
    c.execute("SELECT COUNT(*) FROM candidates")
    if c.fetchone()[0] == 0:
        c.executemany("INSERT INTO candidates (name, party) VALUES (?, ?)",
                      [("Imran Khan", "Party A"), ("Nawaz Sharif", "Party B"), ("Bilawal Bhutto", "Party C")])
        print("Inserted sample candidates.")
    conn.commit()
    conn.close()
    print("Database initialized.")

if __name__ == "__main__":
    init_db()
