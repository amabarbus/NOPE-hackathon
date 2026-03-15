import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'nope.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            time TEXT,
            severity TEXT,
            threat TEXT,
            payload TEXT,
            source_ip TEXT,
            source_site TEXT DEFAULT 'Edge Hub'
        )
    ''')
    conn.commit()
    conn.close()
