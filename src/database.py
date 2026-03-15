import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'nope.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Attack Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            date TEXT,
            time TEXT,
            severity TEXT,
            attack_type TEXT,
            source_ip TEXT,
            payload TEXT,
            source_location TEXT,
            is_live INTEGER DEFAULT 0
        )
    ''')
    
    # 2. Custom Rules Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS custom_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            pattern TEXT NOT NULL
        )
    ''')
    
    # 3. IP Blocklist Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_blocklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print("🗄️ Database initialized successfully.")

if __name__ == "__main__":
    init_db()
