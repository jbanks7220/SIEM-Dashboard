import sqlite3

def init_db():
    conn = sqlite3.connect('siem.db')
    c = conn.cursor()

    # Example: simple logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully as siem.db")

if __name__ == "__main__":
    init_db()
