import sqlite3

conn = sqlite3.connect("dhriti.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    command TEXT,
    time DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()
conn.close()
