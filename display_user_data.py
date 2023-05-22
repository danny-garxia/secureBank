import sqlite3

conn = sqlite3.connect("userdata.db")
cur = conn.cursor()

cur.execute("SELECT * FROM userdata")
rows = cur.fetchall()

for row in rows:
    print(row)

conn.close()
