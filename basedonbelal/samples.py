import sqlite3
import hashlib

FORMAT = 'utf-8'

conn = sqlite3.connect("userdata.db")
cur = conn.cursor()


cur.execute( """
CREATE TABLE IF NOT EXISTS userdata(
idn INTEGER PRIMARY KEY,
id VARCHAR(255) NOT NULL,
password VARCHAR(255),
balance INTEGER DEFAULT 0,
activity TEXT,
timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

id1, passwrod1 = "belal1", hashlib.sha256("belalpass23".encode(FORMAT)).hexdigest()
id2, passwrod2 = "daniel", hashlib.sha256( "danielpass112".encode(FORMAT)).hexdigest()
id3, passwrod3 = "john12",  hashlib.sha256("johnpass11".encode(FORMAT)).hexdigest()
cur.execute("INSERT INTO userdata(id, password) VALUES (?, ?)", (id1, passwrod1))
cur.execute("INSERT INTO userdata(id, password) VALUES (?, ?)", (id2, passwrod2))
cur.execute("INSERT INTO userdata(id, password) VALUES (?, ?)", (id3, passwrod3))
conn.commit()
conn.close()

