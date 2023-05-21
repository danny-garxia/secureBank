import sqlite3
import hashlib


conn = sqlite3.connect("userdata")
cur = conn.cursor()


cur.execute( """

CREATE TABLE IF NOT EXISTS userdata(
idn INTEGER PRIMARY KEY,
id VARCHAR(255) NOT NULL,
password VARCHAR(255) NOT NULL,
balance INTEGER DEFAULT 0
)
""")

id1, passwrod1 = "belal1", hashlib.sha256("belalpass23".encode()).hexdigest()
id2, passwrod2 = "daniel", hashlib.sha256( "danielpass112".encode()).hexdigest()
id3, passwrod3 = "john12",  hashlib.sha256("johnpass11".encode()).hexdigest()
cur.execute("INSERT INTO userdata(username, password) VALUES (?, ?)", (id1, passwrod1))
cur.execute("INSERT INTO userdata(username, password) VALUES (?, ?)", (id2, passwrod2))
cur.execute("INSERT INTO userdata(username, password) VALUES (?, ?)", (id3, passwrod3))

conn.close()

