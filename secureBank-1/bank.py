import socket 
import threading
import ssl
import json
import base64
import sys
from Crypto.Signature import pkcs1_15
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import sqlite3
import hashlib


HEADER = 64
PORT = 5055
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(ADDR)

#Load Banks private key // getting error so i commented it out
with open('private-key-bank.pem', 'rb') as keyfile:
    private_key_bank = serialization.load_pem_private_key(keyfile.read(), password=None)

#Load ATMs Public Keys
with open('public-key-atm-1.pem', 'rb') as keyfile:
    public_key_atm_1 = serialization.load_pem_public_key(keyfile.read())

with open('public-key-atm-2.pem', 'rb') as keyfile:
    public_key_atm_2 = serialization.load_pem_public_key(keyfile.read())

#mock data
account = {
    "Name" : "Joe Biden",
    "ID" : 123456,
    "password" : "test123"
}



def display_amount_money():
    pass

def deposit_money():
    # TODO add deposit money action
    pass

def withdrwals():
    # TODO add widthddrwal action
    pass

def account_activity():
    # TODO time and date when the user perfomed
    #transactions and what transactions the user performed
    pass

def quit():
    # TODO quit 
    pass

def send(msg):
    message = msg.encode(FORMAT)
    #get the data length
    msg_length = len(message)

    # string the datat length
    strLen = str(msg_length).encode(FORMAT)
    send_length +=b' ' * (HEADER - len(send_length))
    server.send(send_length)
    server.send(message)

def recv(server):
    header = server.recv(HEADER)
    if not header:
        return None

    strHead = header.decode()
    intHead = int(strHead)

    data = b''
    while len(data) < intHead:
        recvData = server.recv(intHead - len(data))
        if not recvData:
            break
        data += recvData
    return data



        

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")

    connected = True
    while connected:
        msg = conn.recv(1024).decode(FORMAT)
    
        if msg == DISCONNECT_MESSAGE:
            connected = False
        
        print(f"The [{addr}] {msg}")
        conn.send("Msg received".encode(FORMAT))
        
        message_from_atm = json.loads(msg)
        print("message_from_atm",message_from_atm)
        encrypted_message_from_atm = base64.b64decode(message_from_atm['encrypted_user_account_1'])
        print("encrypted_message_from_atm",encrypted_message_from_atm)

        decrypted_message_from_atm_json = private_key_bank.decrypt(
            encrypted_message_from_atm,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(), label=None))
        
        digital_signature = base64.b64decode(message_from_atm['Digital_Signature'])
        print("decrypted_message_from_atm_json",decrypted_message_from_atm_json)
        decrypted_message_from_atm = decrypted_message_from_atm_json.decode(FORMAT)
        print("Decrypted Message:", decrypted_message_from_atm, type(decrypted_message_from_atm))
        
        
        try:
            public_key_atm_1.verify(
                digital_signature,
                encrypted_message_from_atm,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print('Signature valid', addr)
        except:
            print('Signature not valid', addr)

# Extract id and password from the decrypted message
        decrypted_message_from_atm = json.loads(decrypted_message_from_atm)
        username = decrypted_message_from_atm["ID"]
        
        password = decrypted_message_from_atm["password"]
        password = hashlib.sha256(password.encode()).hexdigest()

        #connect to the database
        connect = sqlite3.connect("userdata")
        cur = connect.cursor()

        cur.execute("SELECT * FROM userdata WHERE username = ? AND password = ?", (username, password))
        if cur.fetchall():
            print("login successful")
            conn.send("Login successful!".encode(FORMAT))
            # 5 Actions:
            
        else:
            conn.send("Login failed!".encode(FORMAT))

    conn.close()



def start():
    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
        


print("[STARTING] server is starting...")
start()