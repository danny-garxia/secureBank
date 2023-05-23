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
from Crypto.PublicKey import DSA
from Crypto.IO import PEM
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# Load the private key from a file
with open('dsa_private_key.pem', 'rb') as f:
    dsa_private_key_atm = DSA.import_key(f.read())

# Load the public key from a file
with open('dsa_public_key.pem', 'rb') as f:
    dsa_public_key_atm_1 = DSA.import_key(f.read())

DATABASE = "userdata.db"

HEADER = 64
PORT = 5062
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(ADDR)




# Load the private key from a file
with open('dsa_private_key.pem', 'rb') as f:
    dsa_private_key_atm = DSA.import_key(f.read())

# Load the public key from a file
with open('dsa_public_key.pem', 'rb') as f:
    dsa_public_key_atm_1 = DSA.import_key(f.read())

#Load Banks private key // getting error so i commented it out
with open('private-key-bank.pem', 'rb') as keyfile:
    private_key_bank = serialization.load_pem_private_key(keyfile.read(), password=None)

#Load ATMs Public Keys
with open('public-key-atm-1.pem', 'rb') as keyfile:
    public_key_atm_1 = serialization.load_pem_public_key(keyfile.read())

with open('public-key-atm-2.pem', 'rb') as keyfile:
    public_key_atm_2 = serialization.load_pem_public_key(keyfile.read())



def record_activity(id, activity):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        
        # Check if the ID exists in the table
        cursor.execute("SELECT * FROM userdata WHERE id = ?", (id,))
        existing_activity = cursor.fetchone()[0] 
        
        if existing_activity:
            # ID exists, retrieve the existing activity
            new_activity = str(existing_activity) + ", " + activity  
            
        else:
            new_activity = activity
            
            # Update the activity for that user
        cursor.execute("UPDATE userdata SET activity = ? WHERE id = ?", (new_activity, id))
        print("Activity recorded successfully.")

def display_amount_money(con, id):
    print("checking...", id)
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT balance FROM userdata WHERE id = ?", (id,))
        result = cursor.fetchone()[0]
        if result is None:
            result = 0
            print("result:",result)
        print("result:",result)
        msg = f"Your balance is: {result}"
        
        con.send(msg.encode(FORMAT))

def deposit_money(con, id, amount):
    print("Depositing...")
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT balance FROM userdata WHERE id = ?", (id,))
            record = cursor.fetchone()
            print(record)
            if record:
                balance = record[0]
                new_balance = balance + amount
                cursor.execute("UPDATE userdata SET balance = ? WHERE id = ?", (new_balance, id))
                conn.commit()  # Commit the transaction
                print("Deposit successful!")
                result = f"Deposit successful! Updated balance: {new_balance}"

                activity = f"Deposit of {amount} made"
                record_activity(id, activity)

                con.send(result.encode(FORMAT))
    except sqlite3.Error as e:
        print("Error during deposit:", e)
        error_message = "An error occurred during the deposit process."
        con.send(error_message.encode(FORMAT))
    finally:
        cursor.close()

def withdrawals(con, id, amount):
    print("Checking...")
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT balance FROM userdata WHERE id = ?", (id,))
            record = cursor.fetchone()
            print(record)
            if record:
                balance = record[0]
                if balance >= amount:
                    new_balance = balance - amount
                    cursor.execute("UPDATE userdata SET balance = ? WHERE id = ?", (new_balance, id))
                    conn.commit()  # Commit the transaction
                    print("Withdrawal successful!")
                    result = f"Withdrawal successful! Updated balance: {new_balance}"

                    activity = f"Withdrawal of {amount} made"
                    record_activity(id, activity)

                else:
                    activity = f"Unsuccessful Attempt of Withdrawal of {amount} made"
                    record_activity(id, activity)

                    print("Insufficient balance.")
                    result = "Insufficient balance."

                con.send(result.encode(FORMAT))
    except sqlite3.Error as e:
        print("Error during withdrawal:", e)
        error_message = "An error occurred during the withdrawal process."
        con.send(error_message.encode(FORMAT))
    finally:
        cursor.close()


def account_activity(con, id):
    print("Showing activities...")
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT activity FROM userdata WHERE id = ?", (id,))
        results = cursor.fetchall()

        if results:
            print("Activities:")
            for row in results:
                activities = row[0]
        else:
            activities = "No activities found!"
        con.send(activities.encode(FORMAT))

def quit():
    # TODO quit 
    pass

def send(msg):
    print("sending msg:", msg)
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
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





def hash_password(password):
    return hashlib.sha256(password.encode(FORMAT)).hexdigest()





def authenticate_user(credentials):
    # Extract id and password from the decrypted message
    id = credentials["ID"]
    password = credentials["password"]
    

    # Connect to the database
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM userdata WHERE id = ? AND password = ?", (id, password))
        result = cursor.fetchall()
        print ("result", result)
        if result:
            print("true")
            return True
            
        else:
            print("false")
            return False
        
def authenticate_user_dsa(credentials):
    # Extract id and password from the decrypted message
    id = credentials["ID"]
    password = credentials["password"]
   
    # Hash the password using the same method used when storing it in the database
    hashed_password = hashlib.sha256(password.encode(FORMAT)).hexdigest()

    # Connect to the database
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM userdata WHERE id = ? AND password = ?", (id, hashed_password))
        result = cursor.fetchall()
        print ("result", result)
        if result:
            print("true")
            return True
        else:
            print("false")
            return False

def DSA_decode_message_and_identify_request(conn, msg):

    print("menu0")
    request = json.loads(msg)
    print ("messge", request)
    # Extracting fields from the request
    user = request.get("user")
    action = request.get("action")
    amount = request.get("amount")

    with sqlite3.connect("userdata.db") as db_conn:
        cursor = db_conn.cursor()

        if action == "check_funds":
            cursor.execute("SELECT balance FROM userdata WHERE id = ?", (user,))
            result = cursor.fetchone()
            if result is not None:
                balance = result[0]
                response = f"User {user} has balance {balance}"
                conn.send(response.encode(FORMAT))
            else:
                conn.send(f"User {user} not found".encode(FORMAT))

        elif action == "withdraw":
            if amount is not None:
                cursor.execute("UPDATE userdata SET balance = balance - ? WHERE id = ?", (amount, user))
                db_conn.commit()
                conn.send(f"User {user} balance updated".encode(FORMAT))
            else:
                conn.send(f"Invalid request: {msg}".encode(FORMAT))

        elif action == "deposit":
            if amount is not None:
                cursor.execute("UPDATE userdata SET balance = balance + ? WHERE id = ?", (amount, user))
                db_conn.commit()
                conn.send(f"User {user} balance updated".encode(FORMAT))
            else:
                conn.send(f"Invalid request: {msg}".encode(FORMAT))

        elif action == "account_activities":
            cursor.execute("SELECT activity FROM userdata WHERE id = ?", (user,))
            result = cursor.fetchall()
            if result:
                activities = ', '.join(map(str, [res[0] for res in result]))
                response = f"User {user} activities are: {activities}"
                conn.send(response.encode(FORMAT))
            else:
                conn.send(f"No activities found for user {user}".encode(FORMAT))
        
        else:
            conn.send(f"Invalid request: {msg}".encode(FORMAT))


def RSA_decode_message_and_identify_request(conn, msg):
    print("msg:",msg)
    message_from_atm = json.loads(msg)
    print("decode_message_and_identify_request...:",message_from_atm)
    encrypted_message_from_atm = base64.b64decode(message_from_atm['encrypted_user_account'])
    decrypted_message_from_atm_json = private_key_bank.decrypt(
        encrypted_message_from_atm,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    digital_signature = base64.b64decode(message_from_atm['Digital_Signature'])
    decrypted_message_from_atm = decrypted_message_from_atm_json.decode(FORMAT)

    try:
        public_key_atm_1.verify(
            digital_signature,
            encrypted_message_from_atm,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print('Signature valid')
    except:
        print('Signature not valid')

    decrypted_message_from_atm = json.loads(decrypted_message_from_atm)
    print("action",decrypted_message_from_atm)
    # Check if the request is for checking funds
    if decrypted_message_from_atm.get("amount") != None:
        amount = int(decrypted_message_from_atm.get("amount"))
    if decrypted_message_from_atm.get("action") == "checkFunds":
        id = decrypted_message_from_atm["ID"]
        display_amount_money(conn, id)  # Call the function to display the amount of money for the given ID
        
        return {"authenticated": True}
    elif decrypted_message_from_atm.get("action") == "withdraw":
        id = decrypted_message_from_atm["ID"]
        withdrawals(conn, id, amount)  # Call the function to withdraw money from balance
        return {"authenticated": True}
    elif decrypted_message_from_atm.get("action") == "deposit":
        id = decrypted_message_from_atm["ID"]
        deposit_money(conn, id, amount)  # Call the function to deposit money into balance
        return {"authenticated": True}
    elif decrypted_message_from_atm.get("action") == "activities":
        id = decrypted_message_from_atm["ID"]
        account_activity(conn, id)  # Call the function to show activities money into balance
        return {"authenticated": True}
    else:
        print("Unknown request type:", decrypted_message_from_atm.get("action"))
        print("action",decrypted_message_from_atm)
        return {"authenticated": False}
 
        
def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")

    connected = True
    while connected:
        msg = conn.recv(1024).decode(FORMAT)

        if msg == DISCONNECT_MESSAGE:
            connected = False

        message_from_atm = json.loads(msg)

        
        encryption = message_from_atm.get('encryption', 'RSA')  # Default to RSA if encryption field is missing
        if encryption == 'RSA':
            print("RSA")
            encrypted_message_from_atm = base64.b64decode(message_from_atm['encrypted_user_account'])

        
            decrypted_message_from_atm_json = private_key_bank.decrypt(
                encrypted_message_from_atm,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None))
            
            print("decrypted_message_from_atm_json",decrypted_message_from_atm_json)
            decrypted_message_from_atm = decrypted_message_from_atm_json.decode(FORMAT)
            print("Decrypted Message:", decrypted_message_from_atm, type(decrypted_message_from_atm))

            digital_signature = base64.b64decode(message_from_atm['Digital_Signature'])
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

            decrypted_message_from_atm = json.loads(decrypted_message_from_atm)

            #login/ check if user exists in the database with matching password
            if authenticate_user(decrypted_message_from_atm):
                conn.send("Login successful!".encode(FORMAT))

                #if the user is authenticated, send a message to ATM:
                msg = conn.recv(1024).decode(FORMAT)
                print("msg",msg)
                RSA_decode_message_and_identify_request(conn,msg)
                break
                print ( "test1")
                
            else:
                conn.send("Login failed!".encode(FORMAT))

        
        elif encryption == 'DSA':
            print("DSA")
            # You need to get the signed message first before decoding it
            encrypted_message_from_atm = message_from_atm['signed_user_account']
            decrypted_message_from_atm_json = base64.b64decode(encrypted_message_from_atm).decode()
            print("decrypted_message_from_atm_json",decrypted_message_from_atm_json)
            decrypted_message_from_atm = json.loads(decrypted_message_from_atm_json)
            print("hello0")

            print("Decrypted Message:", decrypted_message_from_atm, type(decrypted_message_from_atm))
            digital_signature = base64.b64decode(message_from_atm['signature'])
            print("hello1")

          # Recreate the hash of the message to verify the signature
            message_hash = SHA256.new(data=decrypted_message_from_atm_json.encode())
            # Prepare the verifier
            verifier = DSS.new(dsa_public_key_atm_1, 'fips-186-3')
            
            print("hello2")
            try:
                 verifier.verify(message_hash, digital_signature)
                 print('Signature valid', addr)
            except (ValueError, TypeError):
                 print('Signature not valid', addr)
              
                 
             
          
            

            print("hello3")

            #login/ check if user exists in the database with matching password
            if authenticate_user_dsa(decrypted_message_from_atm):
                print("Sending login successful message...")
                conn.send("Login successful!".encode(FORMAT))
                print("Login successful message sent.")
                
                #if the user is authenticated, send a message to ATM:
                msg = conn.recv(1024).decode(FORMAT)
                print ("hi")
                print("msg",msg)
                print ("hi")
                RSA_decode_message_and_identify_request(conn,msg)
                break
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