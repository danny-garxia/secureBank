import socket
import ssl
import json
from Crypto.Signature import pkcs1_15
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

#from bank import SERVER as SERVER_HOST
#from bank import PORT as SERVER_PORT

HEADER = 64
PORT = 5054
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client.connect(ADDR)

#load atm1 private key  // getting error so i commented it out
with open('private-key-atm-1.pem', 'rb') as keyfile:
    private_key_atm_1 = serialization.load_pem_private_key(keyfile.read())

# Load banks public key
with open('public-key-bank.pem', 'rb') as keyfile:
    public_key_bank = serialization.load_pem_public_key(keyfile.read())

def send(msg):
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(message)
    print(client.recv(2048).decode(FORMAT))


print("[Hello! This is ATM 1]")
print("Please enter you ID")
id = input()
print("Please enter your password")
password = input()

# this will take id and passowrd and make it into a dictionary using json.sumps
user_account_1 = json.dumps({'ID': id, 'password': password}).encode(FORMAT)
# Encrypts user_account dictionary with banks public key using SHA256 encryption. 
encrypted_user_account_1 = public_key_bank.encrypt(user_account_1, 
                                                 padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                               algorithm=hashes.SHA256(), label=None))
# provides a digital signature to our encrpyted user acount. 
DS_E_User_Acount_1 = private_key_atm_1.sign(encrypted_user_account_1,
                                            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), 
                                                        salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

# this is the messege that we will send which contains the digitaly signed encryoted message
message = json.dumps({'encrypted_user_account_1': encrypted_user_account_1.decode(FORMAT), 
                      'Digital_SIgnature': DS_E_User_Acount_1.decode(FORMAT)}).encode(FORMAT)


# send(DISCONNECT_MESSAGE)