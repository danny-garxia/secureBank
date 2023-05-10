import socket
import ssl
from cryptography.hazmat.primitives import serialization, hashes

HEADER = 64
PORT = 5054
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

def send(msg):
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(message)
    print(client.recv(2048).decode(FORMAT))

#load atm2 private key   // getting error so i commented it out
# with open('private-key-atm-2.pem', 'rb') as keyfile:
#     private_key_atm_2 = serialization.load_pem_private_key(keyfile.read())
#Load banks public key 
with open('public-key-bank.pem', 'rb') as keyfile:
    public_key_bank = serialization.load_pem_public_key(keyfile.read())

print("[Hello! This is ATM 2]")
print("Please enter you ID")
id = input()
print("Please enter your password")
passowrd = input()

# send("Hello World!")
# input()
# send("Hello Everyone!")
# input()
# send("Hello Tim!")

#send(DISCONNECT_MESSAGE)