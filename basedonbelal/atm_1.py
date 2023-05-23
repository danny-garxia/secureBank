import socket
import ssl
import json
import base64
from Crypto.Signature import pkcs1_15
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
import sqlite3
import hashlib
from Crypto.PublicKey import DSA
from Crypto.IO import PEM



HEADER = 1024
PORT = 5062
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)

# CREATE SOCKET ########################################
########################################################
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)


# Load the private key from a file
with open('dsa_private_key.pem', 'rb') as f:
    dsa_private_key_atm = DSA.import_key(f.read())

# Load the public key from a file
with open('dsa_public_key.pem', 'rb') as f:
    dsa_public_key_atm_1 = DSA.import_key(f.read())

#LOAD KEYS##############################################
#load atm1 private key  // getting error so i commented it out
with open('private-key-atm-1.pem', 'rb') as prv_file:
    private_key_atm_1 = serialization.load_pem_private_key(prv_file.read(), password= None)

# Load banks public key
with open('public-key-bank.pem', 'rb') as keyfile:
    public_key_bank = serialization.load_pem_public_key(keyfile.read())

#Load DSA Keys 
with open('private-key-atm-1-dsa.pem', 'rb') as prv_file:
    dsa_private_key_atm_1 = DSA.import_key(prv_file.read())

# Load bank's public key
with open('public-key-bank-dsa.pem', 'rb') as keyfile:
    dsa_public_key_bank = DSA.import_key(keyfile.read())

# fucntion to send messge properly
def send(msg):
    message = msg
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))

    client.send(send_length)
    client.send(message)

# function to recevive messege properly
def recv(client):

        # receive the header
    header = client.recv(HEADER)

        #decode into a string
    strHead = header.decode()

        #convert the header into an int
    intHead = int(strHead)

    data = b''
    recvData = b''

    while len(data) < intHead:
        recvData = client.recv(intHead - len(data))

        if recvData:
            data += recvData
    return data

with open('private-key-bank.pem', 'rb') as keyfile:
    private_key_bank = serialization.load_pem_private_key(keyfile.read(), password=None) 
"""
def checkFunds(id):
    print("-------------------------------------------------")
    print("[Hello! This is ATM 1]")
    print("Checking funds...")

    # checking funds using the dictionary
    request_message = json.dumps({'request': 'checkFunds', "ID": id}).encode(FORMAT)
    # encrypting request message with banks public key using SHA256 encryption
    encrypted_request = public_key_bank.encrypt(request_message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    signature = private_key_atm_1.sign(request_message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    final_output = base64.b64encode(signature + encrypted_request)
    print("final_output: ",final_output)
    client.send(final_output)
    result = client.recv(1024)
    
    result = base64.b64decode(result)
    signature = result[:256]
    encrypted_result = result[256:]
    decrypted_result = private_key_atm_1.decrypt(encrypted_result, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    try:
        public_key_bank.verify(signature, decrypted_result, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        print("This message is authentic.")
    except Exception as e:
        print("This message is not authentic.")
        print("Error: ", e)

    decrypted_result = json.loads(decrypted_result.decode(FORMAT))
    print("Your account balance is: $", decrypted_result["account_balance"])
    print("-------------------------------------------------")

"""





def withdraw(id,amount):
    RSAEncryption(id,action_req= "withdraw", amount = amount)
    

def deposit(id, amount):
    if amount==None:
        amount = input("How much would you like to deposit? ")
    RSAEncryption(id,action_req= "deposit", amount = amount)
    
def Account_activities(id, activities= "activities"):
    RSAEncryption(id,action_req= "activities")

# Uncomment the following lines to test the checkFunds, withdraw, and deposit functions

#checkFunds()
#withdraw(100)
#deposit(200)



         

def menu(id):
    while True:
        print("What would you like to do?")
        print("1. Check account balance")
        print("2. Withdrawl")
        print("3. Deposit")
        print("4. Account activities")
        print("5. Exit")
        
        option = input()
    
        if option == '1':
            
            check_funds(id)
            break
        
        elif option == '2':
            amount = input("How much would you like to withdraw? ")
            withdraw(id, amount)
            break

        elif option == '3':
            amount = input("How much would you like to deposit? ")
            deposit(id, amount)
            break

        elif option == '4':
            Account_activities(id )

        elif option =='5':
            client.send(DISCONNECT_MESSAGE.encode(FORMAT))
            break
        else:
            print("Invalid option.\n")
        
def RSAEncryption(id ,password=None, action_req=None, amount = None):
    
    print("-------------------------------------------------")
    print("[Hello! This is ATM 1]")
    if id == "":
        id = input("input id: ")
    if password is not None:
        password= hashlib.sha256(password.encode(FORMAT)).hexdigest()
    
    # this will take id and passowrd and make it into a dictionary using json.dumps
    user_account = json.dumps({'ID': id, 'password': password, 'action':action_req, 'amount': amount}).encode(FORMAT)
    #print(user_account.decode(FORMAT))
    

    # Encrypts user_account dictionary with banks public key using SHA256 encryption. 
    encrypted_user_account = public_key_bank.encrypt(user_account, 
                                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                algorithm=hashes.SHA256(), label=None))
    
    # provides a digital signature to our encrpyted user acount. 
    DS_E_User_Acount = private_key_atm_1.sign(encrypted_user_account,
                                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), 
                                                            salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    # need to switch both to base64
    encrypted_user_account = base64.b64encode(encrypted_user_account).decode(FORMAT)+ '"'
    DS_E_User_Acount = base64.b64encode(DS_E_User_Acount).decode(FORMAT)


    # this is the messege that we will send which contains the digitaly signed encrypted message
    message = json.dumps({"encryption": "RSA",  # Add this field
                         "encrypted_user_account": encrypted_user_account,
                         "Digital_Signature": DS_E_User_Acount}).encode(FORMAT)
    

    

    client.send(message)
    if password is not None:
        if client.recv(1024).decode(FORMAT) == "Login successful!":
            print("Login successful!")
            menu(id)
            
        else:
            print("login failed")

            print("Please enter you ID")
            id = input()
            print("Please enter your password")
            password = input()
            #RSAEncryption(id, password)
    else:
        print(client.recv(1024).decode(FORMAT))
        
        

    

def DSASignature(id, password = None, dsa_private_key_atm = None, action_req=None,amount = None):
   #...

    # Generate hash of message
    message = {"ID": id, "password": password}
    message_json = json.dumps(message)
    message_hash = SHA256.new(data=message_json.encode())

    # Sign the hash with the private DSA key of ATM
    signer = DSS.new(dsa_private_key_atm, 'fips-186-3')
    signature = signer.sign(message_hash)

    # Encode `message_json` and `signature` with base64
    signed_message = base64.b64encode(message_json.encode()).decode()
    signature_string = base64.b64encode(signature).decode()

    # Prepare the full message
    full_message = {"signed_user_account": signed_message, "signature": signature_string, "encryption": "DSA"}

    return json.dumps(full_message).encode(FORMAT)


def check_funds(id):
    RSAEncryption(id, action_req="checkFunds")
         
# def check_funds(id):
#     print("-------------------------------------------------")
#     print("[Hello! This is ATM 1]")
#     print("Checking funds...")

#     # checking funds using the dictionary
#     if option == '1': # RSA
#         response = RSAEncryption(id, action_req="checkFunds")
#     elif option == '2': # DSA
#         print ("this is 2")
#         message_to_send = DSASignature(id,action_req="checkFunds")
#         client.send(message_to_send)
#         print ("this is 3")
#         response = client.recv(1024).decode(FORMAT)
#     print(response)


#prompt to see what encryption to use
print("[Hello! This is ATM 1]")
print("How would you like to encypt your data?")
print("[1] RSA encryption")
print("[2] DSA Encryption")

def rsa_or_dsa(client):
    global option
    option = input()
    if option == '1':
        print("Please enter you ID:")
        id = input()
        print("Please enter your password:")
        password = input()
        message_to_send = RSAEncryption(id, password= password)
        if message_to_send is not None:
            client.send(message_to_send)
        else:
            return

        client.send(message_to_send)
        # Add these lines to handle the server response for DSA
        response = client.recv(1024).decode(FORMAT)
        print(response)
        if response == "Login successful!":
            print("Login successful!")
            menu
            (id)
        else:
            print("Login failed")
    elif option == '2':
        print("-------------------------------------------------")
        print("[Hello! This is ATM 1]")
        print("Please enter your ID")
        id = input()
        print("Please enter your password")
        password = input()
        message_to_send = DSASignature(id, password, dsa_private_key_atm)
        client.send(message_to_send)
        # Add these lines to handle the server response for DSA
        response = client.recv(1024).decode(FORMAT)
        print(response)
        if response == "Login successful!":
            print("Login successful!")
            menu(id)
        else:
            print("Login failed")
    else:
        print("\nPlease enter a valid option\n")
        rsa_or_dsa(client)





rsa_or_dsa(client)


# Disconnect from the server

client.close()
