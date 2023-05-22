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


HEADER = 64
PORT = 5061
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)

# CREATE SOCKET ########################################
########################################################
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

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
    RSAEncryption(id,action_req= "withdraw", option = amount)
   

def deposit(id, amount):
    RSAEncryption(id,action_req= "withdraw", option = amount)

def Account_activities(id, activities):
    RSAEncryption(id,action_req= "activities")


# Uncomment the following lines to test the checkFunds, withdraw, and deposit functions

#checkFunds()
#withdraw(100)
#deposit(200)



         

def menu(id):
    print("What would you like to do?")
    print("1. Check account balance")
    print("2. Withdrawl")
    print("3. Deposit")
    print("4. Account activities")
    print("5. Exit")
    
    option = input()

    if option == '1':
        
        check_funds(id)
        menu(id)

    elif option == '2':
        
        withdraw(id)
        menu(id)

    elif option == '3':
        
        deposit(id)
        menu(id)

    elif option == '4':
        pass

    elif option =='5':
        client.close()

    else:
        print("Invalid option.\n")
        menu(id)
def RSAEncryption(id ,password=None, action_req=None, option = None):
    print("-------------------------------------------------")
    print("[Hello! This is ATM 1]")
    if id == "":
        id = input("input id: ")


    # this will take id and passowrd and make it into a dictionary using json.dumps
    user_account = json.dumps({'ID': id, 'password': password, 'action':action_req, 'option': option}).encode(FORMAT)
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
    message = json.dumps({"encrypted_user_account": encrypted_user_account, 
                        "Digital_Signature": DS_E_User_Acount}).encode(FORMAT)
    
    client.send(message)
    
    if password:
        if client.recv(1024).decode(FORMAT) == "Login successful!":
            print("Login successful!")
            menu(id)
        else:
            print("login failed")

            print("Please enter you ID")
            id = input()
            print("Please enter your password")
            password = input()
            RSAEncryption(id, password)
    else:
        print(client.recv(1024).decode(FORMAT))
        

    
def DSAEncryption():
    print("-------------------------------------------------")
    print("[Hello! This is ATM 1]")
    print("Please enter your ID")
    id = input()
    print("Please enter your password")
    password = input()

    # Convert ID and password into a dictionary using json.dumps
    user_account = json.dumps({'ID': id, 'password': password}).encode(FORMAT)
    print(user_account) # Calculate the hash of the user account using SHA256
    hash_object = SHA256.new(user_account)

    # Create a signer object using the ATM1 private key
    signer = DSS.new(dsa_private_key_atm_1, 'fips-186-3')

    # Sign the hash of the user account
    signature = signer.sign(hash_object)

    # Encode the user account, hash, and signature in base64
    encoded_user_account = base64.b64encode(user_account).decode(FORMAT)
    encoded_hash = base64.b64encode(hash_object.digest()).decode(FORMAT)
    encoded_signature = base64.b64encode(signature).decode(FORMAT)

    # Create the message that will be sent, containing the encoded user account, hash, and signature
    message = json.dumps({'encrypted_user_account': encoded_user_account,
                          'hash': encoded_hash,
                          'signature': encoded_signature}).encode(FORMAT)

    print(message)
    client.send(message)
    
    print(client.recv(1024).decode(FORMAT))

         
def check_funds(id):
    RSAEncryption(id, action_req="checkFunds")
    

#prompt to see what encryption to use
print("[Hello! This is ATM 1]")
print("How would you like to encypt your data?")
print("[1] RSA encryption")
print("[2] DSA Encryption")

# choose encryption
def rsa_or_dsa():
    option = input()
    if option == '1':
        print("Please enter you ID:")
        id = input()
        print("Please enter your password:")
        password = input()
        RSAEncryption(id, password)
    elif option == '2':
        DSAEncryption()
    else:
        print("\nPease enter a valid option\n")
        rsa_or_dsa()

rsa_or_dsa()


# Disconnect from the server

client.close()