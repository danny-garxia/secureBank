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


HEADER = 10
PORT = 5054
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
    # Get the data length
    msg_length = len(msg)

    # Convert the length to a string
    strLen = str(msg_length)

    # Pad the header with "0"
    while len(strLen) < HEADER:
        strLen = "0" + strLen

    # The final message
    finalmsg = strLen.encode() + msg
    client.sendall(finalmsg)

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


def RSAEncryption():
    print("-------------------------------------------------")
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

    # need to switch both to base64
    encrypted_user_account_1 = base64.b64encode(encrypted_user_account_1).decode(FORMAT)
    DS_E_User_Acount_1 = base64.b64encode(DS_E_User_Acount_1).decode(FORMAT)


    # this is the messege that we will send which contains the digitaly signed encryoted message
    message = json.dumps({'encrypted_user_account_1': encrypted_user_account_1, 
                        'Digital_Signature': DS_E_User_Acount_1}).encode(FORMAT)


    print(message)
    client.send(message)


def DSAEncryption():
    print("-------------------------------------------------")
    print("[Hello! This is ATM 1]")
    print("Please enter your ID")
    id = input()
    print("Please enter your password")
    password = input()

    # Convert ID and password into a dictionary using json.dumps
    user_account_1 = json.dumps({'ID': id, 'password': password}).encode(FORMAT)

    # Calculate the hash of the user account using SHA256
    hash_object = SHA256.new(user_account_1)

    # Create a signer object using the ATM1 private key
    signer = DSS.new(dsa_private_key_atm_1, 'fips-186-3')

    # Sign the hash of the user account
    signature = signer.sign(hash_object)

    # Encode the user account, hash, and signature in base64
    encoded_user_account = base64.b64encode(user_account_1).decode(FORMAT)
    encoded_hash = base64.b64encode(hash_object.digest()).decode(FORMAT)
    encoded_signature = base64.b64encode(signature).decode(FORMAT)

    # Create the message that will be sent, containing the encoded user account, hash, and signature
    message = json.dumps({'user_account': encoded_user_account,
                          'hash': encoded_hash,
                          'signature': encoded_signature}).encode(FORMAT)

    print(message)
    client.send(message)


#prompt to see what encryption to use
print("[Hello! This is ATM 1]")
print("How would you like to encypt your data?")
print("[1] RSA encryption")
print("[2] DSA Encryption")

# choose encryption
option = input()
if option == '1':
    RSAEncryption()
elif option == '2':
    DSAEncryption()
else:
    print("Pease enter a valid option")
    
def checkFunds():
    print("-------------------------------------------------")
    print("[Hello! This is ATM 1]")
    print("Checking funds...")

    # checking funds using the dictionary
    request_message = json.dumps({'request': 'checkFunds'}).encode(FORMAT)
    # encrypting request message with banks public key using SHA256 encryption
    encrypted_request = public_key_bank.encrypt(request_message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    signature = private_key_atm_1.sign(request_message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    final_output = base64.b64encode(signature + encrypted_request)

    send(final_output)
    result = recv(client)
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


print("What would you like to do?")
print("1. Check account balance")
print("2. Withdrawl")
print("3. Deposit")
print("4. Exit")

option = input()

if option == '1':
    DSAEncryption()
    checkFunds()

elif option == '2':
    DSAEncryption()
    withdraw()

elif option == '3':
    DSAEncryption()
    deposit()

elif option =='4':
    send(DISCONNECT_MESSAGE)

else:
    print("Invalid option.")

def withdraw(amount):
    print("-------------------------------------------------")
    print("[Hello! This is ATM 1]")
    print("Withdrawing funds...")

    # Create a request message with the withdrawal amount
    request_message = json.dumps({'request': 'withdraw', 'amount': amount}).encode(FORMAT)

    # Encrypt the request message using the bank's public key
    encrypted_request = public_key_bank.encrypt(request_message, 0)

    # Sign the encrypted request using the ATM1's private key
    signer = DSS.new(dsa_private_key_atm_1, 'fips-186-3')
    signature = signer.sign(encrypted_request)

    # Encode the encrypted request and signature in base64
    encoded_encrypted_request = base64.b64encode(encrypted_request).decode(FORMAT)
    encoded_signature = base64.b64encode(signature).decode(FORMAT)

    # Create the message that will be sent, containing the encoded encrypted request and signature
    message = json.dumps({'encrypted_request': encoded_encrypted_request,
                          'signature': encoded_signature}).encode(FORMAT)

    # Send the message to the bank
    client.send(message)

    # Receive the response from the bank
    response = recv(client)

    # Decode the response
    response = response.decode(FORMAT)

    # Parse the response as JSON
    response_json = json.loads(response)

    # Extract the encoded encrypted response and signature from the response JSON
    encoded_encrypted_response = response_json['encrypted_response']
    encoded_signature = response_json['signature']

    # Decode the encoded encrypted response and signature from base64
    encrypted_response = base64.b64decode(encoded_encrypted_response)
    signature = base64.b64decode(encoded_signature)

    # Verify the signature using the bank's public key and ATM1's DSA private key
    verifier_bank = DSS.new(dsa_public_key_bank, 'fips-186-3')
    verifier_atm_1 = DSS.new(dsa_private_key_atm_1, 'fips-186-3')

    try:
        verifier_bank.verify(encrypted_response, signature)
        verifier_atm_1.verify(encrypted_response, signature)
        print("Withdrawal successful.")
    except ValueError:
        print("Invalid response received from the bank.")

def deposit(amount):
    print("-------------------------------------------------")
    print("[Hello! This is ATM 1]")
    print("Depositing funds...")

    # Create a request message with the deposit amount
    request_message = json.dumps({'request': 'deposit', 'amount': amount}).encode(FORMAT)

    # Encrypt the request message using the bank's public key
    encrypted_request = public_key_bank.encrypt(request_message, 0)

    # Sign the encrypted request using the ATM1's private key
    signer = DSS.new(dsa_private_key_atm_1, 'fips-186-3')
    signature = signer.sign(encrypted_request)

    # Encode the encrypted request and signature in base64
    encoded_encrypted_request = base64.b64encode(encrypted_request).decode(FORMAT)
    encoded_signature = base64.b64encode(signature).decode(FORMAT)

    # Create the message that will be sent, containing the encoded encrypted request and signature
    message = json.dumps({'encrypted_request': encoded_encrypted_request,
                          'signature': encoded_signature}).encode(FORMAT)

    # Send the message to the bank
    client.send(message)

    # Receive the response from the bank
    response = recv(client)

    # Decode the response
    response = response.decode(FORMAT)

    # Parse the response as JSON
    response_json = json.loads(response)

    # Extract the encoded encrypted response and signature from the response JSON
    encoded_encrypted_response = response_json['encrypted_response']
    encoded_signature = response_json['signature']

    # Decode the encoded encrypted response and signature from base64
    encrypted_response = base64.b64decode(encoded_encrypted_response)
    signature = base64.b64decode(encoded_signature)

    # Verify the signature using the bank's public key and ATM1's DSA private key
    verifier_bank = DSS.new(dsa_public_key_bank, 'fips-186-3')
    verifier_atm_1 = DSS.new(dsa_private_key_atm_1, 'fips-186-3')

    try:
        verifier_bank.verify(encrypted_response, signature)
        verifier_atm_1.verify(encrypted_response, signature)
        print("Deposit successful.")
    except ValueError:
        print("Invalid response received from the bank.")



# Uncomment the following lines to test the checkFunds, withdraw, and deposit functions

checkFunds()
withdraw(100)
deposit(200)

# Disconnect from the server
client.send(DISCONNECT_MESSAGE.encode(FORMAT))
client.close()