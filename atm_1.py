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
    #get the data length
    msg_length = len(client, msg)

    # string the datat length
    strLen = str(msg_length)

    # padd the header with "0"
    while len(strLen) < HEADER:
        strLen = "0" + strLen

    # the final messege
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
