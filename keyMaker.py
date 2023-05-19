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
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization




# Generate DSA ATM1's private key
dsa_atm1_private_key = dsa.generate_private_key(key_size=1024)
dsa_atm1_private_pem = dsa_atm1_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open('private-key-atm-1-dsa.pem', 'wb') as prv_file:
    prv_file.write(dsa_atm1_private_pem)

# Generate ATM1's public key
dsa_atm1_public_key = dsa_atm1_private_key.public_key()
dsa_atm1_public_pem = dsa_atm1_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open('public-key-atm-1-dsa.pem', 'wb') as pub_file:
    pub_file.write(dsa_atm1_public_pem)

# Generate the bank's public key
dsa_bank_private_key = dsa.generate_private_key(key_size=1024)
dsa_bank_private_pem = dsa_bank_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open('private-key-bank-dsa.pem', 'wb') as prv_file:
    prv_file.write(dsa_bank_private_pem)

dsa_bank_public_key = dsa_bank_private_key.public_key()
dsa_bank_public_pem = dsa_bank_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open('public-key-bank-dsa.pem', 'wb') as pub_file:
    pub_file.write(dsa_bank_public_pem)
    
