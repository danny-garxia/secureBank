from Crypto.PublicKey import DSA
from Crypto.IO import PEM

# Generate a DSA key
key = DSA.generate(2048)

# Save the private key into a file
with open('dsa_private_key.pem', 'wb') as f:
    f.write(key.export_key(format='PEM'))

# Save the public key into a file
with open('dsa_public_key.pem', 'wb') as f:
    f.write(key.publickey().export_key(format='PEM'))
