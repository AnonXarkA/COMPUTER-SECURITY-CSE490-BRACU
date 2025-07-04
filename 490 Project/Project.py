from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
import rsa
import os
from OpenSSL import crypto

# from pyfiglet import figlet_format
# from pyfiglet import Figlet
# from termcolor import colored
#
# text = Figlet(font="standard")
# print(colored(text.renderText("AnonXArkA"),"red"))
# # print(figlet_format("",font="standard"))


key = RSA.generate(2048)   # This is for Generating RSA key pair for digital signatures


with open("private_key.pem", "wb") as file:     # RSA private key
    file.write(key.export_key(format='PEM'))


public_key = key.publickey() #RSA public key for verification
# print(public_key)

with open("public_key.pem", "wb") as file:              #this public key for other group
    file.write(public_key.export_key(format='PEM'))

# with open('public_key.pem', 'r') as pem_file:     # Read the PEM file
#     pem_data = pem_file.read()
# public_keys = crypto.load_publickey(crypto.FILETYPE_PEM, pem_data)
# # print(public_keys)


encryption_key = os.urandom(32)     # generates random encryption key with 256-bit key AES encryption. Strong encryptionnnnnn!!


with open("secret.txt", "rb") as file:   #reading the content of the secret file.
    secrettext = file.read()
    # print(secrettext)

padding_length = 32 - (len(secrettext) % 32)
secrettext += bytes([padding_length]) * padding_length   # padding the plaintext with 32bytes
# print(secrettext)



cipher = AES.new(encryption_key, AES.MODE_ECB)  # here creates an AES cipher object with the encryption key in AES ecb mode
ciphertext = cipher.encrypt(secrettext)        #encryptingggg
# print(ciphertext)


#hashing using sha256 and signing it using rsa private key
hash = SHA256.new(ciphertext)
# print(hash)
signer = PKCS1_v1_5.new(key)
signature = signer.sign(hash)
# print(signature)

#saving encrypted file, signature, encryption key in files for future use
with open("secret_encrypted.bin", "wb") as file:    #encrypted fileee!!
    file.write(ciphertext)
with open("signature.txt", "wb") as file:
    file.write(signature)
with open("encryption_key.bin", "wb") as file:
    file.write(encryption_key)

# with open("signature.bin", "rb") as file:
#     ss = file.read()
#     print(ss)

print("Encryption Successful. Ready to send another group")










