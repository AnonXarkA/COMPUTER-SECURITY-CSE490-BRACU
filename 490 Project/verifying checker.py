from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

# from pyfiglet import figlet_format
# from pyfiglet import Figlet
# from termcolor import colored
#
# text = Figlet(font="standard")
# print(colored(text.renderText("AnonXArkA"),"red"))
# # print(figlet_format("",font="standard"))

with open("public_key.pem", "rb") as file:
    public_key_data = file.read()
    public_key = RSA.import_key(public_key_data)

with open("signature.txt", "rb") as file:
    signature_data = file.read()

with open("secret_encrypted.bin", "rb") as file:
    cipher = file.read()

with open("encryption_key.bin", "rb") as file:
    encryption_key = file.read()

authen_verifier = PKCS1_v1_5.new(public_key)
hash = SHA256.new(cipher)
if authen_verifier.verify(hash, signature_data):
    print("File authenticity and integrity verified.")
else:
    print("File authenticity and integrity could not be verified. There's something that is tempered")



# Decrypt the ciphertext


# from Crypto.Cipher import AES
#
# ciphers = AES.new(encryption_key, AES.MODE_ECB)
# plaintext = ciphers.decrypt(cipher)
#
# # Unpad the plaintext
# padding_length = plaintext[-1]
# plaintext = plaintext[:-padding_length]
#
# # Display the decrypted plaintext
# print("Decrypted plaintext:")
# print(plaintext.decode("utf-8"))


