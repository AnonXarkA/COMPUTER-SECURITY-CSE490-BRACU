from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import hashlib
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.backends import default_backend

# ==================== AES Operations ====================
def aes_encrypt(plaintext, key, mode, iv=None):
    cipher = AES.new(key, mode, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return base64.b64encode(ciphertext).decode('utf-8')

def aes_decrypt(ciphertext, key, mode, iv=None):
    cipher = AES.new(key, mode, iv=iv)
    decrypted_data = cipher.decrypt(base64.b64decode(ciphertext))
    return unpad(decrypted_data, AES.block_size)

def handle_aes_operations():
    mode = input("Enter AES mode (ECB/CBC): ").upper()
    operation = input("Enter operation (Encrypt/Decrypt): ").capitalize()
    data = input("Enter plaintext/ciphertext: ")
    key = input("Enter AES key (16/24/32 bytes): ").encode('utf-8')

    if mode not in ['ECB', 'CBC']:
        print("Invalid AES mode.")
        return
    if operation not in ['Encrypt', 'Decrypt']:
        print("Invalid operation.")
        return

    if operation == 'Encrypt':
        plaintext = data.encode('utf-8')
        if mode == 'ECB':
            encrypted_data = aes_encrypt(plaintext, key, AES.MODE_ECB)
            print("Ciphertext:", encrypted_data)
        else:
            iv = get_random_bytes(AES.block_size)
            encrypted_data = aes_encrypt(plaintext, key, AES.MODE_CBC, iv)
            print("IV:", base64.b64encode(iv).decode('utf-8'))
            print("Ciphertext:", encrypted_data)
    else:
        if mode == 'ECB':
            decrypted_data = aes_decrypt(data, key, AES.MODE_ECB)
        else:
            iv = input("Enter initialization vector (IV) in Base64 format: ")
            iv = base64.b64decode(iv)
            decrypted_data = aes_decrypt(data, key, AES.MODE_CBC, iv)
        print("Plaintext:", decrypted_data.decode('utf-8'))

# ==================== RSA Operations ====================
def rsa_encrypt(plaintext, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(plaintext.encode())
    return ciphertext.hex()

def rsa_decrypt(ciphertext, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(bytes.fromhex(ciphertext))
    return decrypted_message.decode()

def handle_rsa_operations():
    operation = input("Enter operation (Encrypt/Decrypt): ").lower()
    plaintext_ciphertext = input("Enter the plaintext or ciphertext: ")
    
    if operation == "encrypt":
        public_key_str = input("Enter RSA public key: ")
        try:
            public_key = RSA.import_key(public_key_str)
            encrypted_text = rsa_encrypt(plaintext_ciphertext, public_key)
            print("Encrypted text:", encrypted_text)
        except Exception as e:
            print("An error occurred:", str(e))
    elif operation == "decrypt":
        private_key_str = input("Enter RSA private key: ")
        try:
            private_key = RSA.import_key(private_key_str)
            decrypted_text = rsa_decrypt(plaintext_ciphertext, private_key)
            print("Decrypted text:", decrypted_text)
        except Exception as e:
            print("An error occurred:", str(e))
    else:
        print("Invalid operation. Please choose 'Encrypt' or 'Decrypt'.")

# ==================== Hashing Operations ====================
def calculate_hash(plaintext, hash_mode):
    try:
        if hash_mode.upper() == 'SHA1':
            hash_object = hashlib.sha1()
        elif hash_mode.upper() == 'SHA256':
            hash_object = hashlib.sha256()
        else:
            return 'Invalid hash mode'
        hash_object.update(plaintext.encode('utf-8'))
        return hash_object.hexdigest()
    except Exception as e:
        return str(e)

def handle_hash_operations():
    plaintext = input("Enter the plaintext: ")
    hash_mode = input("Enter the hash mode (SHA1/SHA256): ")
    hash_value = calculate_hash(plaintext, hash_mode)
    print("Hash value:", hash_value)

# ==================== Digital Signature Operations ====================
def generate_rsa_key_pair():
    return RSA.generate(2048)

def sign_message(message, private_key):
    hash_value = SHA256.new(message.encode())
    signer = pkcs1_15.new(private_key)
    return signer.sign(hash_value)

def verify_signature(message, signature, public_key):
    hash_value = SHA256.new(message.encode())
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(hash_value, signature)
        return True
    except (ValueError, TypeError):
        return False

def handle_signature_operations():
    operation = input("Enter the operation (Generation/Verification): ").lower()
    
    if operation == "generation":
        message = input("Enter the message to be signed: ")
        key = generate_rsa_key_pair()
        private_key = key.export_key().decode()
        public_key = key.publickey().export_key().decode()
        signature = sign_message(message, key).hex()
        print("\nPrivate Key:\n", private_key)
        print("\nPublic Key:\n", public_key)
        print("\nSignature:\n", signature)
    elif operation == "verification":
        message = input("Enter the message: ")
        signature = bytes.fromhex(input("Enter the signature: "))
        public_key_str = input("Enter the RSA public key: ")
        try:
            public_key = RSA.import_key(public_key_str)
            if verify_signature(message, signature, public_key):
                print("Signature is valid.")
            else:
                print("Signature is invalid.")
        except Exception as e:
            print("Error:", str(e))
    else:
        print("Invalid operation. Please choose 'Generation' or 'Verification'.")

# ==================== MAC Operations ====================
def generate_mac(message, algorithm, secret_key=b'your_secret_key'):
    mac_algorithm = hmac.HMAC(secret_key, algorithm, backend=default_backend())
    mac_algorithm.update(message.encode('utf-8'))
    return mac_algorithm.finalize().hex()

def handle_mac_operations():
    message = input("Enter the message: ")
    print("\nAvailable MAC algorithms:")
    print("1. HMAC-SHA256")
    print("2. HMAC-SHA512")
    choice = input("Select MAC algorithm (1 or 2): ")
    
    if choice == '1':
        algorithm = hashes.SHA256()
    elif choice == '2':
        algorithm = hashes.SHA512()
    else:
        print("Invalid choice.")
        return
    
    mac_value = generate_mac(message, algorithm)
    print("\nGenerated MAC:", mac_value)

# ==================== Main Menu ====================
def main():
    while True:
        print("\n===== Cryptographic Operations Menu =====")
        print("1. AES Encryption/Decryption")
        print("2. RSA Encryption/Decryption")
        print("3. Hashing")
        print("4. Digital Signatures")
        print("5. Message Authentication Code (MAC)")
        print("6. Exit")
        
        choice = input("\nSelect an operation (1-6): ")
        
        if choice == '1':
            handle_aes_operations()
        elif choice == '2':
            handle_rsa_operations()
        elif choice == '3':
            handle_hash_operations()
        elif choice == '4':
            handle_signature_operations()
        elif choice == '5':
            handle_mac_operations()
        elif choice == '6':
            print("Exiting program...")
            break
        else:
            print("Invalid choice. Please select 1-6.")
        
        input("\nPress Enter to continue...")

if __name__ == '__main__':
    main()