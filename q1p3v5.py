import hashlib
from Crypto.Cipher import AES
import base64
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# Function to verify the hash of a given file against a provided hash
def verify_file_hash(file_path, hash_file_path):
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    with open(hash_file_path, 'r') as f:
        hashes = f.readlines()

    for hash_line in hashes:
        name, hash_value = hash_line.strip().split()
        if name in file_path:
            return file_hash == hash_value

    return False

# AESCrypto class for decryption
class AESCrypto:
    def md5_hash(self, text):
        h = hashlib.md5()
        h.update(text.encode())
        return h.hexdigest()

    def __init__(self, key):
        self.key = self.md5_hash(key)

    def decrypt(self, enctext):
        enctext = base64.b64decode(enctext)
        iv = enctext[:16]
        crypto = AES.new(self.key.encode(), AES.MODE_CBC, iv)
        decrypted_data = crypto.decrypt(enctext[16:])
        
        # Unpad the decrypted data
        padding_length = decrypted_data[-1]  # directly get the last byte as an integer
        return decrypted_data[:-padding_length].decode('utf-8')

# Verify the hashes of the files
directory_path = 'Files/'
files_to_verify = [directory_path + 'publickey.pem', 
                   directory_path + 'part1.txt.enc', 
                   directory_path + 'part1.txt.sig']

for file in files_to_verify:
    if verify_file_hash(file, directory_path + 'part1.sha256'):
        print(f"Hash for {file} matches!")
    else:
        print(f"Hash for {file} does NOT match!")

# Decrypt using the AESCrypto class
aes = AESCrypto('sfhaCS2023')
with open(directory_path + 'part1.txt.enc', 'rb') as f:
    encrypted_data = f.read()

decrypted_text = aes.decrypt(encrypted_data)
print("\nDecrypted Text:\n", decrypted_text)

