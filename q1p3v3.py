import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_aes(file_path, key):
    """Decrypt an AES-128 encrypted file."""
    # Use SHA-256 hash of the key to get a 16-byte key for AES-128
    key = hashlib.sha256(key.encode()).digest()[:16]

    # Read the encrypted data from the file
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    # Extract the IV (first 16 bytes) and the cipher-text
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Decrypt using AES-128 in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    return decrypted_data.decode('utf-8')

# Decrypt part1.txt.enc
decrypted_text = decrypt_aes('Files/part1.txt.enc', 'sfhaCS2023')
print(decrypted_text)
