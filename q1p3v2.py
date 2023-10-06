import hashlib
from Crypto.Cipher import AES
import base64

def verify_file_hash(file_path, hashes_dict):
    """Compute the SHA-256 hash of a file and compare it to a provided hash."""
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    filename = file_path.split('/')[-1]
    provided_hash = hashes_dict.get(filename, None)
    if not provided_hash:
        print(f"No hash found for {filename} in the hash file.")
        return False

    return file_hash == provided_hash

def decrypt_aes_without_unpad(file_path, key):
    """
    Decrypt an AES encrypted file without immediately removing padding.
    
    :param file_path: Path to the encrypted file.
    :param key: Decryption key.
    :return: Decrypted content as bytes.
    """
    # Use SHA-256 hash of the key to get a 16-byte key for AES-128
    key = hashlib.sha256(key.encode()).digest()[:16]

    # Read the encrypted data (assuming it's base64 encoded)
    with open(file_path, 'rb') as f:
        encrypted_data = base64.b64decode(f.read())

    # AES decryption (assuming IV is prefixed to the encrypted data)
    cipher = AES.new(key, AES.MODE_CBC, iv=encrypted_data[:16])
    decrypted_data = cipher.decrypt(encrypted_data[16:])
    
    return decrypted_data

# Read hashes from the part1.sha256 into a dictionary
hashes_dict = {}
with open('Files/part1.sha256', 'r') as f:
    lines = f.readlines()
    for line in lines:
        parts = line.strip().split()
        if len(parts) == 2:
            filename, file_hash = parts
            hashes_dict[filename] = file_hash

# File paths to verify
files_to_verify = [
    'Files/publickey.pem', 
    'Files/part1.txt.enc', 
    'Files/part1.txt.sig'
]

# Verify the file hashes
for file in files_to_verify:
    if verify_file_hash(file, hashes_dict):
        print(f"Hash for {file} matches!")
    else:
        print(f"Hash for {file} does NOT match!")

# Decrypt part1.txt.enc without immediate unpadding
decrypted_data_bytes = decrypt_aes_without_unpad('Files/part1.txt.enc', 'sfhaCS2023')

# Print the last 32 bytes to inspect the padding
print("\nLast 32 bytes of decrypted data:")
print("---------------------------------")
print(decrypted_data_bytes[-32:])
