import hashlib

# 'Files' directory
directory_path = 'Files/'

files_to_verify = [
    directory_path + 'publickey.pem', 
    directory_path + 'part1.txt.enc', 
    directory_path + 'part1.txt.sig'
]

def verify_file_hash(file_path, hashes_dict):
    # Calculate the SHA-256 hash of the file
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    # Extract the filename from the path
    filename = file_path.split('/')[-1]

    # Get the provided hash from the dictionary
    provided_hash = hashes_dict.get(filename, None)
    if not provided_hash:
        print(f"No hash found for {filename} in the hash file.")
        return False

    return file_hash == provided_hash

# Read hashes from the part1.sha256 into a dictionary
hashes_dict = {}
with open(directory_path + 'part1.sha256', 'r') as f:
    lines = f.readlines()
    for line in lines:
        parts = line.strip().split()
        if len(parts) == 2:
            filename, file_hash = parts
            hashes_dict[filename] = file_hash

# Verify the files
for file in files_to_verify:
    if verify_file_hash(file, hashes_dict):
        print(f"Hash for {file} matches!")
    else:
        print(f"Hash for {file} does NOT match!")