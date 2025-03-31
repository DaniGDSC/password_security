import csv
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import argon2  # Import argon2 for Argon2id

# Read passwords from file
def read_passwords(filename="database/pass_manager/passwords.csv"):
    try:
        with open(filename, "r") as f:
            reader = csv.reader(f)
            passwords = [row[0] for row in reader]
        return passwords
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return []

# Derive AES key from master password using Argon2id
def derive_key(master_password, salt=None):
    """
    Derive a 32-byte AES key from a master password using Argon2id.
    
    Args:
        master_password (str): User's master password
        salt (bytes, optional): Salt for key derivation. If None, generates a new one.
    
    Returns:
        tuple: (key, salt)
    """
    if salt is None:
        salt = get_random_bytes(16)  # 16-byte salt recommended for Argon2
    # Argon2id parameters: memory=64 MiB, parallelism=4, iterations=3
    hasher = argon2.PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)
    hash = hasher.hash(master_password.encode(), salt=salt)
    # Extract 32 bytes from the hash for AES-256 key
    key = base64.b64decode(hash.split('$')[-1])[:32]
    return key, salt

# Encrypt passwords
def encrypt_passwords(passwords, master_password):
    """
    Encrypt passwords using AES-256 CBC with a key derived from master password.
    
    Args:
        passwords (list): List of plaintext passwords
        master_password (str): Master password for key derivation
    
    Returns:
        tuple: (encrypted_passwords, key, iv, salt)
    """
    # Derive key from master password
    key, salt = derive_key(master_password)
    
    # Initialize cipher with key and generate IV
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    
    # Encrypt each password
    encrypted_passwords = []
    for password in passwords:
        padded_data = pad(password.encode('utf-8'), AES.block_size)
        encrypted_password = cipher.encrypt(padded_data)
        encrypted_b64 = base64.b64encode(encrypted_password).decode('utf-8')
        encrypted_passwords.append(encrypted_b64)
    
    return encrypted_passwords, key, iv, salt

# Decrypt passwords
def decrypt_passwords(encrypted_passwords, master_password, iv, salt):
    """
    Decrypt passwords using AES-256 CBC with a key derived from master password.
    
    Args:
        encrypted_passwords (list): List of base64-encoded encrypted passwords
        master_password (str): Master password for key derivation
        iv (bytes): Initialization vector from encryption
        salt (bytes): Salt used during key derivation
    
    Returns:
        list: Decrypted passwords
    """
    # Re-derive key from master password and provided salt
    key, _ = derive_key(master_password, salt)
    
    # Initialize cipher for decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt each password
    decrypted_passwords = []
    for encrypted_b64 in encrypted_passwords:
        encrypted_data = base64.b64decode(encrypted_b64)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        decrypted_password = decrypted_data.decode('utf-8')
        decrypted_passwords.append(decrypted_password)
    
    return decrypted_passwords

# Example usage
if __name__ == "__main__":
    # Read passwords
    passwords = read_passwords()
    if not passwords:
        print("No passwords to process.")
    else:
        # Define a master password
        master_password = "MySecureMasterPass123!"
        
        # Encrypt passwords
        encrypted_data, key, iv, salt = encrypt_passwords(passwords, master_password)
        print(f"Encrypted {len(encrypted_data)} passwords")
        
        # Example of decryption
        decrypted_passwords = decrypt_passwords(encrypted_data, master_password, iv, salt)
        print("First few original, encrypted, and decrypted passwords:")
        for i in range(min(3, len(passwords))):
            print(f"Original: {passwords[i]} | Encrypted (b64): {encrypted_data[i]} | Decrypted: {decrypted_passwords[i]}")
        
        # Demonstrate incorrect master password fails
        try:
            wrong_decrypted = decrypt_passwords(encrypted_data, "WrongPassword!", iv, salt)
        except Exception as e:
            print(f"Decryption with wrong password failed as expected: {str(e)}")