import csv 
from collections import Counter
from nltk.corpus import words
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# Read passwords from file
def read_passwords(filename="passwords.csv"):
    try:
        with open(filename, "r") as f:
            reader = csv.reader(f)
            passwords = [row[0] for row in reader]
        return passwords
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return []
    
# Encrypt passwords
def encrypt_passwords(passwords, key=None):
    # Generate a random 32-byte key if none provided (AES-256 requires 32 bytes)
    if key is None:
        key = get_random_bytes(32)
    
    # Initialize cipher with key and mode
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    
    # Encrypt each password
    encrypted_passwords = []
    for password in passwords:
        # Convert password to bytes and pad to block size
        padded_data = pad(password.encode('utf-8'), AES.block_size)
        # Encrypt and add to list
        encrypted_password = cipher.encrypt(padded_data)
        # Convert to base64 for easier storage
        encrypted_b64 = base64.b64encode(encrypted_password).decode('utf-8')
        encrypted_passwords.append(encrypted_b64)
    
    return (encrypted_passwords, key, iv)

# Decrypt passwords
def decrypt_passwords(encrypted_passwords, key, iv):
    # Initialize cipher for decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt each password
    decrypted_passwords = []
    for encrypted_b64 in encrypted_passwords:
        # Convert from base64 to bytes
        encrypted_data = base64.b64decode(encrypted_b64)
        # Decrypt and unpad
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        # Convert bytes back to string
        decrypted_password = decrypted_data.decode('utf-8')
        decrypted_passwords.append(decrypted_password)
    
    return decrypted_passwords

# Example usage
if __name__ == "__main__":
    # Read passwords
    passwords = read_passwords()
    if passwords:
        # Encrypt passwords
        encrypted_data, key, iv = encrypt_passwords(passwords)
        print(f"Encrypted {len(encrypted_data)} passwords")
        
        # Example of decryption
        decrypted_passwords = decrypt_passwords(encrypted_data, key, iv)
        print("First few original and decrypted passwords:")
        for i in range(min(3, len(passwords))):
            print(f"Original: {passwords[i]} | Encrypted: {encrypted_data[i]} | Decrypted: {decrypted_passwords[i]}")