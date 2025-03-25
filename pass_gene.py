import secrets
import string
import csv
from nltk.corpus import words

# Download a dictionary word list (first-time use)
try:
    words.words()
except LookupError:
    import nltk
    nltk.download('words')

# Load dictionary words (set for fast lookup)
word_list = set(words.words())

def generate_secure_password(length=16):
    """Generates a strong password that avoids dictionary words"""
    characters = string.ascii_letters + string.digits + string.punctuation + " "  # Added symbols
    
    while True:
        password = ''.join(secrets.choice(characters) for _ in range(length))
        
        # Check if the password contains dictionary words
        if not any(word.lower() in word_list for word in password.split()):
            return password  # Return only if it's safe

# Generate multiple passwords
passwords = [generate_secure_password(12)]

def save_passwords(passwords, filename="passwords.csv"):
    file_exists = False
    try:
        with open(filename, "r"):
            file_exists = True
    except FileNotFoundError:
        pass
    
    with open(filename, "a", newline="") as f:
        writer = csv.writer(f)
        
        # Write header only if file is new
        if not file_exists:
            writer.writerow(["password"])
        
        for password in passwords:
            writer.writerow([password])

# Save passwords
save_passwords(passwords)

print("Passwords saved successfully to passwords.csv!")
