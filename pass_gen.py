import random
import string
from aes256 import AES256  # Assuming aes256.py is in the same directory

class PasswordGenerator:    
    def __init__(self, encryption_key):
        """Initialize with an AES-256 encryption key"""
        self.aes = AES256(encryption_key)
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.min_length = 10
        self.max_length = 10

    def _meets_requirements(self, password):
        """Check if password meets strong requirements"""
        if len(password) != 10:
            return False
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in self.special_chars for c in password)
        return has_upper and has_lower and has_digit and has_special

    def generate_from_phrases(self, phrases):
        """Generate a 10-character strong password from one or more phrases"""
        if not phrases or not all(isinstance(p, str) for p in phrases):
            raise ValueError("Phrases must be non-empty strings")
        
        # Combine phrases and clean
        combined = "".join(phrases).replace(" ", "").lower()
        if not combined:
            raise ValueError("Combined phrases must not be empty")

        # Take first characters or random subset if too short
        base = ""
        if len(combined) >= 8:
            base = combined[:8]  # Take first 8 characters
        else:
            base = combined + random.choice(string.ascii_lowercase) * (8 - len(combined))

        # Ensure requirements
        password = list(base)
        password[random.randint(0, 7)] = random.choice(string.ascii_uppercase)  # Add uppercase
        password[random.randint(0, 7)] = random.choice(string.digits)           # Add digit
        password[random.randint(0, 7)] = random.choice(self.special_chars)      # Add special

        # Fill to 10 characters with random strong characters
        while len(password) < 10:
            password.append(random.choice(string.ascii_letters + string.digits + self.special_chars))
        
        # Shuffle and truncate to exactly 10
        random.shuffle(password)
        password = "".join(password[:10])

        # Verify and adjust if needed
        while not self._meets_requirements(password):
            password = list(password)
            if not any(c.isupper() for c in password):
                password[random.randint(0, 9)] = random.choice(string.ascii_uppercase)
            elif not any(c.islower() for c in password):
                password[random.randint(0, 9)] = random.choice(string.ascii_lowercase)
            elif not any(c.isdigit() for c in password):
                password[random.randint(0, 9)] = random.choice(string.digits)
            elif not any(c in self.special_chars for c in password):
                password[random.randint(0, 9)] = random.choice(self.special_chars)
            password = "".join(password)

        return password

    def validate_and_adjust(self, password):
        """Validate and adjust a user-entered password to meet requirements"""
        if not isinstance(password, str):
            raise ValueError("Password must be a string")
        
        # Truncate or pad to 10 characters
        if len(password) > 10:
            password = password[:10]
        elif len(password) < 10:
            password += random.choice(string.ascii_lowercase) * (10 - len(password))

        # Check and adjust for requirements
        if not self._meets_requirements(password):
            password = list(password)
            if not any(c.isupper() for c in password):
                password[random.randint(0, 9)] = random.choice(string.ascii_uppercase)
            if not any(c.islower() for c in password):
                password[random.randint(0, 9)] = random.choice(string.ascii_lowercase)
            if not any(c.isdigit() for c in password):
                password[random.randint(0, 9)] = random.choice(string.digits)
            if not any(c in self.special_chars for c in password):
                password[random.randint(0, 9)] = random.choice(self.special_chars)
            password = "".join(password)

        return password

    def encrypt_password(self, password):
        """Encrypt the password using AES-256"""
        if not isinstance(password, str):
            raise ValueError("Password must be a string")
        return self.aes.encrypt_full(password.encode())

def main():
    # Example encryption key (32 bytes)
    key = b'12345678901234567890123456789012'
    generator = PasswordGenerator(key)

    # Test phrase-based generation
    phrases = ["MyDog", "Spot", "123"]
    try:
        generated_pwd = generator.generate_from_phrases(phrases)
        print(f"Generated from phrases {phrases}: {generated_pwd}")
        encrypted_pwd = generator.encrypt_password(generated_pwd)
        print(f"Encrypted (hex): {encrypted_pwd.hex()}")
    except ValueError as e:
        print(f"Error: {e}")

    # Test user-entered password
    user_pwd = "Daniel@2410"
    try:
        adjusted_pwd = generator.validate_and_adjust(user_pwd)
        print(f"User-entered '{user_pwd}' adjusted to: {adjusted_pwd}")
        encrypted_pwd = generator.encrypt_password(adjusted_pwd)
        print(f"Encrypted (hex): {encrypted_pwd.hex()}")
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()