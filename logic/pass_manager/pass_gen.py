import random
import string
from typing import List, Union
# Assuming aes256 is a custom module - replace with actual import if different
try:
    from aes256 import AES256
except ImportError:
    # Mock implementation for debugging
    class AES256:
        def __init__(self, key): self.key = key
        def encrypt_full(self, data): return data
    print("Warning: Using mock AES256 implementation")

class PasswordGenerator:
    def __init__(self, encryption_key: bytes, password_length: int = 12):
        """Initialize with encryption key and customizable length"""
        if len(encryption_key) != 32:
            raise ValueError("Encryption key must be 32 bytes")
        self.aes = AES256(encryption_key)
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.password_length = max(password_length, 8)  # Minimum 8 chars
        
    def _meets_requirements(self, password: str) -> bool:
        """Check if password meets strong requirements"""
        return (
            len(password) >= self.password_length and
            any(c.isupper() for c in password) and
            any(c.islower() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in self.special_chars for c in password)
        )

    def _adjust_to_requirements(self, password: str) -> str:
        """Ensure password meets all requirements"""
        pwd_list = list(password.ljust(self.password_length, 'a'))
        requirements = [
            (lambda c: c.isupper(), string.ascii_uppercase),
            (lambda c: c.islower(), string.ascii_lowercase),
            (lambda c: c.isdigit(), string.digits),
            (lambda c: c in self.special_chars, self.special_chars),
        ]
        
        for i, (check, chars) in enumerate(requirements):
            if not any(check(c) for c in pwd_list):
                pwd_list[i] = random.choice(chars)
                
        while len(pwd_list) < self.password_length:
            pwd_list.append(random.choice(string.ascii_letters + string.digits + self.special_chars))
            
        random.shuffle(pwd_list)
        return "".join(pwd_list[:self.password_length])

    def _generate_base_password(self, combined: str) -> str:
        """Generate base password from combined phrases"""
        base = combined[:self.password_length] if len(combined) >= self.password_length else \
               combined.ljust(self.password_length, random.choice(string.ascii_lowercase))
        pwd_list = list(base)
        
        # Ensure minimum requirements
        char_sets = [string.ascii_uppercase, string.ascii_lowercase, 
                    string.digits, self.special_chars]
        for i, chars in enumerate(char_sets):
            pwd_list[i] = random.choice(chars)
            
        random.shuffle(pwd_list)
        return "".join(pwd_list[:self.password_length])

    def generate_from_phrases(self, phrases: List[str]) -> str:
        """Generate strong password from phrases"""
        if not phrases or not all(isinstance(p, str) and p.strip() for p in phrases):
            raise ValueError("Phrases must be non-empty strings")
            
        combined = "".join(p.strip() for p in phrases).lower()
        password = self._generate_base_password(combined)
        
        return self._adjust_to_requirements(password) if not self._meets_requirements(password) else password

    def validate_and_adjust(self, password: str) -> str:
        """Validate and adjust user-entered password"""
        if not isinstance(password, str):
            raise ValueError("Password must be a string")
        if not password.strip():
            raise ValueError("Password cannot be empty")
            
        return self._adjust_to_requirements(password)

    def encrypt_password(self, password: str) -> bytes:
        """Encrypt password using AES-256"""
        if not isinstance(password, str):
            raise ValueError("Password must be a string")
        try:
            return self.aes.encrypt_full(password.encode('utf-8'))
        except Exception as e:
            raise ValueError(f"Encryption failed: {e}")

class PasswordManager:
    def __init__(self):
        # Generate a random key instead of hardcoding
        self.key = random.randbytes(32)  # 32 bytes for AES-256
        self.generator = PasswordGenerator(self.key)

    def generate_password_from_phrases(self) -> None:
        """Handle password generation from phrases"""
        try:
            phrases = [p.strip() for p in input("Enter words (comma-separated): ").split(",") if p.strip()]
            if not phrases:
                raise ValueError("No valid phrases provided")
            pwd = self.generator.generate_from_phrases(phrases)
            encrypted = self.generator.encrypt_password(pwd)
            print(f"Generated password: {pwd}")
            print(f"Encrypted (hex): {encrypted.hex()}")
        except ValueError as e:
            print(f"Error: {e}")

    def validate_and_adjust_password(self) -> None:
        """Handle password validation and adjustment"""
        try:
            user_pwd = input("Enter your password: ").strip()
            adjusted = self.generator.validate_and_adjust(user_pwd)
            encrypted = self.generator.encrypt_password(adjusted)
            print(f"Original: '{user_pwd}'")
            print(f"Adjusted: '{adjusted}'")
            print(f"Encrypted (hex): {encrypted.hex()}")
        except ValueError as e:
            print(f"Error: {e}")

    def choose_option(self) -> None:
        """Main menu loop"""
        while True:
            print("\nPassword Manager")
            print("1. Generate from phrases")
            print("2. Validate/adjust password")
            print("3. Exit")
            
            try:
                option = input("Select option (1-3): ").strip()
                if option == "1":
                    self.generate_password_from_phrases()
                elif option == "2":
                    self.validate_and_adjust_password()
                elif option == "3":
                    print("Exiting...")
                    break
                else:
                    print("Please select 1, 2, or 3")
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                print(f"Unexpected error: {e}")

def main():
    try:
        manager = PasswordManager()
        manager.choose_option()
    except Exception as e:
        print(f"Failed to start manager: {e}")

if __name__ == "__main__":
    main()