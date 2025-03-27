import random
import string
from aes256 import AES256  

class PasswordGenerator:
    def __init__(self, encryption_key):
        """Initialize with an AES-256 encryption key"""
        self.aes = AES256(encryption_key)
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.password_length = 10

    def _meets_requirements(self, password):
        """Check if password meets strong requirements"""
        return (
            len(password) == self.password_length
            and any(c.isupper() for c in password)
            and any(c.islower() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in self.special_chars for c in password)
        )

    def _adjust_to_requirements(self, password):
        """Ensure the password meets all requirements"""
        password = list(password)
        requirements = [
            (lambda c: c.isupper(), string.ascii_uppercase),
            (lambda c: c.islower(), string.ascii_lowercase),
            (lambda c: c.isdigit(), string.digits),
            (lambda c: c in self.special_chars, self.special_chars),
        ]
        for check, chars in requirements:
            if not any(check(c) for c in password):
                password[random.randint(0, self.password_length - 1)] = random.choice(chars)
        return "".join(password)

    def _generate_base_password(self, combined):
        """Generate a base password from combined phrases"""
        base = combined[:8] if len(combined) >= 8 else combined.ljust(8, random.choice(string.ascii_lowercase))
        password = list(base)
        for chars in [string.ascii_uppercase, string.digits, self.special_chars]:
            password[random.randint(0, 7)] = random.choice(chars)
        while len(password) < self.password_length:
            password.append(random.choice(string.ascii_letters + string.digits + self.special_chars))
        random.shuffle(password)
        return "".join(password[:self.password_length])

    def generate_from_phrases(self, phrases):
        """Generate a 10-character strong password from one or more phrases"""
        if not phrases or not all(isinstance(p, str) for p in phrases):
            raise ValueError("Phrases must be non-empty strings")
        combined = "".join(phrases).replace(" ", "").lower()
        if not combined:
            raise ValueError("Combined phrases must not be empty")
        password = self._generate_base_password(combined)
        return self._adjust_to_requirements(password) if not self._meets_requirements(password) else password

    def validate_and_adjust(self, password):
        """Validate and adjust a user-entered password to meet requirements"""
        if not isinstance(password, str):
            raise ValueError("Password must be a string")
        password = password[:self.password_length].ljust(self.password_length, random.choice(string.ascii_lowercase))
        return self._adjust_to_requirements(password) if not self._meets_requirements(password) else password

    def encrypt_password(self, password):
        """Encrypt the password using AES-256"""
        if not isinstance(password, str):
            raise ValueError("Password must be a string")
        return self.aes.encrypt_full(password.encode())


class PasswordManager:
    def __init__(self):
        self.key = b'12345678901234567890123456789012'
        self.generator = PasswordGenerator(self.key)

    def generate_password_from_phrases(self):
        phrases = input("Enter your words, separated by commas: ").split(",")
        try:
            generated_pwd = self.generator.generate_from_phrases(phrases)
            print(f"Generated from phrases {phrases}: {generated_pwd}")
            encrypted_pwd = self.generator.encrypt_password(generated_pwd)
            print(f"Encrypted (hex): {encrypted_pwd.hex()}")
        except ValueError as e:
            print(f"Error: {e}")

    def validate_and_adjust_password(self):
        user_pwd = input("Enter your password: ")
        try:
            adjusted_pwd = self.generator.validate_and_adjust(user_pwd)
            print(f"User-entered '{user_pwd}' adjusted to: {adjusted_pwd}")
            encrypted_pwd = self.generator.encrypt_password(adjusted_pwd)
            print(f"Encrypted (hex): {encrypted_pwd.hex()}")
        except ValueError as e:
            print(f"Error: {e}")

    def choose_option(self):
        while True:
            print("\n1. Generate password from phrases")
            print("2. Validate and adjust user-entered password")
            print("3. Exit")
            try:
                option = int(input("Enter your option: "))
                if option == 1:
                    self.generate_password_from_phrases()
                elif option == 2:
                    self.validate_and_adjust_password()
                elif option == 3:
                    print("Exiting...")
                    break
                else:
                    print("Invalid option. Please try again.")
            except ValueError:
                print("Invalid input. Please enter a number.")


def main():
    manager = PasswordManager()
    manager.choose_option()


if __name__ == "__main__":
    main()
