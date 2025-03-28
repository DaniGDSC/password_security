import math
import re
import csv
from collections import Counter
from typing import List, Dict, Union, Optional
import nltk
from nltk.corpus import words
from pathlib import Path

class PasswordAnalyzer:
    """Class to handle password strength analysis operations."""
    
    def __init__(self):
        self.word_list = self._load_word_list()
        self.MIN_PASSWORD_LENGTH = 4
        self.SPECIAL_CHARS = r"[!@#$%^&*(),.?\":{}|<>]"

    @staticmethod
    def _load_word_list() -> set:
        """Load NLTK words corpus with error handling."""
        try:
            nltk.data.find('corpora/words')
        except LookupError:
            nltk.download('words', quiet=True)
        try:
            return set(word.lower() for word in words.words())
        except Exception as e:
            print(f"Warning: Failed to load word list: {e}")
            return set()

    def read_passwords_from_csv(self, filename: str) -> List[str]:
        """Read passwords from CSV file with validation."""
        try:
            path = Path(filename)
            if not path.is_file():
                raise FileNotFoundError(f"File {filename} not found")
            
            with path.open("r", newline="") as file:
                reader = csv.reader(file)
                rows = list(reader)
                if not rows:
                    print(f"Warning: {filename} is empty")
                    return []
                return [row[0].strip() for row in rows if row and row[0].strip()]
        except Exception as e:
            print(f"Error reading CSV: {e}")
            return []

    def collect_passwords_from_user(self) -> List[str]:
        """Collect passwords interactively with validation."""
        passwords = []
        print("Enter passwords (empty line to finish):")
        while True:
            password = input("> ").strip()
            if not password:
                break
            if len(password) < self.MIN_PASSWORD_LENGTH:
                print(f"Password must be at least {self.MIN_PASSWORD_LENGTH} characters")
                continue
            passwords.append(password)
        return passwords

    def calculate_entropy(self, password: str) -> float:
        """Calculate Shannon entropy with optimization."""
        if not password:
            return 0.0
        char_count = Counter(password)
        length = len(password)
        return -sum((count / length) * math.log2(count / length) 
                  for count in char_count.values())

    def analyze_password(self, password: str) -> Dict[str, Union[float, str]]:
        """Analyze password strength with detailed metrics."""
        if not password:
            return self._empty_password_result(password)

        # Calculate component scores
        length_score = min(len(password) / 4, 5)
        char_types = [
            r"[A-Z]",  # Uppercase
            r"[a-z]",  # Lowercase
            r"\d",     # Digits
            self.SPECIAL_CHARS  # Special characters
        ]
        char_score = sum(1 for pattern in char_types if re.search(pattern, password)) * 2
        entropy = self.calculate_entropy(password)
        entropy_score = min(entropy / 2, 5)
        
        # Dictionary check with word segmentation
        lower_pass = password.lower()
        dict_penalty = -5 if (lower_pass in self.word_list or 
                            any(word in self.word_list for word in re.split(r'\W+', lower_pass))) else 0
        
        total_score = max(0, length_score + char_score + entropy_score + dict_penalty)

        # Enhanced strength classification
        strength = self._determine_strength(total_score, entropy, len(password))

        return {
            "password": password,
            "length": len(password),
            "length_score": round(length_score, 2),
            "char_score": round(char_score, 2),
            "entropy": round(entropy, 2),
            "entropy_score": round(entropy_score, 2),
            "dictionary_penalty": dict_penalty,
            "total_score": round(total_score, 2),
            "strength": strength
        }

    def _empty_password_result(self, password: str) -> Dict[str, Union[float, str]]:
        """Return result for empty/invalid password."""
        return {
            "password": password,
            "length": 0,
            "length_score": 0.0,
            "char_score": 0.0,
            "entropy": 0.0,
            "entropy_score": 0.0,
            "dictionary_penalty": 0.0,
            "total_score": 0.0,
            "strength": "Invalid 🚫"
        }

    def _determine_strength(self, score: float, entropy: float, length: int) -> str:
        """Determine password strength with more nuanced criteria."""
        if score >= 15 and entropy > 4 and length >= 12:
            return "Very Strong 💪"
        elif score >= 10 and entropy > 3 and length >= 8:
            return "Strong ✅"
        elif score >= 6 and length >= 6:
            return "Moderate ⚠"
        return "Weak ❌"

    def display_results(self, results: List[Dict[str, Union[float, str]]]) -> None:
        """Display analysis results in a formatted table."""
        if not results:
            print("No passwords analyzed.")
            return

        print("\nPassword Strength Analysis Results:")
        print("=" * 60)
        headers = ["Password", "Length", "Entropy", "Score", "Strength"]
        print(f"{headers[0]:<20} {headers[1]:<8} {headers[2]:<8} {headers[3]:<8} {headers[4]}")
        print("-" * 60)
        
        for result in results:
            print(f"{result['password'][:20]:<20} "
                  f"{result['length']:<8} "
                  f"{result['entropy']:<8} "
                  f"{result['total_score']:<8} "
                  f"{result['strength']}")
        print("=" * 60)

def main() -> None:
    """Main execution function."""
    analyzer = PasswordAnalyzer()
    
    while True:
        print("\nPassword Analyzer Menu:")
        print("1. Analyze CSV file")
        print("2. Enter passwords manually")
        print("3. Exit")
        
        choice = input("Select option (1-3): ").strip()
        
        if choice == "1":
            filename = input("Enter CSV file path: ").strip()
            passwords = analyzer.read_passwords_from_csv(filename)
        elif choice == "2":
            passwords = analyzer.collect_passwords_from_user()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")
            continue

        if passwords:
            results = [analyzer.analyze_password(pwd) for pwd in passwords]
            analyzer.display_results(results)
        else:
            print("No valid passwords to analyze.")

if __name__ == "__main__":
    main()