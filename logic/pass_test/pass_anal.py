import math
import re
import csv
from collections import Counter
from typing import List, Dict, Union
import nltk
from nltk.corpus import words

def ensure_nltk_words() -> None:
    try:
        words.words()
    except LookupError:
        nltk.download('words')

def read_passwords_from_csv(filename: str) -> List[str]:
    try:
        with open(filename, "r", newline="") as file:
            reader = csv.reader(file)
            rows = list(reader)
            if not rows:
                print(f"File {filename} is empty.")
                return []
            return [row[0] for row in rows if row]
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return []
    except csv.Error:
        print(f"Error reading CSV file {filename}.")
        return []

def collect_passwords_from_user() -> List[str]:
    passwords = []
    while True:
        password = input("Enter a password (or press Enter to finish): ")
        if not password:
            break
        passwords.append(password)
    return passwords

def get_user_choice() -> str:
    print("1. Read passwords from a CSV file")
    print("2. Enter passwords manually")
    while True:
        choice = input("Choose an option (1 or 2): ")
        if choice in ("1", "2"):
            return choice
        print("Please enter either 1 or 2.")

def calculate_shannon_entropy(password: str) -> float:
    if not password:
        return 0.0
    char_freq = Counter(password)
    length = len(password)
    return -sum((freq / length) * math.log2(freq / length) for freq in char_freq.values())

def analyze_password(password: str, word_list: set) -> Dict[str, Union[float, str]]:
    if not password:
        return {
            "password": password,
            "length_score": 0.0,
            "char_score": 0.0,
            "entropy": 0.0,
            "entropy_score": 0.0,
            "dictionary_penalty": 0.0,
            "total_score": 0.0,
            "strength": "Invalid (Empty) 🚫"
        }
    length_score = min(len(password) / 4, 5)
    char_types = [r"[A-Z]", r"[a-z]", r"\d", r"[!@#$%^&*(),.?\":{}|<>]"]
    char_score = sum(bool(re.search(pattern, password)) for pattern in char_types) * 2
    dictionary_penalty = -5 if password.lower() in word_list else 0
    entropy = calculate_shannon_entropy(password)
    entropy_score = min(entropy / 2, 5)
    total_score = max(0, length_score + char_score + entropy_score + dictionary_penalty)

    strength = (
        "Very Strong 💪" if total_score >= 15 else
        "Strong ✅" if total_score >= 10 else
        "Moderate ⚠" if total_score >= 6 else
        "Weak ❌"
    )

    return {
        "password": password,
        "length_score": length_score,
        "char_score": char_score,
        "entropy": round(entropy, 2),
        "entropy_score": entropy_score,
        "dictionary_penalty": dictionary_penalty,
        "total_score": total_score,
        "strength": strength
    }

def display_analysis_results(results: List[Dict[str, Union[float, str]]]) -> None:
    print("\nPassword Strength Analysis:")
    print("-" * 50)
    for result in results:
        print(f"Password: {result['password']}")
        print(f"Length Score: {result['length_score']:.2f}")
        print(f"Character Score: {result['char_score']:.2f}")
        print(f"Entropy: {result['entropy']:.2f}")
        print(f"Entropy Score: {result['entropy_score']:.2f}")
        print(f"Dictionary Penalty: {result['dictionary_penalty']:.2f}")
        print(f"Total Score: {result['total_score']:.2f}")
        print(f"Strength: {result['strength']}")
        print("-" * 50)

def main() -> None:
    ensure_nltk_words()
    word_list = set(words.words())

    option = get_user_choice()
    if option == "1":
        filename = input("Enter the path to the CSV file: ")
        passwords = read_passwords_from_csv(filename)
    elif option == "2":
        passwords = collect_passwords_from_user()
    else:
        print("Invalid option. Please try again.")
        return

    if not passwords:
        print("No passwords to analyze.")
        return

    results = [analyze_password(password, word_list) for password in passwords]
    display_analysis_results(results)

if __name__ == "__main__":
    main()