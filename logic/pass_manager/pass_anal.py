import math
import re
import csv
from collections import Counter
from nltk.corpus import words

# Ensure NLTK words corpus is downloaded
def ensure_nltk_words():
    try:
        words.words()
    except LookupError:
        import nltk
        nltk.download('words')

# Read passwords from a CSV file
def get_passwords(filename="passwords.csv"):
    try:
        with open(filename, "r", newline="") as f:
            return [row[0] for row in csv.reader(f)]
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return []

# Calculate Shannon entropy of a password
def shannon_entropy(password):
    if not password:
        return 0
    char_freq = Counter(password)
    length = len(password)
    return -sum((freq / length) * math.log2(freq / length) for freq in char_freq.values())

# Analyze password strength
def password_strength(password, word_list):
    length_score = min(len(password) / 4, 5)  # Max score 5
    char_types = [r"[A-Z]", r"[a-z]", r"\d", r"[!@#$%^&*(),.?\":{}|<>]"]
    char_score = sum(bool(re.search(pattern, password)) for pattern in char_types) * 2  # Max 8 points
    dictionary_penalty = -5 if any(word.lower() in word_list for word in password.split()) else 0
    entropy = shannon_entropy(password)
    entropy_score = min(entropy / 2, 5)  # Max 5 points
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

# Print password analysis results
def print_results(results):
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

# Main function
def main():
    ensure_nltk_words()
    word_list = set(words.words())
    passwords = get_passwords()

    if not passwords:
        print("No passwords found in passwords.csv.")
        return

    results = [password_strength(password, word_list) for password in passwords]
    print_results(results)

if __name__ == "__main__":
    main()
