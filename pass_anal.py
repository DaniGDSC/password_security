import math
import re
from nltk.corpus import words
import csv
from collections import Counter

# Download NLTK words (first-time use)
try:
    words.words()
except LookupError:
    import nltk
    nltk.download('words')

#get passwords from password.csv
def get_passwords(filename="passwords.csv"):
    try:
        with open(filename, "r", newline="") as f:
            reader = csv.reader(f)
            passwords = [row[0] for row in reader]
        return passwords
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return []

def shannon_entropy(password):
    if not password:
        return 0
    # Calculate frequency of each character
    char_freq = Counter(password)
    length = len(password)
    # Shannon entropy formula
    entropy = -sum((freq / length) * math.log2(freq / length) for freq in char_freq.values())
    return entropy


def password_strength(password):
    """Analyzes password strength and provides a score"""

    # Check password length
    length_score = min(len(password) / 4, 5)  # Max score 5 for length
    
    # Character type check
    char_types = [r"[A-Z]", r"[a-z]", r"\d", r"[!@#$%^&*(),.?\":{}|<>]"]
    char_score = sum(bool(re.search(pattern, password)) for pattern in char_types) * 2  # Max 8 points
    
    # Check for dictionary words
    word_list = words.words()
    words_in_password = any(word.lower() in word_list for word in password.split())
    dictionary_penalty = -5 if words_in_password else 0  # Penalize for dictionary words

    # Entropy calculation
    entropy = shannon_entropy(password)
    entropy_score = min(entropy / 2, 5)  # Max 5 points

    # Overall score (max 18, min 0)
    total_score = max(0, length_score + char_score + entropy_score + dictionary_penalty)

    # Strength Rating
    if total_score >= 15:
        strength = "Very Strong 💪"
    elif total_score >= 10:
        strength = "Strong ✅"
    elif total_score >= 6:
        strength = "Moderate ⚠"
    else:
        strength = "Weak ❌"

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

def main():
    if not words.words():
        print("Word list not found. Please download the NLTK words corpus.")
        return
    
    # Read passwords from file
    passwords = get_passwords()
    if not passwords:
        print("No passwords found in passwords.csv.")
        return
    
    # Analyze password strength
    results = [password_strength(password) for password in passwords]

    # Print results
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


    if __name__ == "__main__":
        main()
