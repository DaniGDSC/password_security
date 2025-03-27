import math
import re
import csv
from collections import Counter
from typing import List, Dict, Union
from nltk.corpus import words


def ensure_nltk_words() -> None:
    """
    Ensure the NLTK words corpus is downloaded.
    """
    try:
        words.words()
    except LookupError:
        import nltk
        nltk.download('words')


def get_passwords_from_csv(filename: str = "passwords.csv") -> List[str]:
    """
    Read passwords from a CSV file.

    Args:
        filename (str): Path to the CSV file containing passwords.

    Returns:
        List[str]: List of passwords.
    """
    try:
        with open(filename, "r", newline="") as f:
            return [row[0] for row in csv.reader(f)]
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return []


def get_passwords_from_input() -> List[str]:
    """
    Collect passwords from user input.

    Returns:
        List[str]: List of passwords entered by the user.
    """
    passwords = []
    while True:
        password = input("Enter a password (or press Enter to finish): ")
        if not password:
            break
        passwords.append(password)
    return passwords


def get_user_option() -> str:
    """
    Display options to the user and get their choice.

    Returns:
        str: The user's chosen option.
    """
    print("1. Read passwords from a CSV file")
    print("2. Enter passwords manually")
    return input("Choose an option: ")


def calculate_shannon_entropy(password: str) -> float:
    """
    Calculate the Shannon entropy of a password.

    Args:
        password (str): The password to analyze.

    Returns:
        float: The Shannon entropy of the password.
    """
    if not password:
        return 0.0
    char_freq = Counter(password)
    length = len(password)
    return -sum((freq / length) * math.log2(freq / length) for freq in char_freq.values())


def analyze_password_strength(password: str, word_list: set) -> Dict[str, Union[float, str]]:
    """
    Analyze the strength of a password.

    Args:
        password (str): The password to analyze.
        word_list (set): A set of dictionary words.

    Returns:
        Dict[str, Union[float, str]]: Analysis results for the password.
    """
    length_score = min(len(password) / 4, 5)  # Max score 5
    char_types = [r"[A-Z]", r"[a-z]", r"\d", r"[!@#$%^&*(),.?\":{}|<>]"]
    char_score = sum(bool(re.search(pattern, password)) for pattern in char_types) * 2  # Max 8 points
    dictionary_penalty = -5 if any(word.lower() in word_list for word in password.split()) else 0
    entropy = calculate_shannon_entropy(password)
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


def display_results(results: List[Dict[str, Union[float, str]]]) -> None:
    """
    Display the password analysis results.

    Args:
        results (List[Dict[str, float | str]]): List of password analysis results.
    """
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
    """
    Main function to execute the password strength analysis.
    """
    ensure_nltk_words()
    word_list = set(words.words())

    option = get_user_option()
    if option == "1":
        passwords = get_passwords_from_csv()
    elif option == "2":
        passwords = get_passwords_from_input()
    else:
        print("Invalid option. Please try again.")
        return

    results = [analyze_password_strength(password, word_list) for password in passwords]
    display_results(results)


if __name__ == "__main__":
    main()
