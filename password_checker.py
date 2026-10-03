"""
Password Checker
----------------
Checks a password in two ways:
  1. Strength: length, character mix, and a list of very common passwords.
  2. Breaches: has this password appeared in a known data breach?
     (Uses the Have I Been Pwned "Pwned Passwords" range API, which never
     receives your full password or even your full hash.)

Run it in a normal terminal:  python password_checker.py
"""

import getpass
import hashlib
from pathlib import Path

import requests

API_URL = "https://api.pwnedpasswords.com/range/"
COMMON_PASSWORDS_FILE = Path(__file__).parent / "common_passwords.txt"
MIN_LENGTH = 12


def load_common_passwords():
    """Read the common-passwords file into a set (a set makes lookups fast)."""
    if not COMMON_PASSWORDS_FILE.exists():
        return set()
    with open(COMMON_PASSWORDS_FILE, encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip()}


def check_strength(password, common_passwords):
    """Return a list of problems found. An empty list means no problems."""
    problems = []

    if len(password) < MIN_LENGTH:
        problems.append(f"Shorter than {MIN_LENGTH} characters")
    if not any(c.islower() for c in password):
        problems.append("No lowercase letters")
    if not any(c.isupper() for c in password):
        problems.append("No uppercase letters")
    if not any(c.isdigit() for c in password):
        problems.append("No numbers")
    if not any(not c.isalnum() for c in password):
        problems.append("No symbols (like ! @ # $)")
    if password.lower() in common_passwords:
        problems.append("This is one of the most common passwords in the world")

    return problems


def times_found_in_breaches(password):
    """
    Return how many times this password appears in known breaches.

    How it stays private (the "librarian" trick):
      - We turn the password into a SHA-1 hash (a scrambled fingerprint).
      - We send ONLY the first 5 characters of that fingerprint.
      - The service sends back the rest of every fingerprint that starts with
        those 5 characters (hundreds of them).
      - We look for our own fingerprint in that list, on our own computer.

    Note: SHA-1 is used here only because the service requires it.
    It is NOT a good way to store passwords.
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    response = requests.get(API_URL + prefix, timeout=10)
    response.raise_for_status()  # raises an error if the request failed

    # Each line looks like:  <rest of hash>:<number of times seen>
    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)
    return 0


def main():
    common_passwords = load_common_passwords()

    # getpass hides what you type, like a real login prompt.
    password = getpass.getpass("Enter a password to check (typing is hidden): ")
    if not password:
        print("No password entered.")
        return

    print("\n--- Strength check ---")
    problems = check_strength(password, common_passwords)
    if problems:
        for problem in problems:
            print(f"  [x] {problem}")
    else:
        print("  [ok] Passes all strength checks")

    print("\n--- Breach check ---")
    try:
        count = times_found_in_breaches(password)
    except requests.RequestException:
        count = None
        print("  Could not reach the breach service (check your internet).")
    else:
        if count:
            print(f"  [x] Found {count:,} times in known data breaches")
        else:
            print("  [ok] Not found in known data breaches")

    print("\n--- Verdict ---")
    if count or "This is one of the most common passwords in the world" in problems:
        print("  DON'T USE THIS. Attackers already have it.")
    elif problems:
        print("  WEAK. Fix the problems listed above.")
    elif count is None:
        print("  Strong by our checks, but the breach check didn't run.")
    else:
        print("  GOOD. Strong, and not found in known breaches.")


if __name__ == "__main__":
    main()
