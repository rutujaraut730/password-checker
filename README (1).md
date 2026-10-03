# Password Checker

A small Python command-line tool that checks how safe a password is, in two ways:

1. **Strength check:** length, mix of character types, and a list of very common passwords.
2. **Breach check:** has this password shown up in a known data breach? The check is done **without sending your password anywhere**.

> Built while learning cybersecurity basics (account security, hashing, passwords).

## Demo

<!-- TODO: add a screenshot of the tool running in your terminal, e.g. ![demo](demo.png) -->

## How to run

You need Python 3 installed.

```bash
git clone https://github.com/rutujaraut730/password-checker.git
cd password-checker
pip install -r requirements.txt
python password_checker.py
```

Type a password when asked. Typing is hidden, like a real login prompt.

## How it works

**Strength check.** The tool looks at length (12+ characters), whether the password has lowercase, uppercase, numbers and symbols, and whether it appears in `common_passwords.txt`.

**Breach check (the interesting part).** Sending your real password to a website to ask "is this leaked?" would defeat the purpose. So the tool does this instead:

1. Turns the password into a SHA-1 hash, a scrambled fingerprint.
2. Sends only the **first 5 characters** of that fingerprint to the [Have I Been Pwned Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords).
3. Gets back a list of the remaining parts of every leaked fingerprint that starts with those 5 characters.
4. Searches that list on your own computer for a match.

It is like asking a librarian for every book whose catalog number starts with `5BAA6`, then picking out yours from the pile. She never learns which book you wanted. This idea is called *k-anonymity*.

## Privacy

- The password is never saved, logged, or sent over the network.
- Only a 5-character piece of the hash leaves your computer.

## Limitations

- Strength rules are simple. A password can pass every check and still be guessable (for example `Summer2024!`).
- The common-passwords list is small (about 100 entries). A bigger list such as the top 10,000 from [SecLists](https://github.com/danielmiessler/SecLists) would be better.
- SHA-1 is used only because the breach API requires it. It is not a safe way to *store* passwords.
- Needs an internet connection for the breach check.

## What I learned

<!-- TODO: write 3-4 lines in your own words. What is hashing? Why only 5 characters? What surprised you? -->

## Ideas for next steps

- Load a bigger common-passwords list
- Add a simple strength score instead of a checklist
- Check several passwords from a file
- Turn it into a small web app with Flask
