"""Lab 3 (Cryptography and Security) - Vigenere cipher for Romanian messages (31 letters), Task 3.2.

The letters are coded 0..30 in the order of the Romanian alphabet:
    A Ă Â B C D E F G H I Î J K L M N O P Q R S Ș T Ț U V W X Y Z
    encryption:  c_i = (m_i + k_i) mod 31
    decryption:  m_i = (c_i - k_i) mod 31

Usage:
    python vigenere.py      # interactive menu: encrypt / decrypt / show alphabet
"""
import sys

ALPHABET = "AĂÂBCDEFGHIÎJKLMNOPQRSȘTȚUVWXYZ"
N = len(ALPHABET)                      # 31
CODE = {ch: i for i, ch in enumerate(ALPHABET)}
MIN_KEY = 7

# the cedilla forms (Ş, Ţ) are still common in Romanian texts, they are treated as Ș and Ț
SAME = str.maketrans("ŞşŢţ", "ȘșȚț")
RANGE_HINT = ("allowed characters: 'A'-'Z', 'a'-'z' and the Romanian letters "
              "Ă Â Î Ș Ț / ă â î ș ț")


class InputError(ValueError):
    pass


def prepare(text, what):
    """Remove the spaces, turn everything to upper case and check that only the 31 letters remain."""
    text = text.translate(SAME)
    text = "".join(text.split()).upper()
    bad = sorted({c for c in text if c not in CODE})
    if bad:
        raise InputError(f"the {what} contains invalid characters: {' '.join(bad)}\n"
                         f"  {RANGE_HINT}")
    if not text:
        raise InputError(f"the {what} is empty")
    return text


def prepare_key(key):
    key = prepare(key, "key")
    if len(key) < MIN_KEY:
        raise InputError(f"the key has {len(key)} letters, it must have at least {MIN_KEY}")
    return key


def vigenere(text, key, sign):
    """sign = +1 encrypts (c = m + k), sign = -1 decrypts (m = c - k), everything mod 31."""
    return "".join(ALPHABET[(CODE[c] + sign * CODE[key[i % len(key)]]) % N]
                   for i, c in enumerate(text))


def encrypt(message, key):
    return vigenere(prepare(message, "message"), prepare_key(key), +1)


def decrypt(cryptogram, key):
    return vigenere(prepare(cryptogram, "cryptogram"), prepare_key(key), -1)


def table(text, key, sign):
    """The step-by-step table from the lab guide (letters, their codes and the result)."""
    key = (key * (len(text) // len(key) + 1))[:len(text)]
    res = vigenere(text, key, sign)
    op = "M+K" if sign > 0 else "C-K"
    rows = [("Text", list(text)), ("Key", list(key)),
            ("Text code", [CODE[c] for c in text]), ("Key code", [CODE[c] for c in key]),
            (f"{op} mod 31", [CODE[c] for c in res]), ("Result", list(res))]
    return "\n".join(f"{name:>12} | " + " ".join(f"{v:>2}" for v in vals) for name, vals in rows)


def ask(prompt, check):
    """Read a value until it is valid; the user is told what range of characters is accepted."""
    while True:
        value = input(prompt)
        try:
            return check(value)
        except InputError as e:
            print(f"  Error: {e}")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stdin.reconfigure(encoding="utf-8")
    print(f"Vigenere cipher, Romanian alphabet ({N} letters), key length >= {MIN_KEY}")
    while True:
        print("\n1 - encrypt   2 - decrypt   3 - show the alphabet   0 - exit")
        choice = input("Choose the operation: ").strip()
        if choice == "0":
            break
        if choice == "3":
            for start in (0, 16):
                print("  ".join(f"{c}={i:<2}" for i, c in enumerate(ALPHABET) if start <= i < start + 16))
            continue
        if choice not in ("1", "2"):
            print("  Error: choose 1, 2, 3 or 0")
            continue
        sign = 1 if choice == "1" else -1
        what = "message" if sign > 0 else "cryptogram"
        key = ask("Key: ", prepare_key)
        text = ask(f"{what.capitalize()}: ", lambda s: prepare(s, what))
        print(f"\nPrepared {what}: {text}")
        print(f"Key: {key} ({len(key)} letters)")
        if len(text) <= 24:
            print(table(text, key, sign))
        result = vigenere(text, key, sign)
        print(("Cryptogram: " if sign > 0 else "Decrypted message: ") + result)


if __name__ == "__main__":
    main()
