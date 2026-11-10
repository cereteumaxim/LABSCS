"""Lab 2 (Cryptography and Security) - frequency analysis of a monoalphabetic cipher, Variant 4.

Usage:
    python frequency_analysis.py            # letter frequencies + decryption with the recovered key
"""
import collections
import re
from pathlib import Path

HERE = Path(__file__).parent
ENGLISH = dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                   [8.17, 1.49, 2.78, 4.25, 12.7, 2.23, 2.01, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41,
                    6.75, 7.51, 1.93, 0.09, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07]))

# key recovered by the frequency attack: ciphertext letter -> plaintext letter
KEY = {
    'V': 'e', 'W': 't',                        # step 1: most frequent letters
    'Q': 'h', 'T': 'a', 'N': 'o',              # step 2: "the", "a", "to"
    'G': 'n', 'O': 'd', 'X': 'i', 'J': 'g',    # step 3: "and", "in", "-ing"
    'S': 'l', 'C': 'f', 'R': 'w', 'P': 's',    # step 4: "all", "of", "was", "is"
    'H': 'c', 'I': 'r', 'F': 'y', 'U': 'p',    # step 5: "cryptology"
    'A': 'b', 'D': 'u', 'Z': 'm', 'K': 'v',    # step 6: remaining letters from context
    'L': 'k', 'Y': 'x', 'E': 'j', 'B': 'q', 'M': 'z',
}


def frequencies(text):
    letters = [c for c in text.upper() if 'A' <= c <= 'Z']
    return collections.Counter(letters), len(letters)


def top(items, n):
    return ', '.join(f'{k} ({v})' for k, v in items.most_common(n))


def partial(text, mapping):
    """Upper-case text with the already known letters written in lower case (as in the lab guide)."""
    return ''.join(mapping.get(c, c) for c in text.upper())


def decrypt(text, key):
    out = []
    for c in text:
        p = key.get(c.upper())
        out.append(c if p is None else (p.upper() if c.isupper() else p))
    return ''.join(out)


def main():
    cipher = (HERE / 'cryptogram_v4.txt').read_text(encoding='utf8').strip()
    cnt, total = frequencies(cipher)
    print(f'Letters in the cryptogram: {total}\n')
    print('Cipher  Count      %  |  English letter of the same rank   %')
    english_sorted = sorted(ENGLISH.items(), key=lambda kv: -kv[1])
    for (letter, n), (eng, pct) in zip(cnt.most_common(), english_sorted):
        print(f'  {letter}    {n:5d}  {100 * n / total:6.2f}  |  {eng:>16} {pct:20.2f}')

    up = cipher.upper()
    words = collections.Counter(re.findall(r'[A-Z]+', up))
    for size in (1, 2, 3):
        print(f'\n{size}-letter words:', top(collections.Counter({w: c for w, c in words.items() if len(w) == size}), 6))
    grams = lambda k: collections.Counter(up[i:i + k] for i in range(len(up) - k + 1) if up[i:i + k].isalpha())
    print('Digrams :', top(grams(2), 6))
    print('Trigrams:', top(grams(3), 6))
    print('Doubles :', top(collections.Counter(g for g in grams(2).elements() if g[0] == g[1]), 6))

    plain = decrypt(cipher, KEY)
    inverse = {p: c for c, p in KEY.items()}
    assert decrypt(plain, {p.upper(): c for p, c in inverse.items()}).upper() == up, 'key check failed'
    print('\nKey (plaintext -> ciphertext):')
    print(' '.join('abcdefghijklmnopqrstuvwxyz'))
    print(' '.join(inverse[c] for c in 'abcdefghijklmnopqrstuvwxyz'))
    (HERE / 'decrypted_v4.txt').write_text(plain + '\n', encoding='utf8')
    print('\nDecrypted text written to decrypted_v4.txt:\n')
    print(plain)


if __name__ == '__main__':
    main()
