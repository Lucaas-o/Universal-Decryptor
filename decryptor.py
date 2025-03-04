import base64
import string
import random
from colorama import init, Fore, Style
import re
from itertools import cycle
import hashlib
import nltk
from nltk.tokenize import word_tokenize
import binascii
import math
import enchant

# Initialize colorama and NLTK
init()
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/words')
except LookupError:
    nltk.download('punkt')
    nltk.download('words')

# Try to initialize pyenchant; fallback if not available
try:
    DICT = enchant.Dict("en_US")
    USE_ENCHANT = True
except enchant.errors.DictNotFoundError:
    USE_ENCHANT = False
    print(f"{Fore.YELLOW}Enchant library not found. Using fallback word list.{Style.RESET_ALL}")

# English letter frequency
ENGLISH_FREQ = {
    'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7, 's': 6.3,
    'h': 6.1, 'r': 5.9, 'd': 4.3, 'l': 4.0, 'c': 3.4, 'u': 3.0, 'm': 2.4,
    'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 1.9, 'p': 1.9, 'b': 1.5, 'v': 1.0,
    'k': 0.8, 'j': 0.2, 'x': 0.2, 'q': 0.1, 'z': 0.1
}

# Expanded common words list (NLTK fallback)
COMMON_WORDS = set(nltk.corpus.words.words()[:10000])
COMMON_WORDS.update({
    'hello', 'world', 'secret', 'code', 'test', 'data', 'secure', 'encrypt', 'decrypt', 'hidden',
    'message', 'now', 'alert', 'python', 'cipher', 'key', 'password', 'example', 'sample', 'text',
    'string', 'number', 'one', 'two', 'three', 'four', 'five', 'sos', 'testing', 'encode', 'decode'
})

# Morse Code dictionary
MORSE_CODE_DICT = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G',
    '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N',
    '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U',
    '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z', '-----': '0',
    '.----': '1', '..---': '2', '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9', '...---...': 'SOS'
}

# Bacon Cipher dictionary
BACON_DICT = {
    'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E', 'AABAB': 'F',
    'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J', 'ABABA': 'K', 'ABABB': 'L',
    'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O', 'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R',
    'BAABA': 'S', 'BAABB': 'T', 'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X',
    'BBAAA': 'Y', 'BBAAB': 'Z', 'BBBAA': '1', 'BBBAB': '2', 'BBABA': '3', 'BBABB': '4',
    'BBBBA': '5', 'BBBBB': '6'
}

# Scoring function
def score_text(text):
    if not text or len(text) < 3 or not any(c.isalpha() for c in text):
        return -100000
    
    text_lower = text.lower()
    alpha_count = sum(c.isalpha() for c in text)
    if alpha_count < 3:
        return -100000
    
    # Frequency score
    freq = {}
    for char in text_lower:
        if char in string.ascii_lowercase:
            freq[char] = freq.get(char, 0) + 1
    score = 0
    for char, expected in ENGLISH_FREQ.items():
        actual = (freq.get(char, 0) / alpha_count) * 100
        score += min(30, expected / (abs(expected - actual) + 1))
    
    # Word validation with NLTK and optional Enchant
    words = word_tokenize(text_lower)
    valid_words = 0
    for w in words:
        if len(w) > 2 and (
            w in COMMON_WORDS or
            (USE_ENCHANT and DICT.check(w))
        ):
            valid_words += 1
    score += valid_words * 1000  # High bonus per valid word
    if valid_words > 0:
        score += 1000  # Bonus for any valid English content
    
    # Penalties
    if not text.isascii() or not all(c.isprintable() for c in text):
        score -= 100000
    digit_ratio = sum(c.isdigit() for c in text) / len(text)
    if digit_ratio > 0.6:
        score -= 5000
    if not words or (len(text) < 5 and valid_words == 0):
        score -= 10000
    
    return score

# Confidence calculation function
def compute_confidence(text):
    words = word_tokenize(text.lower())
    valid_words = sum(1 for w in words if len(w) > 2 and (w in COMMON_WORDS or (USE_ENCHANT and DICT.check(w))))
    total_words = len([w for w in words if len(w) > 2])
    if total_words == 0:
        return 0
    return (valid_words / total_words) * 100

# Caesar Cipher decryption
def caesar_decrypt(ciphertext):
    results = []
    for shift in range(26):
        result = ""
        for char in ciphertext:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base - shift) % 26 + base)
            else:
                result += char
        score = score_text(result)
        if score > -5000:
            results.append((result, score, f"Caesar (shift {shift})"))
    return sorted(results, key=lambda x: x[1], reverse=True)

# ROT13 decryption
def rot13_decrypt(ciphertext):
    result = ciphertext.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
    score = score_text(result)
    return [(result, score, "ROT13")] if score > -5000 else []

# Atbash Cipher decryption
def atbash_decrypt(ciphertext):
    result = ""
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr(25 - (ord(char) - base) + base)
        else:
            result += char
    score = score_text(result)
    return [(result, score, "Atbash")] if score > -5000 else []

# Vigenère Cipher decryption with key guessing
def vigenere_decrypt(ciphertext):
    results = []
    common_keys = ['KEY', 'PASSWORD', 'SECRET', 'TEST', 'CODE', 'ENCRYPT', 'DECRYPT', 'FLAG', 'CRYPTO']
    for key in common_keys:
        result = ""
        key_cycle = cycle(key)
        for char in ciphertext:
            if char.isalpha():
                shift = ord(next(key_cycle).upper()) - ord('A')
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base - shift) % 26 + base)
            else:
                result += char
        score = score_text(result)
        if score > -5000:
            results.append((result, score, f"Vigenère (key '{key}')"))
    return sorted(results, key=lambda x: x[1], reverse=True)

# Rail Fence Cipher decryption
def rail_fence_decrypt(ciphertext):
    results = []
    for rails in range(2, min(6, len(ciphertext) // 2 + 1)):
        n = len(ciphertext)
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for i in range(n):
            fence[rail].append(None)
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction = -direction
        idx = 0
        for r in range(rails):
            for _ in range(len(fence[r])):
                if idx < n:
                    fence[r][_] = ciphertext[idx]
                    idx += 1
        result = ""
        rail = 0
        direction = 1
        for _ in range(n):
            if fence[rail]:
                result += fence[rail].pop(0)
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction = -direction
        score = score_text(result)
        if score > -5000:
            results.append((result, score, f"Rail Fence (rails {rails})"))
    return sorted(results, key=lambda x: x[1], reverse=True)

# XOR decryption with key guessing
def xor_decrypt(ciphertext):
    results = []
    try:
        cipher_bytes = bytes.fromhex(ciphertext) if all(c in '0123456789abcdefABCDEF' for c in ciphertext) else ciphertext.encode()
    except ValueError:
        cipher_bytes = ciphertext.encode()
    
    common_keys = ['key', 'secret', 'password', 'test', 'code', 'encrypt', 'decrypt', 'flag', 'crypto']
    for key in common_keys:
        key_bytes = key.encode()
        result = bytearray(c ^ key_bytes[i % len(key_bytes)] for i, c in enumerate(cipher_bytes))
        try:
            decoded = result.decode('utf-8', errors='ignore')
            score = score_text(decoded)
            if score > -5000:
                results.append((decoded, score, f"XOR (key '{key}')"))
        except UnicodeDecodeError:
            continue
    
    # Attempt single-byte XOR decryption
    for key in range(256):
        result = bytearray(c ^ key for c in cipher_bytes)
        try:
            decoded = result.decode('utf-8', errors='ignore')
            score = score_text(decoded)
            if score > -5000:
                results.append((decoded, score, f"XOR (single-byte key '{chr(key) if chr(key).isprintable() else hex(key)}')"))
        except UnicodeDecodeError:
            continue
    
    return sorted(results, key=lambda x: x[1], reverse=True)

# Base64 decryption
def base64_decrypt(ciphertext):
    if not re.match(r'^[A-Za-z0-9+/=]+$', ciphertext):
        return []
    try:
        decoded = base64.b64decode(ciphertext).decode('utf-8', errors='ignore')
        score = score_text(decoded)
        return [(decoded, score, "Base64")] if score > -5000 else []
    except Exception:
        return []

# Base32 decryption
def base32_decrypt(ciphertext):
    if not re.match(r'^[A-Z2-7=]+$', ciphertext):
        return []
    try:
        decoded = base64.b32decode(ciphertext).decode('utf-8', errors='ignore')
        score = score_text(decoded)
        return [(decoded, score, "Base32")] if score > -5000 else []
    except Exception:
        return []

# Binary decryption
def binary_decrypt(ciphertext):
    if not all(c in '01 ' for c in ciphertext):
        return []
    try:
        binary = ''.join(ciphertext.split())
        if len(binary) % 8 != 0:
            return []
        bytes_data = [binary[i:i+8] for i in range(0, len(binary), 8)]
        result = ''.join(chr(int(b, 2)) for b in bytes_data)
        score = score_text(result)
        return [(result, score, "Binary")] if score > -5000 else []
    except Exception:
        return []

# Hexadecimal decryption
def hex_decrypt(ciphertext):
    if not all(c in '0123456789abcdefABCDEF' for c in ciphertext):
        return []
    try:
        result = bytes.fromhex(ciphertext).decode('utf-8', errors='ignore')
        score = score_text(result)
        return [(result, score, "Hexadecimal")] if score > -5000 else []
    except Exception:
        return []

# Morse Code decryption
def morse_decrypt(ciphertext):
    if not all(c in '.-/ ' for c in ciphertext):
        return []
    try:
        words = ciphertext.split('  ')
        result = ''
        for word in words:
            chars = word.split()
            for char in chars:
                result += MORSE_CODE_DICT.get(char, '')
            result += ' '
        result = result.strip()
        score = score_text(result)
        return [(result, score, "Morse Code")] if score > -5000 else []
    except Exception:
        return []

# Bacon Cipher decryption
def bacon_decrypt(ciphertext):
    if not all(c in 'AB ' for c in ciphertext):
        return []
    try:
        parts = re.findall(r'[AB]{5}', ciphertext.replace(' ', ''))
        result = ''.join(BACON_DICT.get(part, '') for part in parts)
        score = score_text(result)
        return [(result, score, "Bacon Cipher")] if score > -5000 else []
    except Exception:
        return []

# Simple Substitution Cipher (basic frequency-based attempt)
def substitution_decrypt(ciphertext):
    if not any(c.isalpha() for c in ciphertext):
        return []
    
    freq = {}
    alpha_count = 0
    for char in ciphertext.lower():
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
            alpha_count += 1
    if alpha_count < 5:
        return []
    
    sorted_cipher = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    sorted_english = sorted(ENGLISH_FREQ.items(), key=lambda x: x[1], reverse=True)
    
    mapping = {}
    for (c, _), (e, _) in zip(sorted_cipher, sorted_english):
        mapping[c] = e
    
    result = ""
    for char in ciphertext:
        if char.isalpha():
            mapped = mapping.get(char.lower(), char.lower())
            result += mapped.upper() if char.isupper() else mapped
        else:
            result += char
    
    score = score_text(result)
    return [(result, score, "Substitution (freq-based)")] if score > -5000 else []

# ASCII Shift decryption
def ascii_shift_decrypt(ciphertext):
    results = []
    for shift in range(-10, 11):
        if shift == 0:
            continue
        result = ""
        for char in ciphertext:
            if char.isprintable():
                new_ord = (ord(char) - shift) % 128
                if 32 <= new_ord <= 126:
                    result += chr(new_ord)
                else:
                    result += char
            else:
                result += char
        score = score_text(result)
        if score > -5000:
            results.append((result, score, f"ASCII Shift ({shift})"))
    return sorted(results, key=lambda x: x[1], reverse=True)[:2]

# URL Encoding decryption
def url_decode(ciphertext):
    try:
        from urllib.parse import unquote
        result = unquote(ciphertext)
        score = score_text(result)
        return [(result, score, "URL Encoded")] if score > -5000 else []
    except Exception:
        return []

# Hash detection
def hash_detect(ciphertext):
    lengths = {
        32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512", 8: "CRC32"
    }
    if all(c in '0123456789abcdefABCDEF' for c in ciphertext) and len(ciphertext) in lengths:
        return [(ciphertext, -1000, f"Detected {lengths[len(ciphertext)]} Hash (irreversible)")]
    return []

# Automated decryption
def automated_decrypt(ciphertext):
    all_results = []
    
    # Check input patterns for prioritization
    is_binary = all(c in '01 ' for c in ciphertext)
    is_morse = all(c in '.- ' for c in ciphertext)
    
    # Define decryptors
    decryptors = [
        caesar_decrypt, rot13_decrypt, atbash_decrypt, vigenere_decrypt,
        rail_fence_decrypt, xor_decrypt, base64_decrypt, base32_decrypt,
        binary_decrypt, hex_decrypt, morse_decrypt, bacon_decrypt,
        substitution_decrypt, ascii_shift_decrypt, url_decode, hash_detect
    ]
    
    # Collect results from all decryptors
    for decryptor in decryptors:
        try:
            results = decryptor(ciphertext)
            # Apply bonus for binary if input is binary-like
            if decryptor == binary_decrypt and is_binary and results:
                results = [(r[0], r[1] + 10000, r[2]) for r in results]
            # Apply bonus for Morse if input is Morse-like
            elif decryptor == morse_decrypt and is_morse and results:
                results = [(r[0], r[1] + 10000, r[2]) for r in results]
            all_results.extend(results)
        except Exception as e:
            print(f"{Fore.RED}Error in {decryptor.__name__}: {e}{Style.RESET_ALL}")
    
    # Include plaintext
    plaintext_score = score_text(ciphertext)
    all_results.append((ciphertext, plaintext_score, "Plaintext"))
    
    # Remove duplicates and sort by score
    unique_results = {r[0]: r for r in all_results if r[1] > -10000}
    ranked_results = sorted(unique_results.values(), key=lambda x: x[1], reverse=True)
    
    # Filter results based on confidence and conditions
    filtered_results = []
    xor_results = []
    
    for result in ranked_results:
        text, score, method = result
        confidence = compute_confidence(text)
        
        if "XOR" in method:
            # For XOR, only include if confidence > 50% or if it's the top XOR result
            if confidence > 50 or (not xor_results and score > 500):
                xor_results.append((text, score, method, confidence))
        else:
            # Include non-XOR results if score > 500
            if score > 500:
                filtered_results.append((text, score, method, confidence))
    
    # Sort XOR results and take the top one if any
    if xor_results:
        top_xor = max(xor_results, key=lambda x: x[1])  # Top by score
        if top_xor[3] > 50:  # Only include if confidence > 50%
            filtered_results.append(top_xor)
    
    # If input is not binary, further restrict XOR unless highly confident
    if not is_binary and xor_results:
        filtered_results = [r for r in filtered_results if "XOR" not in r[2] or r[3] > 75]
    
    # Sort by score and limit to top results
    final_results = sorted(filtered_results, key=lambda x: x[1], reverse=True)
    return final_results[:5] if final_results else ranked_results[:5]

# Manual decryption (unchanged unless further customization requested)
def manual_decrypt(ciphertext, method, key=None):
    methods = {
        '1': lambda x, k: ''.join(chr((ord(c) - (ord('A') if c.isupper() else ord('a')) - int(k)) % 26 + (ord('A') if c.isupper() else ord('a'))) if c.isalpha() else c for c in x) if k else "Key required",
        '2': lambda x, k: ''.join(chr(c ^ ord(k[i % len(k)])) for i, c in enumerate(bytes.fromhex(x) if all(c in '0123456789abcdefABCDEF' for c in x) else x.encode())) if k else "Key required",
        '3': lambda x, k: base64.b64decode(x).decode('utf-8', errors='ignore'),
        '4': lambda x, k: base64.b32decode(x).decode('utf-8', errors='ignore'),
        '5': lambda x, k: bytes.fromhex(x).decode('utf-8', errors='ignore'),
        '6': lambda x, k: ''.join(MORSE_CODE_DICT.get(c, '') for c in x.split()) if ' ' not in x else morse_decrypt(x)[0][0] if morse_decrypt(x) else "Invalid Morse",
    }
    try:
        result = methods.get(method, lambda x, k: "Invalid method")(ciphertext, key)
        return result if isinstance(result, str) else result.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error: {str(e)}"

# Print results with confidence percentage
def print_results(results, show_all=False):
    if not results or (all(isinstance(r, tuple) and len(r) == 3 for r in results) and max(r[1] for r in results) <= -1000):
        print(f"{Fore.RED}No plausible decryption found.{Style.RESET_ALL}")
        if not show_all:
            choice = input(f"{Fore.YELLOW}Show all results anyway? (y/n): {Style.RESET_ALL}").strip().lower()
            if choice == 'y':
                print_results(results, show_all=True)
        return
    
    print(f"{Fore.GREEN}Top decryption results:{Style.RESET_ALL}")
    # Handle both tuple formats: (text, score, method) and (text, score, method, confidence)
    display = []
    for r in results:
        if len(r) == 3:
            text, score, method = r
            confidence = compute_confidence(text)
            display.append((text, score, method, confidence))
        else:
            display.append(r)
    
    display = sorted(display, key=lambda x: x[1], reverse=True)
    display = display if show_all else [r for r in display if r[1] > 500][:5]
    
    for i, (text, score, method, confidence) in enumerate(display, 1):
        print(f"{i}. {Fore.CYAN}{text}{Style.RESET_ALL} (Score: {score:.2f}, Confidence: {confidence:.2f}%, Method: {method})")
    
    if not show_all and len([r for r in results if (len(r) == 3 and r[1] <= 500) or (len(r) == 4 and r[1] <= 500)]) > 0:
        choice = input(f"{Fore.YELLOW}Show more results? (y/n): {Style.RESET_ALL}").strip().lower()
        if choice == 'y':
            print_results(results, show_all=True)

# Main menu
def main():
    print(f"{Fore.YELLOW}=== Universal Decryption Tool ==={Style.RESET_ALL}")
    while True:
        print(f"\n{Fore.MAGENTA}Menu:{Style.RESET_ALL}")
        print("1. Automated Decryption (try everything)")
        print("2. Manual Decryption (specify method)")
        print("3. Exit")
        
        choice = input(f"{Fore.YELLOW}Enter choice (1/2/3): {Style.RESET_ALL}").strip()
        
        if choice == '1':
            ciphertext = input(f"{Fore.YELLOW}Enter text to decrypt: {Style.RESET_ALL}").strip()
            if not ciphertext:
                print(f"{Fore.RED}Input cannot be empty.{Style.RESET_ALL}")
                continue
            print(f"{Fore.GREEN}Analyzing...{Style.RESET_ALL}")
            results = automated_decrypt(ciphertext)
            print_results(results)
        
        elif choice == '2':
            ciphertext = input(f"{Fore.YELLOW}Enter text to decrypt: {Style.RESET_ALL}").strip()
            if not ciphertext:
                print(f"{Fore.RED}Input cannot be empty.{Style.RESET_ALL}")
                continue
            print(f"{Fore.MAGENTA}Methods:{Style.RESET_ALL}")
            print("1. Caesar Cipher (requires shift)")
            print("2. XOR (requires key)")
            print("3. Base64 (no key needed)")
            print("4. Base32 (no key needed)")
            print("5. Hexadecimal (no key needed)")
            print("6. Morse Code (no key needed)")
            method = input(f"{Fore.YELLOW}Enter method (1-6): {Style.RESET_ALL}").strip()
            key = None
            if method in {'1', '2'}:
                key = input(f"{Fore.YELLOW}Enter key/shift: {Style.RESET_ALL}").strip()
            result = manual_decrypt(ciphertext, method, key)
            print(f"{Fore.GREEN}Result:{Style.RESET_ALL} {result}")
        
        elif choice == '3':
            print(f"{Fore.YELLOW}Exiting...{Style.RESET_ALL}")
            break
        
        else:
            print(f"{Fore.RED}Invalid choice. Please enter 1, 2, or 3.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()