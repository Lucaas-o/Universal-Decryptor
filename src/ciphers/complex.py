from itertools import cycle
from ..utils.scoring import score_text, ENGLISH_FREQ
import re

def vigenere_decrypt(ciphertext, key=None):
    if key is not None:
        result = ""
        key_cycle = cycle(key.upper())
        for char in ciphertext:
            if char.isalpha():
                shift = ord(next(key_cycle)) - ord('A')
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base - shift) % 26 + base)
            else:
                result += char
        return [(result, score_text(result), f"Vigenère (key '{key}')")]

    results = []
    common_keys = ['KEY', 'PASSWORD', 'SECRET', 'TEST', 'CODE', 'ENCRYPT', 'DECRYPT', 'FLAG', 'CRYPTO']
    for k in common_keys:
        result = ""
        key_cycle = cycle(k)
        for char in ciphertext:
            if char.isalpha():
                shift = ord(next(key_cycle).upper()) - ord('A')
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base - shift) % 26 + base)
            else:
                result += char
        score = score_text(result)
        if score > -5000:
            results.append((result, score, f"Vigenère (key '{k}')"))
    
    # Simple key length guessing using IC
    def get_ic(text):
        text = re.sub(r'[^A-Z]', '', text.upper())
        if len(text) < 2: return 0
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        ic = sum(n * (n - 1) for n in counts.values()) / (len(text) * (len(text) - 1))
        return ic

    # If top score is low, try periodic analysis
    clean_text = re.sub(r'[^A-Z]', '', ciphertext.upper())
    if len(clean_text) > 20:
        for length in range(2, 9):
            slices = ['' for _ in range(length)]
            for i, char in enumerate(clean_text):
                slices[i % length] += char
            
            avg_ic = sum(get_ic(s) for s in slices) / length
            if avg_ic > 0.055: # Typical English IC is ~0.066, but allow some margin
                # Frequency analysis to find the best shift for each slice
                probable_key = ""
                for s in slices:
                    slice_scores = []
                    for shift in range(26):
                        shifted = ""
                        for char in s:
                            shifted += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                        
                        # Score slice based on letter frequency
                        s_score = 0
                        for char in shifted:
                            s_score += ENGLISH_FREQ.get(char.lower(), 0)
                        slice_scores.append((shift, s_score))
                    
                    best_shift = max(slice_scores, key=lambda x: x[1])[0]
                    probable_key += chr(best_shift + ord('A'))
                
                # Try this key
                if probable_key:
                    results.extend(vigenere_decrypt(ciphertext, key=probable_key))

    return sorted(results, key=lambda x: x[1], reverse=True)

def playfair_decrypt(ciphertext, key):
    # Basic Playfair implementation
    def generate_matrix(key):
        matrix = []
        seen = set(['J'])
        key = key.upper().replace('J', 'I')
        for char in key:
            if char not in seen and char.isalpha():
                seen.add(char)
                matrix.append(char)
        for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
            if char not in seen:
                seen.add(char)
                matrix.append(char)
        return [matrix[i:i+5] for i in range(0, 25, 5)]

    def find_pos(matrix, char):
        for r, row in enumerate(matrix):
            for c, val in enumerate(row):
                if val == char:
                    return r, c
        return None

    matrix = generate_matrix(key)
    ciphertext = re.sub(r'[^A-Z]', '', ciphertext.upper().replace('J', 'I'))
    result = ""
    for i in range(0, len(ciphertext), 2):
        if i + 1 >= len(ciphertext): break
        a, b = ciphertext[i], ciphertext[i+1]
        r1, c1 = find_pos(matrix, a)
        r2, c2 = find_pos(matrix, b)
        
        if r1 == r2:
            result += matrix[r1][(c1-1)%5] + matrix[r2][(c2-1)%5]
        elif c1 == c2:
            result += matrix[(r1-1)%5][c1] + matrix[(r2-1)%5][c2]
        else:
            result += matrix[r1][c2] + matrix[r2][c1]
    
    return [(result, score_text(result), f"Playfair (key '{key}')")]

import re # Need re for Playfair substitute

def hill_decrypt_2x2(ciphertext, a, b, c, d):
    # Hill Cipher 2x2: [[a, b], [c, d]]
    det = (a*d - b*c) % 26
    
    def egcd(a, b):
        if a == 0: return (b, 0, 1)
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

    def modInverse(a, m):
        g, x, y = egcd(a, m)
        if g != 1: return None
        return x % m

    inv_det = modInverse(det, 26)
    if inv_det is None: return "Invalid matrix (determinant not invertible mod 26)"
    
    # Inverted matrix [[d, -b], [-c, a]] * inv_det
    ia = (d * inv_det) % 26
    ib = (-b * inv_det) % 26
    ic = (-c * inv_det) % 26
    id_ = (a * inv_det) % 26
    
    clean_text = re.sub(r'[^A-Z]', '', ciphertext.upper())
    result = ""
    for i in range(0, len(clean_text), 2):
        if i + 1 >= len(clean_text): break
        x = ord(clean_text[i]) - ord('A')
        y = ord(clean_text[i+1]) - ord('A')
        
        nx = (ia * x + ib * y) % 26
        ny = (ic * x + id_ * y) % 26
        
        result += chr(nx + ord('A')) + chr(ny + ord('A'))
        
    return [(result, score_text(result), f"Hill 2x2 (matrix {a},{b},{c},{d})")]
