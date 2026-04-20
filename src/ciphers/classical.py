from ..utils.scoring import score_text

def caesar_decrypt(ciphertext, shift=None):
    if shift is not None:
        result = ""
        for char in ciphertext:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base - int(shift)) % 26 + base)
            else:
                result += char
        return [(result, score_text(result), f"Caesar (shift {shift})")]

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

def rot13_decrypt(ciphertext):
    result = ciphertext.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
    score = score_text(result)
    return [(result, score, "ROT13")] if score > -5000 else []

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

def rail_fence_decrypt(ciphertext, rails=None):
    if rails is not None:
        rails = int(rails)
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
        return [(result, score_text(result), f"Rail Fence (rails {rails})")]

    results = []
    for rails in range(2, min(6, len(ciphertext) // 2 + 1)):
        # logic same as above but in loop
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

def egcd(a, b):
    if a == 0: return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modInverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1: return None
    return x % m

def affine_decrypt(ciphertext, a=None, b=None):
    if a is not None and b is not None:
        a, b = int(a), int(b)
        a_inv = modInverse(a, 26)
        if a_inv is None: return [] # Invalid 'a'
        result = ""
        for char in ciphertext:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result += chr(((a_inv * (ord(char) - base - b)) % 26) + base)
            else:
                result += char
        return [(result, score_text(result), f"Affine (a={a}, b={b})")]

    results = []
    for a in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
        a_inv = modInverse(a, 26)
        for b in range(26):
            result = ""
            for char in ciphertext:
                if char.isalpha():
                    base = ord('A') if char.isupper() else ord('a')
                    result += chr(((a_inv * (ord(char) - base - b)) % 26) + base)
                else:
                    result += char
            score = score_text(result)
            if score > 0: # Be stricter with affine since it has many permutations
                results.append((result, score, f"Affine (a={a}, b={b})"))
    return sorted(results, key=lambda x: x[1], reverse=True)[:5]
