import re
from ..utils.scoring import score_text

def is_hex(s):
    return bool(re.fullmatch(r'[0-9A-Fa-f]+', s)) and len(s) % 2 == 0

def xor_decrypt(ciphertext, key=None):
    # Empty input is the cheapest, most common mistake — flag it clearly.
    if ciphertext is None or ciphertext == "":
        return [("Invalid input: ciphertext is empty.", -100000, "XOR (error)")]

    # Decode the ciphertext bytes. Surface a specific error when a key
    # was provided (i.e. the user is in manual mode) so they know exactly
    # why the call failed; in brute-force mode (no key), fall back silently.
    try:
        if is_hex(ciphertext):
            cipher_bytes = bytes.fromhex(ciphertext)
        else:
            cipher_bytes = ciphertext.encode()
    except ValueError as e:
        if key is not None:
            return [(f"Invalid hex input: {e}", -100000, "XOR (error)")]
        cipher_bytes = ciphertext.encode()

    if key is not None:
        # Validate the user-supplied key before doing any work.
        if not isinstance(key, str) or key == "":
            return [("Invalid key: XOR key must be a non-empty string.",
                     -100000, "XOR (error)")]
        try:
            key_bytes = key.encode()
        except (UnicodeEncodeError, AttributeError) as e:
            return [(f"Invalid key encoding: {e}", -100000, "XOR (error)")]

        result = bytearray(c ^ key_bytes[i % len(key_bytes)]
                           for i, c in enumerate(cipher_bytes))
        # `errors='ignore'` never raises, but keep the try for defense-in-depth.
        try:
            decoded = result.decode('utf-8', errors='ignore')
        except Exception as e:
            return [(f"XOR decode failed: {e}", -100000, "XOR (error)")]
        return [(decoded, score_text(decoded), f"XOR (key '{key}')")]

    results = []
    common_keys = ['key', 'secret', 'password', 'test', 'code', 'encrypt', 'decrypt', 'flag', 'crypto']
    
    # Try common keys
    for k in common_keys:
        k_bytes = k.encode()
        result = bytearray(c ^ k_bytes[i % len(k_bytes)] for i, c in enumerate(cipher_bytes))
        try:
            decoded = result.decode('utf-8', errors='ignore')
            score = score_text(decoded)
            if score > -5000:
                results.append((decoded, score, f"XOR (key '{k}')"))
        except Exception:
            continue
            
    # Single byte XOR brute force
    for b in range(256):
        result = bytearray(c ^ b for c in cipher_bytes)
        try:
            decoded = result.decode('utf-8', errors='ignore')
            score = score_text(decoded)
            if score > 0:
                results.append((decoded, score, f"Single-byte XOR (0x{b:02x})"))
        except Exception:
            continue
            
    return sorted(results, key=lambda x: x[1], reverse=True)[:5]

def hash_detect(ciphertext):
    lengths = {
        32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512", 8: "CRC32"
    }
    if all(c in '0123456789abcdefABCDEF' for c in ciphertext) and len(ciphertext) in lengths:
        return [(ciphertext, -1000, f"Detected {lengths[len(ciphertext)]} Hash (irreversible)")]
    return []