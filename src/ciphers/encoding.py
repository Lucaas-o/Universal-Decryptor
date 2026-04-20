import base64
import re
import binascii
from urllib.parse import unquote
from ..utils.scoring import score_text

def is_hex(s):
    return bool(re.fullmatch(r'[0-9A-Fa-f]+', s)) and len(s) % 2 == 0

def is_base64(s):
    try:
        if not s.strip(): return False
        return base64.b64encode(base64.b64decode(s)).decode() == s.strip()
    except Exception:
        return False

def base64_decrypt(ciphertext):
    if not is_base64(ciphertext):
        return []
    try:
        decoded = base64.b64decode(ciphertext).decode('utf-8', errors='ignore')
        score = score_text(decoded)
        return [(decoded, score, "Base64")] if score > -5000 else []
    except Exception:
        return []

def base32_decrypt(ciphertext):
    ciphertext = ciphertext.strip().upper()
    if not re.match(r'^[A-Z2-7=]+$', ciphertext):
        return []
    
    missing_padding = len(ciphertext) % 8
    if missing_padding:
        ciphertext += "=" * (8 - missing_padding)

    try:
        decoded_bytes = base64.b32decode(ciphertext, casefold=True)
        decoded = decoded_bytes.decode('utf-8', errors='ignore')
        score = score_text(decoded)
        return [(decoded, score, "Base32")] if score > -5000 else []
    except (binascii.Error, ValueError):
        return []

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

def hex_decrypt(ciphertext):
    if not all(c in '0123456789abcdefABCDEF' for c in ciphertext):
        return []
    try:
        result = bytes.fromhex(ciphertext).decode('utf-8', errors='ignore')
        score = score_text(result)
        return [(result, score, "Hexadecimal")] if score > -5000 else []
    except Exception:
        return []

def url_decode(ciphertext):
    try:
        result = unquote(ciphertext)
        if result == ciphertext: return []
        score = score_text(result)
        return [(result, score, "URL Encoded")] if score > -5000 else []
    except Exception:
        return []

def base85_decrypt(ciphertext):
    try:
        # standard b85
        decoded = base64.b85decode(ciphertext.strip()).decode('utf-8', errors='ignore')
        score = score_text(decoded)
        return [(decoded, score, "Base85")] if score > -5000 else []
    except Exception:
        return []

def ascii85_decrypt(ciphertext):
    try:
        # Adobe-style ascii85
        decoded = base64.a85decode(ciphertext.strip()).decode('utf-8', errors='ignore')
        score = score_text(decoded)
        return [(decoded, score, "Ascii85")] if score > -5000 else []
    except Exception:
        return []
