import re
from ..utils.scoring import score_text

MORSE_CODE_DICT = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G',
    '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N',
    '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U',
    '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z', '-----': '0',
    '.----': '1', '..---': '2', '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9', '...---...': 'SOS'
}

BACON_DICT = {
    'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E', 'AABAB': 'F',
    'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J', 'ABABA': 'K', 'ABABB': 'L',
    'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O', 'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R',
    'BAABA': 'S', 'BAABB': 'T', 'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X',
    'BBAAA': 'Y', 'BBAAB': 'Z', 'BBBAA': '1', 'BBBAB': '2', 'BBABA': '3', 'BBABB': '4',
    'BBBBA': '5', 'BBBBB': '6'
}

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
