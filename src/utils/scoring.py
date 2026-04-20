from nltk.tokenize import word_tokenize
from .nlp import is_word

ENGLISH_FREQ = {
    'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7, 's': 6.3,
    'h': 6.1, 'r': 5.9, 'd': 4.3, 'l': 4.0, 'c': 3.4, 'u': 3.0, 'm': 2.4,
    'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 1.9, 'p': 1.9, 'b': 1.5, 'v': 1.0,
    'k': 0.8, 'j': 0.2, 'x': 0.2, 'q': 0.1, 'z': 0.1
}

def score_text(text):
    if not text or len(text) < 3 or not any(c.isalpha() for c in text):
        return -100000
    
    text_lower = text.lower()
    
    # Word validation
    try:
        words = word_tokenize(text_lower)
    except Exception:
        words = text_lower.split()

    valid_words = 0
    for w in words:
        if is_word(w):
            valid_words += 1

    score = valid_words * 1000  # Boost score for valid words
    
    # Penalty for excessive non-printable characters or weird ratios
    alpha_chars = sum(1 for c in text if c.isalpha())
    if len(text) > 0 and (alpha_chars / len(text)) < 0.3:
        score -= 500
        
    return score

def compute_confidence(text):
    try:
        words = word_tokenize(text.lower())
    except Exception:
        words = text.lower().split()
        
    meaningful_words = [w for w in words if len(w) > 2 and any(c.isalpha() for c in w)]
    if not meaningful_words:
        return 0

    valid_words = sum(1 for w in meaningful_words if is_word(w))
    confidence = (valid_words / len(meaningful_words)) * 100
    return min(confidence, 100)
