from .utils.scoring import score_text, compute_confidence
from .ciphers.encoding import base64_decrypt, base32_decrypt, binary_decrypt, hex_decrypt, url_decode, base85_decrypt, ascii85_decrypt
from .ciphers.classical import caesar_decrypt, rot13_decrypt, atbash_decrypt, rail_fence_decrypt, affine_decrypt
from .ciphers.esoteric import morse_decrypt, bacon_decrypt
from .ciphers.modern import xor_decrypt, hash_detect
from .ciphers.complex import vigenere_decrypt

def automated_decrypt(ciphertext):
    all_results = []
    
    # Check input patterns for prioritization
    is_binary = all(c in '01 ' for c in ciphertext)
    is_morse = all(c in '.- ' for c in ciphertext)
    
    # List of decryptor functions
    decryptors = [
        base64_decrypt, base32_decrypt, caesar_decrypt, rot13_decrypt,
        atbash_decrypt, vigenere_decrypt, rail_fence_decrypt, binary_decrypt,
        hex_decrypt, morse_decrypt, bacon_decrypt, affine_decrypt,
        url_decode, hash_detect, xor_decrypt, base85_decrypt, ascii85_decrypt
    ]
    
    # Collect results from all decryptors
    for decryptor in decryptors:
        try:
            results = decryptor(ciphertext)
            if not results: continue
            
            # Apply prioritization bonuses
            if decryptor == binary_decrypt and is_binary:
                results = [(r[0], r[1] + 10000, r[2]) for r in results]
            elif decryptor == morse_decrypt and is_morse:
                results = [(r[0], r[1] + 10000, r[2]) for r in results]
                
            all_results.extend(results)
        except Exception:
            continue
    
    # Include plaintext
    plaintext_score = score_text(ciphertext)
    all_results.append((ciphertext, plaintext_score, "Plaintext"))
    
    # Remove duplicates and calculate confidence
    unique_results = {}
    for r in all_results:
        text, score, method = r
        if score < -10000: continue
        
        if text not in unique_results or score > unique_results[text][1]:
            confidence = compute_confidence(text)
            unique_results[text] = (text, score, method, confidence)
    
    # Sort and filter
    ranked_results = sorted(unique_results.values(), key=lambda x: x[1], reverse=True)
    
    # Heuristic filtering: if we have high confidence results, show them. 
    # Otherwise show best scores.
    top_results = ranked_results[:5]
    
    return top_results
