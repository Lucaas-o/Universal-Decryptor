import concurrent.futures
from .utils.scoring import score_text, compute_confidence
from .ciphers.encoding import base64_decrypt, base32_decrypt, binary_decrypt, hex_decrypt, url_decode, base85_decrypt, ascii85_decrypt
from .ciphers.classical import caesar_decrypt, rot13_decrypt, atbash_decrypt, rail_fence_decrypt, affine_decrypt, reverse_decrypt, columnar_decrypt
from .ciphers.esoteric import morse_decrypt, bacon_decrypt
from .ciphers.modern import xor_decrypt, hash_detect
from .ciphers.complex import vigenere_decrypt

from .utils.nlp import init_nlp

def automated_decrypt(ciphertext, depth=1):
    # Ensure NLP is initialized (NLTK data, dictionaries, etc.)
    init_nlp()
    
    all_results = []
    
    # Check input patterns for prioritization
    is_binary = all(c in '01 ' for c in ciphertext) and len(ciphertext) > 7
    is_morse = all(c in '.- /' for c in ciphertext) and any(c in '.-' for c in ciphertext)
    
    # List of decryptor functions
    decryptors = [
        base64_decrypt, base32_decrypt, caesar_decrypt, rot13_decrypt,
        atbash_decrypt, vigenere_decrypt, rail_fence_decrypt, binary_decrypt,
        hex_decrypt, morse_decrypt, bacon_decrypt, affine_decrypt,
        url_decode, hash_detect, xor_decrypt, base85_decrypt, ascii85_decrypt,
        reverse_decrypt, columnar_decrypt
    ]
    
    def run_decryptor(d, text):
        try:
            res = d(text)
            if not res: return []
            processed = []
            for r_text, r_score, r_method in res:
                # Prioritization bonuses
                if d == binary_decrypt and is_binary: r_score += 10000
                elif d == morse_decrypt and is_morse: r_score += 10000
                processed.append((r_text, r_score, r_method))
            return processed
        except Exception:
            return []

    # Layer 1: Parallel Execution
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(decryptors)) as executor:
        future_to_decryptor = {executor.submit(run_decryptor, d, ciphertext): d for d in decryptors}
        for future in concurrent.futures.as_completed(future_to_decryptor):
            all_results.extend(future.result())
    
    # Include plaintext
    plaintext_score = score_text(ciphertext)
    all_results.append((ciphertext, plaintext_score, "Plaintext"))
    
    # Deduplicate and initial ranking
    unique_results = {}
    for text, score, method in all_results:
        if score < -10000: continue
        if text not in unique_results or score > unique_results[text][1]:
            unique_results[text] = (text, score, method)
    
    ranked_results = sorted(unique_results.values(), key=lambda x: x[1], reverse=True)
    
    # --- RECURSIVE RE-CHECK (Deep Search) ---
    # If we are at depth 1 and the best result is not high confidence, 
    # try one more layer on the top 5 candidates.
    if depth == 1:
        best_candidate = ranked_results[0] if ranked_results else (None, -99999, "")
        best_confidence = compute_confidence(best_candidate[0]) if best_candidate[0] else 0
        
        if best_confidence < 90:
            # Deep Search! Try top 5 candidates
            deep_results = []
            candidates = ranked_results[:5]
            
            # Heuristic: Always include Reverse in candidates if it's not already there
            # because it's very common and can bridge other ciphers.
            rev_res = unique_results.get(ciphertext[::-1])
            if rev_res and rev_res not in candidates:
                candidates.append(rev_res)

            for candidate_text, candidate_score, candidate_method in candidates:
                if candidate_text == ciphertext: continue
                
                sub_results = automated_decrypt(candidate_text, depth=2)
                for sub_text, sub_score, sub_method, sub_conf in sub_results:
                    if sub_method == "Plaintext": continue
                    combined_method = f"{candidate_method} -> {sub_method}"
                    # Bonus for finding something better in deep search
                    deep_results.append((sub_text, sub_score, combined_method))
            
            # Merge deep results back
            for text, score, method in deep_results:
                if text not in unique_results or score > unique_results[text][1]:
                    unique_results[text] = (text, score, method)
            
            ranked_results = sorted(unique_results.values(), key=lambda x: x[1], reverse=True)

    # Final Confidence calculation and formatting
    final_output = []
    for text, score, method in ranked_results:
        conf = compute_confidence(text)
        final_output.append((text, score, method, conf))
        
    return sorted(final_output, key=lambda x: x[1], reverse=True)[:5]
