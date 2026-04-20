import sys
import argparse
from colorama import init, Fore, Style

# Import from src
from src.utils.nlp import init_nlp, is_word
from src.utils.scoring import score_text, compute_confidence
from src.utils.io import save_best_decryption, save_all_decryptions
from src.engine import automated_decrypt

# Import manual decryptors
from src.ciphers.classical import caesar_decrypt, rot13_decrypt, atbash_decrypt, rail_fence_decrypt, affine_decrypt, reverse_decrypt, columnar_decrypt
from src.ciphers.encoding import base64_decrypt, base32_decrypt, hex_decrypt, binary_decrypt, url_decode, base85_decrypt, ascii85_decrypt
from src.ciphers.esoteric import morse_decrypt, bacon_decrypt
from src.ciphers.modern import xor_decrypt
from src.ciphers.complex import vigenere_decrypt, playfair_decrypt, hill_decrypt_2x2

# Initialize colorama and NLP
init()
init_nlp()

all_results_list = []

def run_automated(ciphertext):
    # Print a distinct start message
    print(f"\n{Fore.CYAN}🚀 Initializing Universal Analysis Engine...{Style.RESET_ALL}")
    
    # We could add a spinner thread here if we wanted to be fancy, 
    # but for now we'll just use better status prints.
    print(f"{Fore.BLUE}🔍 Scanning for 17+ common patterns and encodings...{Style.RESET_ALL}")
    
    results = automated_decrypt(ciphertext)
    
    # Check if a deep search was performed (detect multi-layer in methods)
    deep_search_found = any("->" in r[2] for r in results)
    
    if not results:
        print(f"{Fore.RED}No valid decryption methods found.{Style.RESET_ALL}")
        return

    # Visual Banner for the #1 Best Guess
    best_text, best_score, best_method, best_conf = results[0]
    
    print("\n" + "="*60)
    print(f"{Fore.GREEN}{Style.BRIGHT}🏆 TOP RESULT FOUND{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Method:  {Fore.YELLOW}{best_method}{Style.RESET_ALL}")
    
    conf_color = Fore.GREEN if best_conf > 70 else Fore.YELLOW if best_conf > 30 else Fore.RED
    print(f"{Fore.WHITE}Confidence: {conf_color}{best_conf:.2f}%{Style.RESET_ALL}")
    
    if deep_search_found:
        print(f"{Fore.MAGENTA}✨ Multi-layer Deep Search was applied!{Style.RESET_ALL}")
        
    print("-" * 30)
    print(f"{Fore.CYAN}{Style.BRIGHT}{best_text}{Style.RESET_ALL}")
    print("="*60 + "\n")

    print(f"{Fore.WHITE}Other potential candidates:{Style.RESET_ALL}")
    for i, (text, score, method, conf) in enumerate(results[1:], 2):
        c_color = Fore.GREEN if conf > 70 else Fore.YELLOW if conf > 30 else Fore.WHITE
        # Shorten text for preview
        preview = (text[:60] + '...') if len(text) > 60 else text
        preview = preview.replace('\n', ' ')
        print(f"{i}. {Fore.YELLOW}[{method}]{Style.RESET_ALL} (Conf: {c_color}{conf:5.2f}%{Style.RESET_ALL}) -> {preview}")
    print()
    return results

def manual_menu():
    print(f"\n{Fore.MAGENTA}Manual Decryption Methods:{Style.RESET_ALL}")
    methods = [
        ("1", "Caesar Cipher", ["shift"]),
        ("2", "XOR", ["key"]),
        ("3", "Base64", []),
        ("4", "Base32", []),
        ("5", "Hexadecimal", []),
        ("6", "Morse Code", []),
        ("7", "Atbash Cipher", []),
        ("8", "Vigenere Cipher", ["key"]),
        ("9", "Rail Fence", ["rails"]),
        ("10", "Affine Cipher", ["a", "b"]),
        ("11", "Bacon Cipher", []),
        ("12", "Playfair Cipher", ["key"]),
        ("13", "Hill Cipher (2x2)", ["a", "b", "c", "d"]),
        ("14", "Base85", []),
        ("15", "Ascii85", []),
        ("16", "Reverse Cipher", []),
        ("17", "Columnar (Regular)", ["width"]),
    ]
    
    for idx, name, args in methods:
        print(f"{idx}. {name}")
    
    choice = input(f"{Fore.YELLOW}Enter method (1-17): {Style.RESET_ALL}").strip()
    ciphertext = input(f"{Fore.YELLOW}Enter text to decrypt: {Style.RESET_ALL}").strip()
    
    result = None
    if choice == '1':
        shift = input("Enter shift: ")
        result = caesar_decrypt(ciphertext, shift)[0]
    elif choice == '2':
        key = input("Enter key: ")
        result = xor_decrypt(ciphertext, key)[0]
    elif choice == '3': result = base64_decrypt(ciphertext)[0]
    elif choice == '4': result = base32_decrypt(ciphertext)[0]
    elif choice == '5': result = hex_decrypt(ciphertext)[0]
    elif choice == '6': result = morse_decrypt(ciphertext)[0]
    elif choice == '7': result = atbash_decrypt(ciphertext)[0]
    elif choice == '8':
        key = input("Enter key: ")
        result = vigenere_decrypt(ciphertext, key)[0]
    elif choice == '9':
        rails = input("Enter rails: ")
        result = rail_fence_decrypt(ciphertext, rails)[0]
    elif choice == '10':
        a = input("Enter a: ")
        b = input("Enter b: ")
        result = affine_decrypt(ciphertext, a, b)[0]
    elif choice == '11': result = bacon_decrypt(ciphertext)[0]
    elif choice == '12':
        key = input("Enter key: ")
        result = playfair_decrypt(ciphertext, key)[0]
    elif choice == '13':
        a, b, c, d = input("Enter a,b,c,d (space separated): ").split()
        result = hill_decrypt_2x2(ciphertext, int(a), int(b), int(c), int(d))[0]
    elif choice == '14': result = base85_decrypt(ciphertext)[0]
    elif choice == '15': result = ascii85_decrypt(ciphertext)[0]
    elif choice == '16': result = reverse_decrypt(ciphertext)[0]
    elif choice == '17':
        width = input("Enter width: ")
        result = columnar_decrypt(ciphertext, width)[0]

    if result:
        text, score, method = result
        confidence = compute_confidence(text)
        print(f"{Fore.GREEN}Result:{Style.RESET_ALL} {text} (Confidence: {confidence:.2f}%)")
        all_results_list.append((text, score, method, confidence))

def main():
    parser = argparse.ArgumentParser(description="Universal Decryption Tool")
    parser.add_argument("-a", "--auto", help="Automated decryption of provided text")
    parser.add_argument("-m", "--manual", action="store_true", help="Open manual decryption menu")
    args = parser.parse_args()

    if args.auto:
        run_automated(args.auto)
        return

    if args.manual:
        manual_menu()
        return

    # Interactive Menu (Legacy support)
    print(f"{Fore.YELLOW}=== Universal Decryption Tool ==={Style.RESET_ALL}")
    while True:
        print(f"\n{Fore.MAGENTA}Menu:{Style.RESET_ALL}")
        print("1. Automated Decryption (try everything)")
        print("2. Manual Decryption (specify method)")
        print("3. Exit")
        print("4. Save best decryption")
        print("5. Save all decryption attempts")

        choice = input(f"{Fore.YELLOW}Enter choice (1-5): {Style.RESET_ALL}").strip()

        if choice == '1':
            ciphertext = input(f"{Fore.YELLOW}Enter text to decrypt: {Style.RESET_ALL}").strip()
            if ciphertext:
                res = run_automated(ciphertext)
                if res: all_results_list.extend(res)
        elif choice == '2':
            manual_menu()
        elif choice == '3':
            break
        elif choice == '4':
            if all_results_list:
                best = max(all_results_list, key=lambda x: x[1])
                save_best_decryption(best)
            else: print(f"{Fore.RED}No results to save.{Style.RESET_ALL}")
        elif choice == '5':
            if all_results_list:
                save_all_decryptions(all_results_list)
            else: print(f"{Fore.RED}No results to save.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()