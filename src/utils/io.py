from colorama import Fore, Style
import os

def save_best_decryption(best_result, filename="decrypted.txt"):
    """Saves the best decryption result to a file."""
    text, score, method, confidence = best_result
    
    with open(filename, "w", encoding="utf-8") as file:
        file.write(f"Decryption Method: {method}\n")
        file.write(f"Confidence: {confidence:.2f}%\n")
        file.write(f"Score: {score:.2f}\n")
        file.write(f"Decrypted Text:\n{text}\n")

    print(f"{Fore.GREEN}Best decryption saved to {filename}{Style.RESET_ALL}")

def save_all_decryptions(results_list, filename="decryption_log.txt"):
    """Saves all decryption attempts to a file."""
    with open(filename, "a", encoding="utf-8") as file:
        file.write("\n=== New Decryption Session ===\n")
        for result in results_list:
            if len(result) == 3:
                text, score, method = result
                confidence = 0 # Need to compute if not provided
            else:
                text, score, method, confidence = result
                
            file.write(f"Method: {method}\n")
            file.write(f"Confidence: {confidence:.2f}%\n")
            file.write(f"Score: {score:.2f}\n")
            file.write(f"Decrypted Text: {text}\n")
            file.write("-" * 40 + "\n")

    print(f"{Fore.GREEN}All decryption attempts saved to {filename}{Style.RESET_ALL}")
