import base64
import random
import string
import pyperclip

# Step 1: Shift each character by 5 (Caesar Cipher)
def shift_by_5(message):
    alphabet = string.ascii_lowercase
    shifted_alphabet = alphabet[5:] + alphabet[:5]
    shifted_message = ""
    for char in message:
        if char.isalpha():
            if char.islower():
                shifted_message += shifted_alphabet[alphabet.index(char)]
            else:
                shifted_message += shifted_alphabet[alphabet.index(char.lower())].upper()
        else:
            shifted_message += char
    return shifted_message


# Step 1b: Replace spaces with underscores
def replace_spaces(message):
    return message.replace(' ', '_')


# Step 2: Base64 encode
def base64_encode(message):
    return base64.encodebytes(message.encode()).decode()


# Step 3: Add symbols (#, %, $)
def add_symbols(encoded_message):
    return '#'.join(encoded_message[i:i+3] for i in range(0, len(encoded_message), 3))


# Step 4: XOR encryption with key
def xor_encrypt(message, key):
    key_bytes = key.encode()
    message_bytes = message.encode()
    encrypted_bytes = bytearray(len(message_bytes))
    for i, (m, k) in enumerate(zip(message_bytes, key_bytes * (len(message_bytes) // len(key_bytes) + 1))):
        encrypted_bytes[i] = m ^ k
    return encrypted_bytes.decode()


# New step: Additional XOR encryption
def additional_xor(message, second_key):
    second_key_length = len(second_key)
    return ''.join(chr(ord(m) ^ ord(second_key[i % second_key_length])) for i, m in enumerate(message))


# To decrypt the XOR, just apply the same XOR operation again
def xor_decrypt(encrypted_message, key):
    key_bytes = key.encode()
    encrypted_bytes = encrypted_message.encode()
    decrypted_bytes = bytearray(
        m ^ key_bytes[i % len(key_bytes)]
        for i, m in enumerate(encrypted_bytes)
    )
    return decrypted_bytes.decode()


# To remove symbols for decryption
def remove_symbols(symbolized_message):
    symbols = {'#', '%', '$'}
    return ''.join(filter(lambda c: c not in symbols, symbolized_message))


# Base64 decode
def base64_decode(encoded_message):
    return base64.decodebytes(encoded_message.encode()).decode()


# Reverse the character shift
def reverse_shift_by_5(shifted_message):
    alphabet = string.ascii_lowercase
    return ''.join(
        chr((ord(char) - ord('a') - 5) % 26 + ord('a')) if char.islower() else
        chr((ord(char) - ord('A') - 5) % 26 + ord('A')) if char.isupper() else
        char
        for char in shifted_message
    )


# Generate a random XOR key
def generate_random_key(length=6):
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choices(alphabet, k=length))


# Encrypt function
def encrypt(message, key):
    message = replace_spaces(message)
    message = shift_by_5(message)
    message = base64_encode(message)
    message = add_symbols(message)
    message = xor_encrypt(message, key)
    message = additional_xor(message, key)
    return message, key


# Decrypt function
def decrypt(final_encrypted_message, key):
    decrypted_first_layer = additional_xor(final_encrypted_message, key)
    symbolized_message = xor_decrypt(decrypted_first_layer, key)
    base64_encoded = remove_symbols(symbolized_message)
    shifted_message = base64_decode(base64_encoded)
    return reverse_shift_by_5(shifted_message).replace('_', ' ')


# Main function to handle user input
def main():
    while True:
        print("\nWhat would you like to do?")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Exit")

        choice = input("Enter your choice (1/2/3): ").strip()

        if choice == '1':
            message = input("Enter the message to encrypt: ")
            random_key = generate_random_key()
            encrypted_message, key = encrypt(message, random_key)

            pyperclip.copy(''.join(f'{ord(c):02x}' for c in encrypted_message))
            print(f"Encrypted message (copied to clipboard): {''.join(f'{ord(c):02x}' for c in encrypted_message)}")
            print(f"Encryption key (for decryption): {random_key}")

        elif choice == '2':
            encrypted_message = bytes.fromhex(input("Enter the encrypted message (hex): ")).decode()
            key = input("Enter the encryption key: ")
            decrypted_message = decrypt(encrypted_message, key)
            print(f"Decrypted message: {decrypted_message}")

        elif choice == '3':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
