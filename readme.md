# Message Encryption and Decryption Tool

This is a Python script that provides a simple menu-driven interface for encrypting and decrypting messages using a combination of Caesar Cipher, Base64 encoding, and XOR encryption.

## Features

Encrypts messages using a combination of Caesar Cipher, Base64 encoding, and XOR encryption
Decrypts messages using the same encryption keys
Generates random encryption keys for each encryption operation
Copies encrypted messages to the clipboard for easy sharing
Supports hexadecimal input for decryption

## Usage

Run the script using python encrypt_decrypt.py
Choose an option from the menu:
1: Encrypt a message
2: Decrypt a message
3: Exit
Follow the prompts to enter the message to encrypt or decrypt, and the encryption key (if required)

## Encryption Process

Replace spaces with underscores
Shift each character by 5 positions (Caesar Cipher)
Base64 encode the message
Add symbols (#, %, $) to the encoded message
XOR encrypt the message with a random key
Perform an additional XOR encryption with the same key

## Decryption Process

Remove symbols from the encrypted message
XOR decrypt the message with the encryption key
Base64 decode the message
Reverse the Caesar Cipher shift
Replace underscores with spaces

## Requirements

Python 3.x
pyperclip library for clipboard operations
base64 library for Base64 encoding and decoding

### Notes

The encryption key is generated randomly for each encryption operation and is required for decryption.
The encrypted message is copied to the clipboard for easy sharing.
The script uses hexadecimal input for decryption to ensure accurate transmission of the encrypted message.
