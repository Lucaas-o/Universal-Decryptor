# Universal Decryption Tool

A Python-based tool designed to decrypt a wide variety of ciphers by intelligently guessing the encryption method and producing human-readable results. Whether you're exploring cryptography or solving puzzles, this tool offers both automated and manual decryption capabilities with a user-friendly, colorful command-line interface.

## Features

- **Automated Mode**: Attempts multiple decryption methods (e.g., Caesar Cipher, XOR, Base64, Binary, Morse Code) and ranks results by readability using a scoring system based on English letter frequency and word detection.
- **Manual Mode**: Supports 9 specific decryption methods, including advanced ciphers like Affine and Hill, with customizable keys.
- **Confidence Scores**: Displays a percentage indicating the likelihood each result is correct, based on English word recognition.
- **Input Prioritization**: Boosts Binary decryption for `0` and `1` inputs and Morse Code for `.` and `-` patterns.
- **File Output**: Save decryption results to a text file for later analysis.
- **Colorful CLI**: Uses `colorama` for an intuitive, visually appealing terminal experience.
- **Extensive Cipher Support**: Handles plain text, hexadecimal, binary, and more, with robust error handling.

## Installation

1. **Install Python**: Ensure you have Python 3.13 or later installed. [Download Python](https://www.python.org/downloads/).
2. **Clone the Repository**:

   ```sh
   git clone https://github.com/yourusername/Encryption-Decryption.git
   cd Encryption-Decryption
   ```

3. **Install Dependencies**:

   ```sh
   pip install -r requirements.txt
   ```

   Dependencies include `colorama`, `nltk`, and optionally `pyenchant` for enhanced word validation.

## Usage

1. **Run the Tool**:

   ```sh
   python decryptor.py
   ```

2. **Menu Options**:
   - `1. Automated Decryption`: Tries all supported methods and displays the top 5 results.
   - `2. Manual Decryption`: Choose a specific method and provide a key if required.
   - `3. Save Results to File`: Saves the latest decryption results to `decryption_results.txt`.
   - `4. Exit`: Closes the tool.

3. **Follow Prompts**: Enter the text to decrypt and select options as guided.

### Example

**Input**:

```sh
01001000 01100101 01101100 01101100 01101111
```

**Output**:

```
=== Universal Decryption Tool ===

Menu:

    Automated Decryption (try everything)
    Manual Decryption (specify method)
    Save Results to File
    Exit

Enter choice (1-4): 1
Enter text to decrypt: 01001000 01100101 01101100 01101100 01101111
Analyzing...
--- Starting Automated Decryption ---
Trying caesar_decrypt...
Trying xor_decrypt...
--- Decryption Complete ---
Top decryption results:
    Hello (Score: 15020.00, Confidence: 100.00%, Method: Binary)
```

## How It Works

- **Automated Decryption**: Tests a suite of decryption methods (Caesar, XOR, Base64, etc.), scores results using English letter frequency and a dictionary check (via `nltk` and optionally `pyenchant`), and prioritizes methods based on input patterns (e.g., binary or Morse).
- **Manual Decryption**: Offers precise control with methods like:
  - `Caesar Cipher (shift)`
  - `XOR (key)`
  - `Base64`, `Base32`, `Hexadecimal` (no key)
  - `Morse Code` (no key)
  - `Affine Cipher (key: a,b)`
  - `Playfair Cipher (key)`
  - `Hill Cipher (key: a,b,c,d)`
- **Scoring**: Combines frequency analysis with word validation, applying bonuses for valid English and penalties for non-printable characters or excessive digits.

## Requirements

- **Python**: `3.13` or later
- **Dependencies** (listed in `requirements.txt`):

  ```
  colorama==0.4.6  # For colored terminal output
  nltk==3.9.1      # For word tokenization and validation
  pyenchant==3.2.2 # (Optional) Enhances word recognition; falls back to nltk if unavailable.
  ```

## Notes

- **Limitations**: Not guaranteed to decrypt complex or heavily keyed ciphers without hints (e.g., unknown Vigenère keys). Advanced ciphers like Playfair and Hill are placeholders awaiting full implementation.
- **Purpose**: Designed for educational exploration and cipher-solving fun, not as a professional cryptographic solution.
- **Logging**: Errors are logged to `decryption_tool.log` for debugging.

## Contributing

We welcome contributions! Here's how to get started:

1. Fork the repository.
2. Create a branch:
   
   ```sh
   git checkout -b feature/your-feature
   ```

3. Commit changes:

   ```sh
   git commit -m "Add your feature"
   ```

4. Push to your fork:

   ```sh
   git push origin feature/your-feature
   ```

5. Open a pull request.

Check out our issues page for tasks. Look for `good first issue` labels if you're new to contributing! See `CONTRIBUTING.md` for details.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Feedback

Have suggestions or found a bug? Open an issue or use the "Provide Feedback" option in the tool (coming soon!). Your input helps us improve.
