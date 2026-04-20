import pytest
from src.ciphers.classical import caesar_decrypt, atbash_decrypt, affine_decrypt
from src.ciphers.encoding import base64_decrypt, binary_decrypt
from src.ciphers.esoteric import morse_decrypt
from src.ciphers.complex import playfair_decrypt, hill_decrypt_2x2
from src.engine import automated_decrypt

def test_caesar():
    # "Hello" shifted by 3 is "Khoor"
    result = caesar_decrypt("Khoor", shift=3)
    assert result[0][0] == "Hello"

def test_atbash():
    # "Hello" in Atbash is "Svool"
    result = atbash_decrypt("Svool")
    assert result[0][0] == "Hello"

def test_base64():
    # "SGVsbG8=" is "Hello"
    result = base64_decrypt("SGVsbG8=")
    assert result[0][0] == "Hello"

def test_binary():
    # "01001000 01100101 01101100 01101100 01101111" is "Hello"
    result = binary_decrypt("01001000 01100101 01101100 01101100 01101111")
    assert result[0][0] == "Hello"

def test_morse():
    # ".... . .-.. .-.. ---" is "HELLO"
    result = morse_decrypt(".... . .-.. .-.. ---")
    assert result[0][0] == "HELLO"

def test_affine():
    # "Hello" with a=5, b=8 is "Rclla"
    # a_inv = 21. (5*21 = 105 = 4*26 + 1)
    # H(7): (5*7+8)%26 = 43%26 = 17 (R)
    # e(4): (5*4+8)%26 = 28%26 = 2 (c)
    # l(11): (5*11+8)%26 = 63%26 = 11 (l)
    # o(14): (5*14+8)%26 = 78%26 = 0 (a)
    result = affine_decrypt("Rclla", a=5, b=8)
    assert result[0][0] == "Hello"

def test_playfair():
    # Key: "SECRET" -> Matrix: S E C R T / A B D F G / H I K L M / N O P Q U / V W X Y Z
    # "Hello" -> HE LL O -> HE LX LO -> (Matrix logic)
    # H(2,0), E(0,1) -> Rec: (2,1)=I, (0,0)=S -> IS
    # L(2,3), X(4,2) -> Rec: (2,2)=K, (4,3)=Y -> KY
    # L(2,3), O(3,1) -> Rec: (2,1)=I, (3,3)=Q -> IQ
    # "HELXLO" -> "ISKYIQ"
    result = playfair_decrypt("ISKYIQ", "SECRET")
    # Playfair might return "HELXLO" (with filler X)
    assert "HEL" in result[0][0]

def test_hill_2x2():
    # Matrix [[3, 3], [2, 5]]
    # "HE L L O" -> HE (7,4), LL (11,11), O (14, filler 14)
    # H,E: [3 3; 2 5] * [7; 4] = [21+12; 14+20] = [33; 34] mod 26 = [7; 8] (H, I)
    # L,L: [3 3; 2 5] * [11; 11] = [33+33; 22+55] = [66; 77] mod 26 = [14; 25] (O, Z)
    # Cipher: HIOZ
    result = hill_decrypt_2x2("HIOZ", 3, 3, 2, 5)
    assert result[0][0] == "HELL"

def test_engine():
    # Caesar shift 1: "Hello" -> "Ifmmp"
    results = automated_decrypt("Ifmmp")
    assert any("Hello" in r[0] for r in results)

def test_multi_layer():
    # Double encoding: "Attack at dawn" -> Base64 -> Reverse
    # "Attack at dawn" -> "QXR0YWNrIGF0IGRhd24="
    # Reversed: "=42dhRGI0FGIrNWY0RXQ"
    ciphertext = "=42dhRGI0FGIrNWY0RXQ"
    results = automated_decrypt(ciphertext)
    # The nested method should be 'Reverse -> Base64'
    assert any("Attack at dawn" in r[0] for r in results)
