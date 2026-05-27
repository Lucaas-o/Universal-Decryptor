"""Unit tests for caesar_decrypt.

Issue #2: verify caesar_decrypt works with inputs like
'Khoor' (shift 3) -> 'Hello' and friends.
"""
import pytest
from src.ciphers.classical import caesar_decrypt


# ---------- shift mode (known-shift decryption) ----------

def test_caesar_khoor_shift_3():
    """The canonical example from issue #2."""
    result = caesar_decrypt("Khoor", shift=3)
    assert result[0][0] == "Hello"


def test_caesar_preserves_mixed_case():
    # 'HELLO' all uppercase round-trip.
    assert caesar_decrypt("KHOOR", shift=3)[0][0] == "HELLO"
    # all lowercase.
    assert caesar_decrypt("khoor", shift=3)[0][0] == "hello"


def test_caesar_preserves_non_alpha():
    # Punctuation, digits, and spaces must pass through unchanged.
    assert caesar_decrypt("Khoor, Zruog! 123", shift=3)[0][0] == "Hello, World! 123"


def test_caesar_wraparound_at_alphabet_edges():
    # 'a' shifted forward by 1 becomes 'b'; decrypt 'b' with shift 1 -> 'a'.
    # 'A' shifted forward by 1 becomes 'B'; decrypt 'A' with shift 1 -> 'Z' (wrap).
    assert caesar_decrypt("b", shift=1)[0][0] == "a"
    assert caesar_decrypt("A", shift=1)[0][0] == "Z"
    assert caesar_decrypt("a", shift=1)[0][0] == "z"


def test_caesar_shift_zero_is_identity():
    assert caesar_decrypt("Hello, World!", shift=0)[0][0] == "Hello, World!"


def test_caesar_shift_26_is_identity():
    # A full rotation should leave the text unchanged.
    assert caesar_decrypt("Hello", shift=26)[0][0] == "Hello"


def test_caesar_negative_shift():
    # Decrypting with -3 is the same as encrypting with +3.
    # 'Hello' + 3 = 'Khoor', so decrypt 'Hello' with shift=-3 -> 'Khoor'.
    assert caesar_decrypt("Hello", shift=-3)[0][0] == "Khoor"


def test_caesar_large_shift_wraps_mod_26():
    # shift=29 ≡ shift=3.
    assert caesar_decrypt("Khoor", shift=29)[0][0] == "Hello"


def test_caesar_accepts_string_shift():
    # decryptor.py passes the shift in as a string from the menu;
    # caesar_decrypt must tolerate that.
    assert caesar_decrypt("Khoor", shift="3")[0][0] == "Hello"


def test_caesar_returns_method_label():
    # The third tuple element must describe the operation.
    _, _, method = caesar_decrypt("Khoor", shift=3)[0]
    assert "Caesar" in method
    assert "3" in method


def test_caesar_empty_string():
    # No alphabetic content -> score_text penalises it (-100000), so the
    # function still returns a result but with a sentinel score.
    result = caesar_decrypt("", shift=3)
    assert result[0][0] == ""


# ---------- brute-force mode (shift=None) ----------

def test_caesar_brute_force_finds_hello():
    """With shift=None the function tries every shift; 'Hello' must appear."""
    results = caesar_decrypt("Khoor")
    decoded_texts = [r[0] for r in results]
    assert "Hello" in decoded_texts


def test_caesar_brute_force_returns_sorted():
    """Results should be sorted by score, highest first."""
    results = caesar_decrypt("Khoor")
    scores = [r[1] for r in results]
    assert scores == sorted(scores, reverse=True)


def test_caesar_brute_force_returns_list_of_tuples():
    """API shape: list of (text, score, method) tuples."""
    results = caesar_decrypt("Khoor")
    assert isinstance(results, list)
    for entry in results:
        assert len(entry) == 3
        text, score, method = entry
        assert isinstance(text, str)
        assert isinstance(score, (int, float))
        assert isinstance(method, str)