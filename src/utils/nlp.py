import nltk
from colorama import Fore, Style
import enchant

# Constants
COMMON_WORDS = set()
DICT = None
USE_ENCHANT = False

def init_nlp():
    global COMMON_WORDS, DICT, USE_ENCHANT
    
    # Initialize NLTK
    try:
        nltk.data.find('tokenizers/punkt')
        nltk.data.find('corpora/words')
    except LookupError:
        nltk.download('punkt')
        nltk.download('words')
    
    # Try to initialize pyenchant; fallback if not available
    try:
        DICT = enchant.Dict("en_US")
        USE_ENCHANT = True
    except (enchant.errors.DictNotFoundError, ImportError, Exception):
        USE_ENCHANT = False
        print(f"{Fore.YELLOW}Enchant library not found or dict missing. Using fallback word list.{Style.RESET_ALL}")

    # Expanded common words list (NLTK fallback)
    try:
        COMMON_WORDS = set(nltk.corpus.words.words()[:10000])
    except Exception:
        COMMON_WORDS = set()
        
    COMMON_WORDS.update({
        'hello', 'world', 'secret', 'code', 'test', 'data', 'secure', 'encrypt', 'decrypt', 'hidden',
        'message', 'now', 'alert', 'python', 'cipher', 'key', 'password', 'example', 'sample', 'text',
        'string', 'number', 'one', 'two', 'three', 'four', 'five', 'sos', 'testing', 'encode', 'decode'
    })

def is_word(word):
    word = word.lower()
    if len(word) <= 2:
        return False
    if word in COMMON_WORDS:
        return True
    if USE_ENCHANT and DICT:
        try:
            return DICT.check(word)
        except Exception:
            return False
    return False
