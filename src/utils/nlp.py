import nltk
from colorama import Fore, Style
import enchant

# Constants
COMMON_WORDS = set()
DICT = None
USE_ENCHANT = False
CUSTOM_WORDS_LOADED = False  # True once a user-supplied list has replaced the default.

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
    # Only check words that are predominantly alphabetic to avoid Enchant/Glib UTF-8 assertions
    # and improve performance by filtering out punctuation-heavy tokens.
    word = ''.join(filter(str.isalpha, word.lower()))
    
    if len(word) <= 2:
        return False
        
    if word in COMMON_WORDS:
        return True

    # When a custom list is loaded, the user opted out of the broader English
    # dictionary — skip Enchant so scoring reflects only their vocabulary.
    if CUSTOM_WORDS_LOADED:
        return False

    if USE_ENCHANT and DICT:
        try:
            return DICT.check(word)
        except Exception:
            # Silently handle cases where enchant might still fail or error out
            return False
    return False


def load_custom_word_list(path):
    """Replace COMMON_WORDS with one word per line from `path`.

    Returns the number of words loaded (0 on failure). After a successful
    call, `is_word` will validate only against the user's vocabulary and
    skip the Enchant English dictionary — this is the point of a custom
    list (e.g. non-English text, or domain-specific jargon).
    """
    global COMMON_WORDS, CUSTOM_WORDS_LOADED
    try:
        with open(path, 'r', encoding='utf-8') as f:
            words = {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        print(f"{Fore.RED}Word list not found: {path}{Style.RESET_ALL}")
        return 0
    except OSError as e:
        print(f"{Fore.RED}Could not read {path}: {e}{Style.RESET_ALL}")
        return 0

    if not words:
        print(f"{Fore.RED}Word list is empty: {path}{Style.RESET_ALL}")
        return 0

    COMMON_WORDS = words
    CUSTOM_WORDS_LOADED = True
    print(f"{Fore.GREEN}Loaded {len(words)} words from {path}.{Style.RESET_ALL}")
    return len(words)