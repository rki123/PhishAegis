"""
Synthetic URL Data Augmentation.
Generates realistic URL variants from existing malicious URLs
to give the model more diverse training examples.
"""
import random
import re
from urllib.parse import urlparse


# Character substitutions commonly used in phishing
CHAR_SWAPS = {
    'o': '0', '0': 'o',
    'l': '1', '1': 'l',
    'i': '1',
    'e': '3', '3': 'e',
    'a': '@', 's': '5',
    'g': '9', 'b': '6',
}

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
                   '.site', '.live', '.online', '.club', '.icu', '.work']

PHISHING_WORDS = ['login', 'secure', 'verify', 'account', 'update',
                  'confirm', 'banking', 'signin', 'password', 'auth',
                  'wallet', 'recover', 'suspend', 'alert', 'urgent']

FAKE_SUBDOMAINS = ['secure', 'login', 'auth', 'account', 'verify',
                   'update', 'service', 'support', 'help', 'mail',
                   'my', 'web', 'app', 'portal', 'client']

random.seed(42)


def swap_chars(url, n_swaps=1):
    """Randomly swap characters with lookalikes (e.g., o->0, l->1)."""
    chars = list(url)
    swappable = [(i, c) for i, c in enumerate(chars) if c in CHAR_SWAPS]
    if not swappable:
        return url
    for _ in range(min(n_swaps, len(swappable))):
        idx, char = random.choice(swappable)
        chars[idx] = CHAR_SWAPS[char]
        swappable.remove((idx, char))
    return ''.join(chars)


def add_subdomain(url):
    """Prepend a phishing-style subdomain."""
    sub = random.choice(FAKE_SUBDOMAINS)
    # Strip scheme if present
    clean = url
    scheme = ''
    if '://' in clean:
        scheme, clean = clean.split('://', 1)
        scheme += '://'
    return scheme + sub + '.' + clean


def change_tld(url):
    """Replace TLD with a suspicious one."""
    clean = url
    scheme = ''
    if '://' in clean:
        scheme, clean = clean.split('://', 1)
        scheme += '://'
    # Find the domain part (before first /)
    parts = clean.split('/', 1)
    domain = parts[0]
    rest = '/' + parts[1] if len(parts) > 1 else ''
    # Replace TLD
    dot_idx = domain.rfind('.')
    if dot_idx > 0:
        domain = domain[:dot_idx] + random.choice(SUSPICIOUS_TLDS)
    return scheme + domain + rest


def add_phishing_path(url):
    """Add a phishing-style path segment."""
    word = random.choice(PHISHING_WORDS)
    if url.endswith('/'):
        return url + word
    return url + '/' + word


def add_query_params(url):
    """Add suspicious query parameters."""
    params = random.choice([
        '?user=admin&action=verify',
        '?token=abc123&redirect=true',
        '?id=1&login=true',
        '?session=expired&update=1',
        '?ref=email&action=confirm',
    ])
    if '?' in url:
        return url + '&extra=1'
    return url + params


def add_encoding(url):
    """Add percent-encoding obfuscation to parts of the URL."""
    # Encode a few random characters
    chars = list(url)
    for i in range(len(chars)):
        if chars[i].isalpha() and random.random() < 0.15:
            chars[i] = '%' + format(ord(chars[i]), '02x')
    return ''.join(chars)


def augment_url(url):
    """Apply 1-3 random transformations to create a URL variant."""
    transforms = [swap_chars, add_subdomain, change_tld,
                  add_phishing_path, add_query_params, add_encoding]
    n = random.randint(1, 3)
    chosen = random.sample(transforms, min(n, len(transforms)))
    result = url
    for fn in chosen:
        try:
            result = fn(result)
        except Exception:
            pass
    return result


def generate_synthetic_urls(urls, n_augmented=1):
    """
    Generate synthetic URL variants from existing URLs.
    Each URL gets n_augmented variants.
    Returns a list of augmented URLs.
    """
    augmented = []
    for url in urls:
        for _ in range(n_augmented):
            try:
                aug = augment_url(url)
                if aug != url and len(aug) > 5:
                    augmented.append(aug)
            except Exception:
                continue
    return augmented
