import re
import math
from urllib.parse import urlparse, unquote


def entropy(string):
    if not string:
        return 0.0
    prob = [float(string.count(c)) / len(string) for c in set(string)]
    return -sum(p * math.log2(p) for p in prob)


def url_length(url):
    return len(url)


def hostname_length(url):
    try:
        netloc = urlparse(url).netloc
        return len(netloc) if netloc else 0
    except Exception:
        return 0


def domain_entropy(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname if parsed.hostname else ""
        return entropy(hostname)
    except Exception:
        return 0



def count_special_characters(url):
    chars = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']
    return sum(url.count(c) for c in chars)


def digit_count(url):
    return sum(c.isdigit() for c in url)


def letter_count(url):
    return sum(c.isalpha() for c in url)


def digit_ratio(url):
    if len(url) == 0:
        return 0.0
    return sum(c.isdigit() for c in url) / len(url)


def having_ip_address(url):
    """Returns 1 if the URL uses an IP address instead of a domain name."""
    try:
        netloc = urlparse(url).netloc
        if not netloc:
            return 0
        hostname = netloc.split(':')[0]
        # IPv4 regex
        ipv4_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        # IPv6 regex
        ipv6_pattern = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
        
        if ipv4_pattern.match(hostname) or ipv6_pattern.match(hostname):
            return 1
        return 0
    except:
        return 0


def has_shortening_service(url):
    """Returns 1 if a known URL shortener is detected."""
    shortening_services = (
        r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
        r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
        r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
        r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|"
        r"db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|"
        r"q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
        r"x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|"
        r"v\.gd|tr\.im|link\.zip\.net"
    )
    match = re.search(shortening_services, url, flags=re.IGNORECASE)
    return 1 if match else 0


def has_javascript_Code(url):
    return 1 if "javascript:" in url.lower() else 0


def check_text_encoding(url):
    """Returns 1 if obfuscated %xx encoding is found."""
    return 1 if "%" in url else 0


def path_depth(url):
    """Counts the depth of the URL path."""
    try:
        parsed = urlparse(url)
        path = parsed.path
        # Ignore trailing slashes
        if path.endswith('/'):
            path = path[:-1]
        # Split by slash and remove empty strings
        depth = len([segment for segment in path.split('/') if segment])
        return depth
    except Exception:
        return 0


def subdomain_count(url):
    """Counts the number of subdomains in the URL."""
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return 0
        # If it's an IP, 0 subdomains
        if having_ip_address(url):
            return 0
        
        parts = hostname.split('.')
        # Usually, the last two parts are domain.tld (e.g., example.com)
        # Anything before that is a subdomain.
        if len(parts) > 2:
            return len(parts) - 2
        return 0
    except:
        return 0


def suspicious_tld(url):
    """Returns 1 if the TLD is known to be frequently abused."""
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return 0
        
        abused_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.site', 
            '.live', '.online', '.club', '.stream', '.men', '.icu', '.work'
        }
        
        # Check if hostname ends with any abused TLD
        for tld in abused_tlds:
            if hostname.lower().endswith(tld):
                return 1
        return 0
    except:
        return 0


def abnormal_url(url):
    """Returns 1 if the hostname is NOT present within the raw URL string."""
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return 1
        if hostname not in url:
            return 1
        return 0
    except:
        return 1


# --- DATA LEAKAGE FIX --- #
def extract_features(url):
    """
    Normalizes the URL to remove dataset-biased prefixes (http, https, www)
    before extracting pure mathematical features.
    """
    raw_url = url.lower()
    
    # 1. Clean the URL (Strip Schemes & WWW) to fix Data Leakage bias
    clean_url = raw_url
    if clean_url.startswith('https://'):
        clean_url = clean_url[8:]
    elif clean_url.startswith('http://'):
        clean_url = clean_url[7:]
    
    if clean_url.startswith('www.'):
        clean_url = clean_url[4:]
        
    # 2. Artificially prepend 'http://' to EVERYTHING so urlparse() works perfectly.
    # Without a scheme, Python's urlparse fails to find the netloc/hostname for Benign URLs.
    parsed_url = 'http://' + clean_url
    
    # 3. Extract purely mathematical 16 features
    features = {
        'url_len': len(clean_url),
        'hostname_length': hostname_length(parsed_url),
        'num_special_chars': count_special_characters(clean_url),
        'domain_entropy': domain_entropy(parsed_url),
        'digit_count': digit_count(clean_url),
        'letter_count': letter_count(clean_url),
        'digit_ratio': digit_ratio(clean_url),
        'use_of_ip': having_ip_address(parsed_url),
        'has_shortening_service': has_shortening_service(clean_url),
        'has_javascript_code': has_javascript_Code(raw_url),
        'has_text_encoding': check_text_encoding(raw_url),
        'path_depth': path_depth(parsed_url),
        'subdomain_count': subdomain_count(parsed_url),
        'has_at_symbol': 1 if '@' in clean_url else 0,
        'suspicious_tld': suspicious_tld(parsed_url),
        'abnormal_url': abnormal_url(parsed_url)
    }
    return features


def get_feature_names():
    return [
        'url_len', 'hostname_length', 'num_special_chars', 'domain_entropy',
        'digit_count', 'letter_count', 'digit_ratio',
        'use_of_ip', 'has_shortening_service', 'has_javascript_code',
        'has_text_encoding', 'path_depth', 'subdomain_count',
        'has_at_symbol', 'suspicious_tld', 'abnormal_url'
    ]
