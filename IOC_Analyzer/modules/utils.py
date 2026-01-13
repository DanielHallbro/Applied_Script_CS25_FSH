import re

def is_valid_ip(ioc: str) -> bool:
    # Checks if the string is a valid IPv4 address.
    # Simple check for IPv4 address
    ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ipv4_pattern.match(ioc):
        # Additional check to ensure each octet is <= 255
        try:
            octets = ioc.split('.')
            return all(0 <= int(o) <= 255 for o in octets)
        except ValueError:
            return False
    return False

def is_valid_hash(ioc: str) -> bool:
    # Checks if the string is a valid MD5, SHA1, or SHA256 hash.
    # Regex checks for exact length of Hex-characters (a-f, 0-9).
    # MD5=32, SHA1=40, SHA256=64 chars.
    hash_pattern = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
    return bool(hash_pattern.match(ioc))

def is_valid_url(ioc: str) -> bool:
    # Checks if the string is a valid URL/domain.
    # This regex covers domains and URLs with schema (http/https)
    domain_pattern = re.compile(
        r"^(https?://)?"                # Optional protocol (http:// or https://)
        r"([a-zA-Z0-9-]+\.)+"           # Subdomain/Domain parts (abc.)
        r"[a-zA-Z]{2,}"                 # Top Level Domain (.com, .se, etc)
        r"(:[0-9]{1,5})?"               # Optional port (:8080)
        r"(/.*)?$"                      # Optional path (/foo/bar)
    )
    return bool(domain_pattern.match(ioc))

def get_ioc_type(ioc: str) -> str:
    # Returns strict IOC type or None if invalid.
    
    # 1. Cleaning: Remove whitespace
    ioc = ioc.strip()
    
    # 2. Empty check
    if not ioc:
        return None

    # 3. Type Checking
    if is_valid_ip(ioc):
        return 'IP'
    if is_valid_hash(ioc):
        return 'HASH'
    if is_valid_url(ioc):
        return 'URL'
        
    # If nothing matches, it is invalid.
    return None