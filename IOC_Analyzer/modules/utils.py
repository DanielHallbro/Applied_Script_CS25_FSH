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

def is_valid_url(ioc: str) -> bool:
    # Checks if the string is a valid URL/domain.
    # This regex covers domains and URLs with schema (http/https)
    domain_pattern = re.compile(r'^([a-zA-Z0-9-]+\.){1,}[a-zA-Z]{2,}$') # Only domain names (google.com)

    return bool(domain_pattern.match(ioc))

def get_ioc_type(ioc: str) -> str:
    # Returns IOC type ('IP', 'URL', or 'UNKNOWN').
    if is_valid_ip(ioc):
        return 'IP'
    if is_valid_url(ioc):
        return 'URL'
    return 'UNKNOWN'