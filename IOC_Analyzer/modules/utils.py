import re

def is_valid_ip(ioc: str) -> bool:
    # Kontrollerar om strängen är en giltig IPv4-adress.
    # Enkel kontroll för IPv4-adress
    ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ipv4_pattern.match(ioc):
        # Ytterligare kontroll för att se till att varje oktett är <= 255
        try:
            octets = ioc.split('.')
            return all(0 <= int(o) <= 255 for o in octets)
        except ValueError:
            return False
    return False

def is_valid_url(ioc: str) -> bool:
    # Kontrollerar om strängen är en giltig URL/domän.
    # Denna regex täcker domäner och URL:er med schema (http/https)
    domain_pattern = re.compile(r'^([a-zA-Z0-9-]+\.){1,}[a-zA-Z]{2,}$') # Endast domännamn (google.com)

    return bool(domain_pattern.match(ioc))

def get_ioc_type(ioc: str) -> str:
    # Returnerar IOC-typ ('IP', 'URL', eller 'UNKNOWN').
    if is_valid_ip(ioc):
        return 'IP'
    if is_valid_url(ioc):
        return 'URL'
    return 'UNKNOWN'