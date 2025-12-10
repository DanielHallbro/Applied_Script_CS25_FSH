#!/usr/bin/env python3
# -*- -*- -*-

"""
Password and Hash Generator (Very UNsecure version)
Generates random numeric passwords and calculates their MD5 hashes.

Author: Frans Schartau
Last Update: 2025-12-08

WARNING: MD5 is considered cryptographically broken and should not be used
for security-critical applications.
"""

import random
import hashlib

def generate_random_number_string():
    """
    Generates a random string consisting only of digits.
    The length is fixed to PWD_LGT constant.
    
    Returns:
        str: A random string containing only digits (0-9) with fixed length.
        
    Example:
        '4738291650'  # Random 10-digit string
    """
    # Använder random.choice för att välja siffror (hyfasd randomisering)
    # Skapar en någorlunda enhetlig fördelning över alla möjliga 10-siffriga kombinationer
    return ''.join(random.choice("0123456789") for X in range(PWD_LGT))

def md5_hash(text):
    """
    Calculates the MD5 hash of a given string.
    
    Args:
        text (str): The input string to hash.
        
    Returns:
        str: The hexadecimal representation of the MD5 hash.
        
    Security Note:
        MD5 is cryptographically broken and vulnerable to collision attacks.
        It should not be used for password storage or security-sensitive applications.
        Consider using SHA-256 or bcrypt instead for real-world applications.
    """
    # encode() konverterar sträng till bytes, vilket krävs av hashlib
    # hexdigest() returnerar hash-värdet som en hexadecimal sträng
    return hashlib.md5(text.encode()).hexdigest()

def main():
    """
    Main function that orchestrates the password generation and hashing.
    
    Generates NO_PASS random passwords with fixed length PWD_LGT
    and displays them alongside their corresponding MD5 hashes.
    """
    # Programbeskrivning för användaren
#    print("-" * 60)
#    print("Password and MD5 Hash Generator (Very UNsecure version)")
#    print("-" * 60)
#    print(f"Skapar {NO_PASS} st randomiserade {PWD_LGT}-siffriga lösenord och deras MD5 hashes:\n")
    
    # Generera och visa lösenorden med deras hash-värden
    for i in range(NO_PASS):
        # Generera ett slumpmässigt lösenord med fast längd
        password = generate_random_number_string()
        
        # Beräkna MD5-hashen för lösenordet
        hash_value = md5_hash(password)
        
        # Formatera och visa resultatet med sekventiell numrering
        print(f"{hash_value}")
    
    # Säkerhetsvarning
#    print("\n" + "=" * 50)
#    print("⚠️ Extra Viktig säkerhetsinformation:")
#    print("-" * 50)
#    print("MD5 är inte längre säkert för kryptografiskt bruk.")
#    print("Det används här ENDAST i utbildningssyfte.")
#    print("För riktiga system bör man använda moderna algoritmer som SHA-256")
#    print("eller lösenordshashfunktioner som bcrypt eller Argon2.")
#    print("=" * 50)

# Fasta konstanter för programmet (Går att ändra på efter behov)
PWD_LGT = 9
NO_PASS = 10

# Standard Python idiom för att kontrollera om skriptet körs direkt!
if __name__ == "__main__":
    main()
