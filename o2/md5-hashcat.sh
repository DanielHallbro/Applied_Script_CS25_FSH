#!/bin/bash
# Enkelt script för MD5-hashcracking med hashcat
# Användning: ./md5-hashcat.sh [HASH_FILE] [MASK] 

# Kontrollera att hashcat är installerat
if ! command -v hashcat &> /dev/null; then
    echo "ERROR: hashcat är inte installerat!"
    echo "Installera med: sudo apt install hashcat"
    exit 1
fi

echo "=== Hashcat MD5 Cracker ==="
hashcat --version | head -n 1
echo "==========================="

# Standardinställningar
HASH_FILE="${1:-mina_hashar.txt}"
MASK="${2:-?d?d?d?d?d?d?d?d?d}"  			# Antalet siffror att försöka
HASH_TYPE="0"    				# 0=MD5 hash mode
ATTACK_MODE="3"  				# Använd Mask attack

echo "Startar hashcat ..."
echo "=================="

# Kör hashcat
hashcat -m "$HASH_TYPE" -a "$ATTACK_MODE" "$HASH_FILE" "$MASK" -O -w 3 --force

echo ""
echo "=================="
echo "Hashcat körning slutförd! Allt OK!"
