# Modulen hanterar miljökontroller (pre-flight checks) innan huvudanalysen påbörjas.
import os
import sys
import socket
from modules.logger import log

def check_internet_connection():
    # Kontrollera nätverksstatus genom att försöka nå en pålitlig server.
    
    # Försöker ansluta till Googles DNS-server (8.8.8.8) på port 53 (DNS).
    # Detta testar både nätverk och DNS-upplösning.
    REMOTE_SERVER = "8.8.8.8"
    PORT = 53
    TIMEOUT = 3
    
    try:
        # Försöker skapa anslutning för att testa nätverksstatus
        s = socket.create_connection((REMOTE_SERVER, PORT), TIMEOUT)
        s.close()
        log("Miljökontroll lyckades: Internetanslutning aktiv.", 'DEBUG')
        return True
    except socket.error:
        # Fångar anslutningsfel
        log("Miljökontroll misslyckades: Ingen internetanslutning eller DNS-problem.", 'ERROR')
        # Felmeddelanden och åtgärdsförslag
        print(f"\n[FEL] Ingen internetanslutning. Scriptet kan inte nå API:erna.")
        print("  -> Åtgärd: Kontrollera din nätverksstatus.")
        return False
    except Exception as e:
        # Fångar oväntade fel i loggen
        log(f"Oväntat fel vid nätverkskontroll: {e}", 'ERROR')
        return False


def check_api_keys():
    
    # Kontrollera API-nycklar. 
    # Kräver VirusTotal som minimum, men varnar för de andra.
    
    vt_key = os.getenv('VT_API_KEY')
    abuse_key = os.getenv('ABUSE_API_KEY')
    ipinfo_key = os.getenv('IPINFO_API_KEY') # Ändrad till IPINFO 
    
    # 1. Kontrollera MINIMUMKRAVET (VirusTotal)
    if not vt_key:
        log("Miljökontroll misslyckades: MINIMUMKRAV (VT_API_KEY) saknas.", 'CRITICAL')
        print(f"\n[KRITISKT FEL] Scriptet kräver åtminstone VT_API_KEY för att kunna analysera IOC.")
        print("  -> Åtgärd: Exportera nyckeln i din terminal: export VT_API_KEY=\"DIN_NYCKEL\"")
        return False
    
    # 2. Varna om andra nycklar saknas (om scriptet ska fortsätta)
    missing_optional = []
    if not abuse_key:
        missing_optional.append('ABUSE_API_KEY')
    if not ipinfo_key: 
        missing_optional.append('IPINFO_API_KEY') # Ändrad till IPINFO

    if missing_optional:
        log(f"VARNING: Följande VALFRIA API-nycklar saknas: {', '.join(missing_optional)}.", 'WARNING')
        print(f"\n[VARNING] Analys kommer att sakna data från: {', '.join(missing_optional)}.")
        print("  -> Scriptet fortsätter. Sätt API-nycklarna för fullständig analys.")
    else:
        log("Miljökontroll lyckades: Alla nödvändiga och valfria API-nycklar finns.", 'DEBUG')

    return True

def run_pre_checks(log_file_path):
    # Huvudfunktion för miljökontroll.
    log("Startar Miljökontroller (Pre-flight checks)...", 'INFO')

    if not check_internet_connection():
        print(f"  -> Scriptet avslutas. Kontrollera loggfilen ({log_file_path}) för detaljer.")
        return False
        
    if not check_api_keys():
        # Avslutas här endast om VT_API_KEY saknas. Saknade valfria nycklar varnas bara för.
        print(f"  -> Scriptet avslutas. Kontrollera loggfilen ({log_file_path}) för detaljer.")
        return False

    log("Alla Miljökontroller slutfördes framgångsrikt.", 'INFO')
    return True