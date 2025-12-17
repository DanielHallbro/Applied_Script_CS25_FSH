import os
import requests
from modules.logger import log

ABUSE_API_KEY = os.getenv('ABUSE_API_KEY') # Hämta API-nyckel från miljövariabel. Går att ändra till ren inmatning av nyckel vid behov.
BASE_URL = "https://api.abuseipdb.com/api/v2/check"

def check_ip(ip_address: str) -> dict:
    # Hantera AbuseIPDB IP-kontroll.
    log(f"AbuseIPDB: Startar IP-analys för {ip_address}.", 'DEBUG')
    
    if not ABUSE_API_KEY:
        log("AbuseIPDB: API-nyckel saknas (valfri). Hoppar över anrop.", 'WARNING')
        return {"source": "AbuseIPDB", "status": "Skipped", "data": "API Key Missing"}

    url = f"{BASE_URL}?ipAddress={ip_address}&maxAgeInDays=90&verbose"
    headers = {
        "Accept": "application/json",
        "Key": ABUSE_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        data = response.json().get('data', {})
        
        # Hämtar Abuse Score (skala 0-100)
        abuse_score = data.get('abuseConfidenceScore', 0)
        
        log(f"AbuseIPDB: Lyckades hämta data. Abuse Score: {abuse_score}", 'DEBUG')
        
        return {
            "source": "AbuseIPDB",
            "status": "Success",
            "raw_score": abuse_score, # Rådata (0-100)
            "data": data
        }
    
    except requests.exceptions.HTTPError as e:
        log(f"AbuseIPDB: HTTP-fel {e.response.status_code} vid anrop för {ip_address}.", 'ERROR')
        return {"source": "AbuseIPDB", "status": f"HTTP Error {e.response.status_code}", "data": None}
    except requests.exceptions.RequestException as e:
        log(f"AbuseIPDB: Anslutningsfel: {e}", 'ERROR')
        return {"source": "AbuseIPDB", "status": "Connection Error", "data": None}