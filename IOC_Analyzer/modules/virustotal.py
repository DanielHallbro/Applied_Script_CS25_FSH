import os
import requests
from modules.logger import log

VT_API_KEY = os.getenv('VT_API_KEY') # Hämta API-nyckel från miljövariabel. Går att ändra till ren inmatning av nyckel vid behov.
BASE_URL = "https://www.virustotal.com/api/v3"

def check_ip(ioc: str) -> dict:
    # Hanterar VirusTotal IP-kontroll.
    log(f"VT: Startar IP-analys för {ioc}.", 'DEBUG')
    
    # Pre-flight check (VG-krav)
    if not VT_API_KEY:
        log("VT: API-nyckel saknas (borde ha fångats av pre-checks). Avbryter anrop.", 'ERROR')
        return {"source": "VirusTotal", "status": "Error", "data": "API Key Missing"}

    url = f"{BASE_URL}/ip_addresses/{ioc}"
    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status() # Kastar undantag för 4xx/5xx svar

        data = response.json().get('data', {})
        attributes = data.get('attributes', {})
        
        # Hämtar relevant information
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        malicious = last_analysis_stats.get('malicious', 0)
        
        # Riskpoäng: Rådata är antalet "malicious" detektionsmotorer.
        raw_score = malicious
        
        log(f"VirusTotal: Lyckades hämta data för {ioc}. Malicious count: {raw_score}", 'DEBUG') # ändra till 'INFO'? Fundera på detta.

        return {
            "source": "VirusTotal",
            "status": "Success",
            "raw_score": raw_score, 
            "data": attributes
        }
    
    except requests.exceptions.HTTPError as e:
        log(f"VT: HTTP-fel {e.response.status_code} vid anrop för {ioc}.", 'ERROR')
        return {"source": "VirusTotal", "status": f"HTTP Error {e.response.status_code}", "data": None}
    except requests.exceptions.RequestException as e:
        log(f"VT: Anslutningsfel: {e}", 'ERROR')
        return {"source": "VirusTotal", "status": "Connection Error", "data": None}


# Implementerar senare för URL/Hash.
def check_url_or_hash(ioc: str) -> dict:
    """Skelett: Hanterar URL/Hash-kontroll."""
    return {"source": "VirusTotal", "status": "Not Implemented"}