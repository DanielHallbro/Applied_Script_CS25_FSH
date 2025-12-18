# modules/ipinfo.py
import os
import requests
from modules.logger import log

IPINFO_API_KEY = os.getenv('IPINFO_API_KEY')
BASE_URL = "https://ipinfo.io"

def check_ip(ip_address: str) -> dict:
    """Hantera IPinfo.io Geolocation/ASN kontroll."""
    log(f"IPinfo: Startar Geo/ASN-analys för {ip_address}.", 'DEBUG')
    
    if not IPINFO_API_KEY:
        log("IPinfo: API-nyckel saknas (valfri). Hoppar över anrop.", 'WARNING')
        return {"source": "IPinfo", "status": "Skipped", "data": "API Key Missing"}

    url = f"{BASE_URL}/{ip_address}/json"
    params = {"token": IPINFO_API_KEY}

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()

        data = response.json()
        
        # IPinfo används för geolocation/ASN, så råpoängen sätts till 0.
        raw_score = 0 
        
        log(f"IPinfo: Lyckades hämta data (Geo/ASN). Land: {data.get('country')}", 'DEBUG')
        
        return {
            "source": "IPinfo",
            "status": "Success",
            "raw_score": raw_score, 
            "data": data # Hela Geodatan. Kanske plockar ut specifika fält senare.
        }
    
    except requests.exceptions.HTTPError as e:
        log(f"IPinfo: HTTP-fel {e.response.status_code} vid anrop för {ip_address}.", 'ERROR')
        return {"source": "IPinfo", "status": f"HTTP Error {e.response.status_code}", "data": None}
    except requests.exceptions.RequestException as e:
        log(f"IPinfo: Anslutningsfel: {e}", 'ERROR')
        return {"source": "IPinfo", "status": "Connection Error", "data": None}