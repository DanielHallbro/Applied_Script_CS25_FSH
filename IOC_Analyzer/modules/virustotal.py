import os
import requests
from modules.logger import log
import base64 # Behövs för URL-kodning. Förklaras vidare i funktionen 'def _get_vt_endpoint'

VT_API_KEY = os.getenv('VT_API_KEY') # Hämta API-nyckel från miljövariabel. Går att ändra till ren inmatning av nyckel vid behov.
BASE_URL = "https://www.virustotal.com/api/v3"

def check_ip(ioc: str) -> dict:
    # Hanterar VirusTotal IP-kontroll.
    log(f"VT: Startar IP-analys för {ioc}.", 'DEBUG')
    
    # Pre flight check bör fånga detta innan.
    if not VT_API_KEY:
        log("VT: API-nyckel saknas (bör fångas av pre-checks). Avbryter anrop.", 'ERROR')
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
        
        # Riskpoäng: Rådata är antalet "malicious" rapporter.
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


def _get_vt_endpoint(ioc: str) -> tuple[str, str]:
    # Hjälpfunktion för att bestämma VT-endpoint och analys-ID.
    # Kontrollerar om det är en SHA-256 hash (64 tecken, alfanumerisk)
    if len(ioc) == 64 and ioc.isalnum():
        return f"{BASE_URL}/files/{ioc}", "hash"
    
    # För URL och okänd format använder vi URL-endpointen.
    # VT kräver att URL:en Base64-kodas (URL-safe) och rensas från utfyllnad.
    # Vi gör detta lokalt istället för att VirusTotal ska göra det.
    encoded_url = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
    return f"{BASE_URL}/urls/{encoded_url}", "url"


def check_url_or_hash(ioc: str) -> dict:
    # Hanterar VirusTotal analys för URL eller Hash.
    
    endpoint, ioc_type_friendly = _get_vt_endpoint(ioc)
    log(f"VT: Startar analys för {ioc_type_friendly} ({ioc}).", 'DEBUG')

    # Pre flight check bör fånga detta innan.
    if not VT_API_KEY:
        log("VT: API-nyckel saknas (bör fångas av pre-checks). Avbryter anrop.", 'ERROR')
        return {"source": "VirusTotal (Other)", "status": "Error", "data": "API Key Missing"}

    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json"
    }

    try:
        response = requests.get(endpoint, headers=headers, timeout=10)
        
        if response.status_code == 404:
            log(f"VT: Hittade ingen rapport för {ioc}.", 'INFO')
            return {"source": "VirusTotal (Other)", "status": "Not Found", "ioc_type": ioc_type_friendly, "data": None}
            
        response.raise_for_status() 

        # Hämtar relevant information
        data = response.json().get('data', {})
        attributes = data.get('attributes', {})
        
        # Riskpoäng: Rådata är antalet "malicious" rapporter.
        analysis_stats = attributes.get('last_analysis_stats', {})
        malicious = analysis_stats.get('malicious', 0)
        
        log(f"VT: Lyckades hämta data. Malicious count: {malicious}", 'DEBUG')

        return {
            "source": "VirusTotal (Other)",
            "status": "Success",
            "raw_score": malicious,
            "ioc_type": ioc_type_friendly,
            "data": attributes
        }
    
    except requests.exceptions.HTTPError as e:
        log(f"VT: HTTP-fel {e.response.status_code} vid anrop.", 'ERROR')
        return {"source": "VirusTotal (Other)", "status": f"HTTP Error {e.response.status_code}", "data": None}
    except requests.exceptions.RequestException as e:
        log(f"VT: Anslutningsfel: {e}", 'ERROR')
        return {"source": "VirusTotal (Other)", "status": "Connection Error", "data": None}