import json
import os
from datetime import datetime, timedelta

from modules.logger import log

CACHE_FILE = "ioc_cache.json"
CACHE_EXPIRY_DAYS = 1 # IOC:er cachas i 1 dag. Kan justeras vid behov.

def load_cache() -> dict:
    # Laddar upp befintlig cache från disk. Returnerar en tom dictionary om filen saknas/är korrupt.
    if not os.path.exists(CACHE_FILE):
        return {}
        
    try:
        with open(CACHE_FILE, 'r') as f:
            log(f"Använder cachad data från {CACHE_FILE}.", 'DEBUG')
            return json.load(f)
    except json.JSONDecodeError:
        log(f"Cache: Varning! {CACHE_FILE} är korrupt och återskapas.", 'WARNING')
        return {}
    except Exception as e:
        log(f"Cache: Ett oväntat fel uppstod vid laddning: {e}", 'ERROR')
        return {}

# Cache-data laddas och sparas globalt för prestanda
IOC_CACHE = load_cache()

def save_cache():
    # Sparar cache-data till disk.
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(IOC_CACHE, f, indent=4)
        log(f"Cache: Sparade uppdaterad data till {CACHE_FILE}.", 'DEBUG')
    except Exception as e:
        log(f"Cache: Kunde inte spara cache-filen: {e}", 'ERROR')


def check_cache(ioc: str) -> list | None:
    # Kontrollerar om en IOC finns i cachen och är giltig. Returnerar resultat om giltig.
    if ioc not in IOC_CACHE:
        log(f"Cache: Inget resultat för {ioc}.", 'DEBUG')
        return None

    entry = IOC_CACHE[ioc]
    cache_time = datetime.fromisoformat(entry['timestamp'])
    
    # Kontrollera utgångsdatum
    if datetime.now() > cache_time + timedelta(days=CACHE_EXPIRY_DAYS):
        log(f"Cache: Inget resultat för {ioc}. Resultatet har gått ut.", 'INFO')
        del IOC_CACHE[ioc] # Ta bort ogiltig post
        return None

    log(f"Cache: Resultat finns för {ioc}. Använder cachat resultat.", 'INFO')
    return entry['results']

def update_cache(ioc: str, api_results: list):
    # Sparar ett nytt API-resultat till cachen och sparar filen.
    IOC_CACHE[ioc] = {
        "timestamp": datetime.now().isoformat(),
        "results": api_results
    }
    save_cache()