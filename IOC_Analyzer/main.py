import argparse # Import för att hantera kommandoradsargument i Linux CLI.
from datetime import datetime # Import för tidsstämpel i startloggen.
import sys
import os # Import för miljövariabler.
from dotenv import load_dotenv # Import för att ladda .env-filen med API-nycklar.
load_dotenv() # Laddar API-nycklar från .env-filen.

# Import för logger, utils, pre_checks
from modules.logger import setup_logger, log
from modules.utils import get_ioc_type # Importerar utils för IOC-validering.
from modules.pre_checks import run_pre_checks # Importerar pre_checks för miljökontroller

# Import för API-anrop/cache/formatter/reporter
from modules.virustotal import check_ip as check_vt_ip, check_url_or_hash as check_vt_other
from modules.abuseipdb import check_ip as check_abuse_ip
from modules.ipinfo import check_ip as check_ipinfo_ip
from modules.formatter import format_ip_analysis, format_other_analysis
from modules.cache import check_cache, update_cache, save_cache # Importerar cache-modulen (FB1).
from modules.reporter import generate_report # Importerar reporter-modulen (FB2).

VERSION = "0.6" 
DEVELOPER = "Daniel Hållbro (Student)"
LOG_FILE_PATH = "ioc_analyzer.log" # Loggfilens namn. Information om filens namn och sökväg ska in i README.


def analyze_ioc(ioc,report_filename=None):
    # Analyserar en IOC (IP, URL/Domain) med hjälp av olika API:er.
    log(f"--- Analys startad för: {ioc} ---", 'DEBUG') 

    cached_data = check_cache(ioc)
    if cached_data:
        log(f"Använder cachad data för presentation.", 'DEBUG')
        
        # Bestäm om det är IP eller URL/Hash-presentation
        ioc_type = get_ioc_type(ioc)
        
        if ioc_type == 'IP':
            formatted_output = format_ip_analysis(cached_data, ioc)
        else:
            # För URL/Hash, hämtar vi det första (och enda) resultatet i listan
            formatted_output = format_other_analysis(cached_data[0], ioc)
        if report_filename:
            generate_report(report_filename, formatted_output)
        else:
            print(formatted_output)

        log(f"Formaterad analysrapport (från cache):\n{formatted_output}", 'DEBUG')
        log("Analysen slutförd och presenterades (CACHAT).", 'INFO')
        return # Avsluta funktionen om cachat resultat finns
        
    ioc_type = get_ioc_type(ioc)
    api_results = []

    if ioc_type == 'IP':
        log("IOC-typ: IP-adress. Inget cachat resultat. Använder multisource IP-analys.", 'DEBUG')
        
        # Anrop till alla tre API:er för IP-analys
        vt_result = check_vt_ip(ioc)
        abuse_result = check_abuse_ip(ioc)
        ipinfo_result = check_ipinfo_ip(ioc)

        # Samla in alla resultat
        api_results.append(vt_result)
        api_results.append(abuse_result)
        api_results.append(ipinfo_result)
        
        # Använd formatter för att skriva ut snyggt
        formatted_output = format_ip_analysis(api_results, ioc)
        if report_filename:
            generate_report(report_filename, formatted_output)
        else:
            print(formatted_output)

        update_cache(ioc, api_results) # Sparar det insamlade resultatet
        log(f"Sparade analysresultat för {ioc} till cachen.", 'DEBUG')

        log(f"Formaterad analysrapport:\n{formatted_output}", 'DEBUG') # Säkerställer att logga formaterad output på ett snyggt sätt.

    elif ioc_type == 'URL' or ioc_type == 'UNKNOWN':
        log(f"IOC-typ: {ioc_type}. Inget cachat resultat. Använder VirusTotal för analys.", 'DEBUG')
        
        vt_result = check_vt_other(ioc)
        api_results.append(vt_result)
        
        formatted_output = format_other_analysis(vt_result, ioc)
        if report_filename:
            generate_report(report_filename, formatted_output)
        else:
            print(formatted_output)


        update_cache(ioc, api_results) # Sparar det insamlade resultatet
        log(f"Sparade analysresultat för {ioc} till cachen.", 'DEBUG')

        log(f"Formaterad analysrapport:\n{formatted_output}", 'DEBUG') # Säkerställer att logga formaterad output på ett snyggt sätt.
        
    log("Analysen slutförd och presenterades.", 'DEBUG')

def main():
    # Sätt upp loggern vid programmets start
    setup_logger(LOG_FILE_PATH)
    log(f"IOC Analyzer v{VERSION} startad ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})", 'DEBUG')


    if not run_pre_checks(LOG_FILE_PATH):
        log("Miljökontroller misslyckades. Avslutar kontrollerat.", 'CRITICAL')
        sys.exit(1) # Viktigt: Avsluta scriptet kontrollerat om VT saknas!

    # Argumentparser för kommandoradsargument
    # Fundera på att göra beskrivningen mer detaljerad.
    parser = argparse.ArgumentParser(
        description="IOC Analyzer Script – Automatiserad hotanalys från VirusTotal och AbuseIPDB samt Geolocation/ASN från IPinfo.io.\n\n"
                    "Exempel på användning:\n"
                    "  python3 main.py -v/--version\n"
                    "  python3 main.py -h/--help/\n"
                    "  python3 main.py -t/--target <IOC>\n"
                    "  python3 main.py -r/--report <FILNAMN>\n"
                    "  python3 main.py -t <IOC> -r <FILNAMN>\n\n",
        formatter_class=argparse.RawTextHelpFormatter # För snyggare exempel/beskrivning
    )    

    # Version flagga -v/--version
    parser.add_argument(
        '-v', '--version', 
        action='version', 
        version=f'%(prog)s v{VERSION} av {DEVELOPER}', 
        help="Visar scriptets version och utvecklare."
    )

    # Target flagga -t/--target
    parser.add_argument(
        '-t', '--target', 
        type=str,
        help="-t eller --target för att specificera en IOC (IP eller URL) direkt från kommandoraden. Scriptet körs i icke-interaktivt läge."
    )

    # Rapport flagga -r/--report
    parser.add_argument(
        '-r', '--report',
        type=str,
        help="-r eller --report för att specificera en fil att skriva analysrapporten till (exempelvis rapport.txt)."
    )

    args = parser.parse_args()

    # Icke-interaktivt läge med target-flagga
    if args.target:
        log(f"Startar analys i icke-interaktivt läge för: {args.target}", 'INFO') 
        analyze_ioc(args.target, args.report)
    else:
        # Endast om inget target skickas, går vi in i interaktivt läge
        print("Välkommen till IOC Analyzer v" + VERSION)
    
        while True:
            try:
                ioc = input("Ange IOC (IP eller URL) att analysera, eller 'exit' för att avsluta: ")
            
                if ioc.lower() == 'exit':
                    log("Användaren valde att avsluta.", 'DEBUG') 
                    break
                    
                analyze_ioc(ioc, args.report)
                
            except KeyboardInterrupt:
                # Hantering av avbrott från användaren t.ex. Ctrl+C
                log("Användaren avbröt scriptet via Ctrl+C.", 'DEBUG')
                print("\nAnalys avbruten av användaren. Avslutar.")
                break
            except Exception as e:
                # Hantering av oväntade fel
                log(f"Ett oväntat fel uppstod i main loop: {e}", 'CRITICAL')
                print(f"\n[KRITISKT FEL] Ett oväntat fel uppstod. Kontrollera loggfilen ({LOG_FILE_PATH}).")
                break


    log("Scriptet avslutades kontrollerat.", 'DEBUG') 

    save_cache() # Sparar cachen vid programmets avslutning (FB1).
if __name__ == "__main__":
    main()