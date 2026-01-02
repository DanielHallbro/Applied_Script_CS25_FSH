import argparse # Import för att hantera kommandoradsargument i Linux CLI.
from datetime import datetime # Import för tidsstämpel i startloggen
import sys
import os # Import för miljövariabler

# Import från den egna logger-modulen modules/logger.py
from modules.logger import setup_logger, log
from modules.utils import get_ioc_type # Importerar utils för IOC-validering.
from modules.pre_checks import run_pre_checks # Importerar pre_checks för miljökontroller

# Import för API-anrop
from modules.virustotal import check_ip as check_vt_ip, check_url_or_hash as check_vt_other
from modules.abuseipdb import check_ip as check_abuse_ip
from modules.ipinfo import check_ip as check_ipinfo_ip
from modules.formatter import format_ip_analysis
from modules.formatter import format_other_analysis

VERSION = "0.5" 
DEVELOPER = "Daniel Hållbro (Student)"
LOG_FILE_PATH = "ioc_analyzer.log" # Loggfilens namn. Information om filens namn och sökväg ska in i README.


def analyze_ioc(ioc):
    # Analyserar en IOC (IP, URL/Domain) med hjälp av olika API:er.
    log(f"--- Analys startad för: {ioc} ---", 'INFO') 

    ioc_type = get_ioc_type(ioc)
    
    api_results = []

    if ioc_type == 'IP':
        log("IOC-typ: IP-adress. Använder multisource IP-analys.", 'DEBUG')
        
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
        print(formatted_output)
        log(f"Formaterad analysrapport:\n{formatted_output}", 'INFO') # Säkerställer att logga formaterad output på ett snyggt sätt.

    elif ioc_type == 'URL' or ioc_type == 'UNKNOWN':
        log(f"IOC-typ: {ioc_type}. Använder VirusTotal för analys.", 'DEBUG')
        
        vt_result = check_vt_other(ioc)
        api_results.append(vt_result)
        
        formatted_output = format_other_analysis(vt_result, ioc)
        print(formatted_output)
        log(f"Formaterad analysrapport:\n{formatted_output}", 'INFO') # Säkerställer att logga formaterad output på ett snyggt sätt.
        
    log("Analysen slutförd och presenterades.", 'INFO')

def main():
    # Sätt upp loggern vid programmets start
    setup_logger(LOG_FILE_PATH)
    log(f"IOC Analyzer v{VERSION} startad ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})", 'INFO')


    if not run_pre_checks(LOG_FILE_PATH):
        log("Miljökontroller misslyckades. Avslutar kontrollerat.", 'CRITICAL')
        sys.exit(1) # Viktigt: Avsluta scriptet kontrollerat om VT saknas!

    # Argumentparser för kommandoradsargument
        # Fundera på att göra beskrivningen mer detaljerad.
    parser = argparse.ArgumentParser(
        description="IOC Analyzer Script – Automatiserad hotanalys från VirusTotal och AbuseIPDB.\n\n"
                    "Exempel på användning:\n"
                    "  python3 main.py -v/--version\n"
                    "  python3 main.py -h/--help/\n"
                    "  python3 main.py -t/--target <IOC>\n\n",
        formatter_class=argparse.RawTextHelpFormatter # För snyggare exempel/beskrivning
    )    

    # Version flagga -v/--version
    parser.add_argument(
        '-v', '--version', 
        action='version', 
        version=f'%(prog)s {VERSION} av {DEVELOPER}', 
        help="Visar scriptets version och utvecklare."
    )

    # Target flagga -t/--target
    parser.add_argument(
        '-t', '--target', 
        type=str,
        help="-t eller --target för att specificera en IOC (IP eller URL) direkt från kommandoraden. Scriptet körs i icke-interaktivt läge."
    )

    args = parser.parse_args()

    # Feature: Icke-interaktivt läge med target-flagga
    if args.target:
        log(f"Startar analys i icke-interaktivt läge för: {args.target}", 'INFO') 
        analyze_ioc(args.target)
    else:
        # Endast om inget target skickas, går vi in i interaktivt läge
        print("Välkommen till IOC Analyzer v0.2")
    
        while True:
            try:
                ioc = input("Ange IOC (IP eller URL) att analysera, eller 'exit' för att avsluta: ")
            
                if ioc.lower() == 'exit':
                    log("Användaren valde att avsluta.", 'INFO') 
                    break
                    
                analyze_ioc(ioc)
                
            except KeyboardInterrupt:
                # Hantering av avbrott från användaren t.ex. Ctrl+C
                log("Användaren avbröt scriptet via Ctrl+C.", 'WARNING')
                print("\nAnalys avbruten av användaren. Avslutar.")
                break
            except Exception as e:
                # Hantering av oväntade fel
                log(f"Ett oväntat fel uppstod i main loop: {e}", 'CRITICAL')
                print(f"\n[KRITISKT FEL] Ett oväntat fel uppstod. Kontrollera loggfilen ({LOG_FILE_PATH}).")
                break


    log("Scriptet avslutades kontrollerat.", 'INFO') 

if __name__ == "__main__":
    main()