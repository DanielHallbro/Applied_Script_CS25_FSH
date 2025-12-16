import argparse # Import för att hantera kommandoradsargument i Linux CLI.
from datetime import datetime # Ny import för tidsstämpel i startloggen
import sys

# Import från den egna logger-modulen modules/logger.py
from modules.logger import setup_logger, log

VERSION = "0.3" 
DEVELOPER = "Daniel Hållbro (Student)"
LOG_FILE_PATH = "ioc_analyzer.log" # Loggfilens namn. Information om filens namn och sökväg ska in i README.


def analyze_ioc(ioc):
    """Placeholder för analysfunktionen."""
    ioc = ioc.strip()
    if not ioc:
        return
        
    log(f"--- Analys startad för: {ioc} ---", 'INFO') # Ersatt print med log
    
    # Implementera validering av IOC-format (IP eller URL)
    # Implementera API-anrop (Virustotal och AbuseIPDB) och hantering av svar
    
    log("Analysen slutförd. Resultat saknas (ej implementerat ännu).", 'INFO') # Ersatt print med log


def main():
    # Sätt upp loggern vid programmets start
    setup_logger(LOG_FILE_PATH)
    log(f"IOC Analyzer v{VERSION} startad ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})", 'INFO')

    # Argumentparser för kommandoradsargument
        # Fundera på att göra beskrivningen mer detaljerad. Lagt till -t/--target-exempel.
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
        help="-t eller --target för att specificera en IOC (IP eller URL) direkt från kommandoraden."
    )

    args = parser.parse_args()

    # Feature: Icke-interaktivt läge med target-flagga
    if args.target:
        log(f"Startar analys i icke-interaktivt läge för: {args.target}", 'INFO') # Ersatt print med log
        analyze_ioc(args.target)
    else:
        # Endast om inget target skickas, går vi in i interaktivt läge
        print("Välkommen till IOC Analyzer v0.2")
    
        while True:
            try:
                ioc = input("Ange IOC (IP eller URL) att analysera, eller 'exit' för att avsluta: ")
            
                if ioc.lower() == 'exit':
                    log("Användaren valde att avsluta.", 'INFO') # Ersatt print med log
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


    log("Scriptet avslutades kontrollerat.", 'INFO') # Ersatt print med log

if __name__ == "__main__":
    main()