import argparse # Import för att hantera kommandoradsargument i Linux CLI.

VERSION = "0.2" 
DEVELOPER = "Daniel Hållbro (Student)"

def analyze_ioc(ioc):
    """Placeholder för analysfunktionen."""
    ioc = ioc.strip()
    if not ioc:
        return
        
    print(f"\n--- Analys startad för: {ioc} ---")
    
    # Implementera validering av IOC-format (IP eller URL)
    # Implementera API-anrop (Virustotal och AbuseIPDB) och hantering av svar
    
    print("Analysen slutförd. Resultat saknas (ej implementerat ännu).")


def main():
    # -h/--help läggs till automatiskt av argparse
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

    # Ny feature: Icke-interaktivt läge med target-flagga
    if args.target:
        print(f"Startar analys i icke-interaktivt läge för: {args.target}")
        analyze_ioc(args.target)
    else:
        # Endast om inget target skickas, går vi in i interaktivt läge
        print("Välkommen till IOC Analyzer v0.2")
    
        while True:
            ioc = input("Ange IOC (IP eller URL) att analysera, eller 'exit' för att avsluta: ")
        
            if ioc.lower() == 'exit':
                print("Avslutar programmet.")
                break
                
            analyze_ioc(ioc)
            
if __name__ == "__main__":
    main()