import argparse # Ny import för att hantera kommandoradsargument i Linux CLI.

VERSION = "1.0.0" 
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
    # NYTT: Argument Parser
    # -h/--help läggs till automatiskt av argparse
        # Fundera på att göra beskrivningen mer detaljerad
    parser = argparse.ArgumentParser(
        description="IOC Analyzer Script – Automatiserad hotanalys från VirusTotal och AbuseIPDB.\n\n"
                    "Exempel på användning:\n"
                    "  python3 main.py -v\n"
                    "  python3 main.py --help",
        formatter_class=argparse.RawTextHelpFormatter # För snyggare exempel/beskrivning
    )
    
    # Version flagga -v/--version
    parser.add_argument(
        '-v', '--version', 
        action='version', 
        version=f'%(prog)s {VERSION} av {DEVELOPER}', 
        help="Visar scriptets version och utvecklare."
    )


    print("Välkommen till IOC Analyzer (v0.1)")
    
    while True:
        ioc = input("Ange IOC (IP eller URL) att analysera, eller 'exit' för att avsluta: ")
        
        if ioc.lower() == 'exit':
            print("Avslutar programmet.")
            break
            
        analyze_ioc(ioc)

if __name__ == "__main__":
    main()