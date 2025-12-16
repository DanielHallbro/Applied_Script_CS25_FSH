
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
    print("Välkommen till IOC Analyzer (v0.1)")
    
    while True:
        ioc = input("Ange IOC (IP eller URL) att analysera, eller 'exit' för att avsluta: ")
        
        if ioc.lower() == 'exit':
            print("Avslutar programmet.")
            break
            
        analyze_ioc(ioc)

if __name__ == "__main__":
    main()