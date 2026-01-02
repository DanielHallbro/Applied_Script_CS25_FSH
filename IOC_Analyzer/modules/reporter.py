import os
from modules.logger import log

def generate_report(output_filename: str, report_content: str):
    # Skriver den formaterade analysrapporten till en angiven fil i append-läge.
    # Lägger till en avgränsare för tydlighet mellan analyser.
    if not output_filename:
        log("Reporter: Inget filnamn specificerat för rapport. Avbryter.", 'DEBUG')
        return

    try:
        # Använd 'a' (Append/Lägg till) för att hantera multipla analyser korrekt
        with open(output_filename, 'a', encoding='utf-8') as f: 
            
            # Lägg till en tydlig avgränsare
            f.write("\n\n" + "="*20 + f" ANALYS STARTAD: {os.path.basename(output_filename)} " + "="*20 + "\n\n")
            f.write(report_content)
            
        log(f"Reporter: Analysrapport tillagd framgångsrikt i: {output_filename}", 'DEBUG')
        print(f"\n[REPORT] Analysresultat tillagt i: {output_filename}")
        
    except Exception as e:
        log(f"Reporter: Kunde inte skriva rapport till {output_filename}. Fel: {e}", 'ERROR')
        print(f"\n[FEL] Kunde inte skriva rapport till fil: {output_filename}")