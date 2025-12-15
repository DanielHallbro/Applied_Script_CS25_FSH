#!/usr/bin/env python3
import platform     # importera plattform modul för att identifiera operativsystem
import os           # importera os modul för filhantering
import time		    # import av lämplig python modul

system = platform.system()
if system == "Windows":
    # Fortsätt med Windows-specifik kod
    print("Windows upptäckt. Scriptet fortsätter..")
elif system == "Linux":
    print("Linux upptäckt. Detta script är avsett för Windows.")
    exit()
elif system == "Darwin":
    print("macOS upptäckt. Detta script är avsett för Windows.")
    exit()
else:
    print(f"Okänt operativsystem ({system}). Detta script är avsett för Windows. Avbryter körning.")
    exit()
print()
print("==================================================================")
print()

# EICAR testfil innehåll
eicar_str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

#Skapa testfil på skrivbordet
desktop_path = os.path.join(os.environ["USERPROFILE"], "OneDrive", "Desktop")
file_path = os.path.join(desktop_path, "AV-TEST-NOT-DANGEROUS.txt")
with open(file_path, "w") as f:
    f.write(eicar_str)
print("[---]OS version:", system)
print()
print("==================================================================")
print()
print("[+++] Testfil skapad på skrivbordet:"+ file_path)
print()
print("==================================================================")
print()
print("[...] Väntar på AV/EDR att skanna filen...")
print()
print("==================================================================")
print()
print()
time.sleep(3)   	# Väntar några sekunder på AV/EDR respons

# Kontrollera om innehållet matchar EICAR-signaturen
try:
    with open(file_path, "r") as f:
        fil_innehåll = f.read()
    if fil_innehåll == eicar_str:
        print("[!!!] Filen är fortfarande intakt och kunde läsas!")
        print("[!!!] Din AV/EDR-lösning har inte upptäckt den kända virus-signaturen.")
    else:
        print("[---] Din AV/EDR-lösning har upptäckt och hanterat den kända virus-signaturen.")

except Exception as e:
    # Om ett fel uppstår här pga att filen har tagits bort eller flyttats
    print("[!!!] Filen kunde inte läsas!")
    print()
    print("[!!!] AV har tagit bort/karantänat filen.")
    print()
    print("[---] Din AV/EDR-lösning är helt fungerande och skyddar mot kända virus-signaturer.")
    print()