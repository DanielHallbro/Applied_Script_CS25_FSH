Välkommen till mitt script!

Syftet med detta script är att testa AV/EDR-funktioner i Windows OS genom att skapa, skriva och läsa en känd malware fil med ett Python script.

Scriptet kontrollerar att det körs på Windows OS.
Scriptet skapar en fil och lägger in en, för Windows Defender, känd virus signatur.
Scriptet ger sedan Windows Defender lite tid att identifiera och åtgärda hotet, sen försöker den öppna filen.
Om allt gått bra så har Windows Defender redan tagit bort filen och scriptet misslyckas med att öppna den. 
