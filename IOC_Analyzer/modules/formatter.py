import json

def format_ip_analysis(results: list, ioc: str):
    # Formaterar och presenterar rådata vid IP-sökning från VT, AbuseIPDB och IPinfo.
    # Utför ingen aggregering av riskpoäng.

    output = f"\n--- ANALYSRESULTAT FÖR {ioc} ---\n"
    # Använder next() för att hitta resultatet baserat på källan
    vt_data = next((r for r in results if r['source'] == 'VirusTotal'), None)
    abuse_data = next((r for r in results if r['source'] == 'AbuseIPDB'), None)
    ipinfo_data = next((r for r in results if r['source'] == 'IPinfo'), None)

    # --- 1. VirusTotal Resultat ---
    output += "\n### 🦠 VirusTotal (Hotrykte)\n"
    if vt_data and vt_data['status'] == 'Success':
        # Vi extraherar nyckeldata direkt från VT
        stats = vt_data['data'].get('last_analysis_stats', {})
        total_engines = sum(stats.values()) # Totala antal motorer (Rough estimate)
        malicious = stats.get('malicious', 0)
        
        output += f"  > Malicious Detektioner: {malicious} av {total_engines}\n"
        output += f"  > Hotfullt Rykte: {'Ja' if malicious > 0 else 'Nej'}\n"
        output += f"  > Rapport: https://www.virustotal.com/gui/ip-address/{ioc}\n"
    else:
        output += f"  > Status: {vt_data['status'] if vt_data else 'Misslyckades'}\n"


    # --- 2. AbuseIPDB Resultat ---
    output += "\n### 🛡️ AbuseIPDB (Community Malicious Score)\n"
    if abuse_data and abuse_data['status'] == 'Success':
        # Vi extraherar Abuse Confidence Score
        score = abuse_data['data'].get('abuseConfidenceScore', 'N/A')
        reports = abuse_data['data'].get('totalReports', 'N/A')

        output += f"  > Community Malicious Score: {score}% (Skala 0-100)\n"
        output += f"  > Totala Rapporter: {reports}\n"
        output += f"  > Senaste Rapport: {abuse_data['data'].get('lastReportedAt', 'N/A')}\n"
    elif abuse_data and abuse_data['status'] == 'Skipped':
        output += "  > **VARNING:** Skippades. API-nyckel (ABUSE_API_KEY) saknas.\n"
    else:
        output += f"  > Status: {abuse_data['status'] if abuse_data else 'Misslyckades'}\n"

    # --- 3. IPinfo.io Resultat (Kontextuell Data) ---
    output += "\n### 📍 IPinfo.io (Geolokalisering & Nätverk)\n"
    if ipinfo_data and ipinfo_data['status'] == 'Success':
        data = ipinfo_data['data']
        output += f"  > Land: {data.get('country_name', data.get('country', 'N/A'))} ({data.get('country')})\n"
        output += f"  > Stad/Region: {data.get('city', 'N/A')}, {data.get('region', 'N/A')}\n"
        output += f"  > Organisation (ASN): {data.get('org', 'N/A')}\n"
        output += f"  > Hostnamn: {data.get('hostname', 'N/A')}\n"
    elif ipinfo_data and ipinfo_data['status'] == 'Skipped':
        output += "  > **VARNING:** Skippades. API-nyckel (IPINFO_API_KEY) saknas.\n"
    else:
        output += f"  > Status: {ipinfo_data['status'] if ipinfo_data else 'Misslyckades'}\n"

    output += "\n--- ANALYS SLUTFÖRD ---\n"
    return output

def format_other_analysis(result: dict, ioc: str) -> str:
    # Formaterar och presenterar analys för URL och Hash (endast VT).
    output = f"\n--- ANALYSRESULTAT FÖR {ioc} ---\n"
    
    vt_data = result # Borde vara det enda resultatet
    ioc_type = vt_data.get('ioc_type', 'N/A')
    
    output += f"\n### 🦠 VirusTotal ({ioc_type.upper()} Analys)\n"
    
    if vt_data['status'] == 'Success':
        stats = vt_data['data'].get('last_analysis_stats', {})
        total_engines = sum(stats.values())
        malicious = stats.get('malicious', 0)
        
        output += f"  > IOC Typ: **{ioc_type.upper()}**\n"
        output += f"  > Malicious Detektioner: **{malicious} av {total_engines}**\n"
        output += f"  > Hotfullt Rykte: {'Ja' if malicious > 0 else 'Nej'}\n"
        
        # Sätter rätt rapport-URL beroende på typ
        if ioc_type == 'hash':
            output += f"  > Rapport: https://www.virustotal.com/gui/file/{ioc}\n"
        else:
            # För URL, byt bort protokoll för säkrare länk.
            output_ioc = ioc.replace('http://', '').replace('https://', '')
            output += f"  > Rapport: https://www.virustotal.com/gui/{ioc_type}/{output_ioc}\n"
        
    elif vt_data['status'] == 'Not Found':
         output += f"  > **Resultat:** Inga rapporter hittades för denna {ioc_type}.\n"
         
    else:
        output += f"  > Status: {vt_data['status']}\n"
        
    output += "\n--- ANALYS SLUTFÖRD ---\n"
    return output