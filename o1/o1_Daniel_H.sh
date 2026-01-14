#!/bin/bash
#
#Övning 1
#
# Author: Daniel H.
# Last Update: 2025-12-08
 
echo "Välkommen till mitt RECON script för att kontrollera en Linux-miljö"
 
echo
echo "=== SYSTEMINFO ==="
uname -a
 
echo
echo "=== AKTUELL ANVÄNDARE ==="
echo $USER
 
echo
echo "=== ANVÄNDARE MED SHELL ==="
grep "sh$" /etc/passwd
 
echo
echo "=== NÄTVERK ==="
ip a | grep inet
 
echo
echo "=== VART ÄR JAG? ==="
pwd
 
echo
echo "=== VAD HÄNDER I BAKGRUNDEN? ==="
ps aux
 
echo
echo "=== VART ÄR FILEN? ==="
cd ..
touch Här_Är_Filen
echo Här är filen:
pwd
ls
cd script.sh
echo Kan du hitta hit?

