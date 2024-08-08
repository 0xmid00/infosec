# Checklist - Local Windows Privilege Escalation
***
##  Kernel Exploits

* [ ] [[windows-hardening/windows-local-privilege-escalation/README#^01782b|Kernel Exploits]] - `python wes.py systeminfo.txt -i 'Elevation
of Privilege' --exploits-only | le`
***
## Services
 -  `.\winPEASany.exe quiet servicesinfo`
   
* [ ] [[windows-hardening/windows-local-privilege-escalation/README#^f3a293|Insecure Service Properties]] 
* [ ] [[windows-hardening/windows-local-privilege-escalation/README#^184214|Unquoted Service Path]] 
* [ ] [[windows-hardening/windows-local-privilege-escalation/README#^bcb515|Services registry modify permissions]]
* [ ] [[windows-hardening/windows-local-privilege-escalation/README#^e9c31e| Services binaries weak permissions]]
* [ ] [[windows-hardening/windows-local-privilege-escalation/README#^daff90|PATH DLL Hijacking]]
***
## Registry

* [ ] [[windows-hardening/windows-local-privilege-escalation/README#^9c74f8|Run at startup]] - `.\winPEASany.exe quiet applicationsinfo`
* [ ] [[windows-hardening/windows-local-privilege-escalation/README#^ccc4be|AlwaysInstallElevated]] - `.\winPEASany.exe quiet windowscreds`
***

## Passwords

* [ ] [[windows-hardening/windows-local-privilege-escalation/README#^39c818|Searching the Registry for Passwords]]                                                                                                                                      - `.\winPEASany.exe quiet filesinfo userinfo`
* [ ]  [[windows-hardening/windows-local-privilege-escalation/README#^a378c5|Saved Creds]] - `winPEASany.exe quiet cmd windowscreds`