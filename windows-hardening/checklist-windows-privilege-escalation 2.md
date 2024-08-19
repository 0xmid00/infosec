# Checklist - Local Windows Privilege Escalation
***
##  Kernel Exploits

* [ ] [[windows-hardening/windows-local-privilege-escalation/README#^01782b|Kernel Exploits]] - `python wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only | less`
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

* [ ] [[windows-hardening/windows-local-privilege-escalation/README#^39c818|Searching the Registry for Passwords]] 
- `.\winPEASany.exe quiet filesinfo userinfo`
* [ ]  [[windows-hardening/windows-local-privilege-escalation/README#^a378c5|Saved Creds]] - `winPEASany.exe quiet cmd windowscreds`
* [ ] [[windows-hardening/windows-local-privilege-escalation/README#**Generic Password search in files and Configuration Files**|Generic Password search in files and Configuration Files]] 
- `.\winPEASany.exe quiet cmd searchfast filesinfo`
- `dir /s *pass* == *.config`
- `findstr /si password *.xml *.ini *.txt`
* [ ] [[windows-hardening/windows-local-privilege-escalation/README#^eea1bf|SAM & SYSTEM backups]] - `.\winPEASany.exe quiet filesinfo`
***
* [ ] [[privilege-escalation-with-autorun-binaries#^bf7821|Scheduled Tasks]] - `schtasks /query /fo LIST /v`
***
* [ ]  [[windows-hardening/windows-local-privilege-escalation/README#^2987ff| Insecure GUI Apps]] 
-`1.open shortcut or gui app.exe`
-`tasklist /V | findstr app.exe`
***
* [ ] [[privilege-escalation-with-autorun-binaries#^c48dcd|Startup Apps]] 
* `.\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"`
***
* [ ] [[windows-hardening/windows-local-privilege-escalation/README#^65e359|Exploit Installed Applications]] - `.\winPEASany.exe quiet procesinfo`
***
## Token Impersonation
###  Potatoes
* [ ] [[Hot Potato|Hot potato]] 
*` Windows 7, 8, early versions of Windows 10, win Server 2008, and Server 2012. and their server counterparts`
* [ ] [[juicypotato|Juicy Potato]] 
*  `meterpreter> whoami /priv` ->  1. be instantiable by the current user, normally a “service user” which has impersonation privileges ,`SeImpersonate` or `SeAssignPrimaryToken` privileges

