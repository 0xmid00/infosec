# Checklist - Local Windows Privilege Escalation
***
## “getsystem”  Meterpreter
`meterpreter> getsystem`
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

#### From LOCAL/NETWORK SERVICE to SYSTEM by abusing  `SeImpersonate` or `SeAssignPrimaryToken` privileges 
  `whoami /priv` ->  1. be instantiable by the current user, normally a “service user” which has impersonation privileges ,`SeImpersonate` or `SeAssignPrimaryToken` privileges
* [ ] [[juicypotato|Juicy Potato]] ` doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards.`
* [ ] [[roguepotato-and-printspoofer#^0e832b|Rogue Potato]]  `can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.`
* [ ] [[roguepotato-and-printspoofer#^c42fff|PrintSpoofer]]   `Windows 10 and Server 2016/2019..`
***
## Strategy
```text
Enumeration
1. Check your user (whoami) and groups (net user <username>)
2. Run winPEAS with fast, searchfast, and cmd options.
3. Run Seatbelt & other scripts as well!
4. If your scripts are failing and you don’t know why, you can always run the
manual commands from this course, and other Windows PrivEsc cheatsheets
online (e.g.
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Method
ology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

Strategy
Spend some time and read over the results of your
enumeration.
If WinPEAS or another tool finds something interesting, make
a note of it.
Avoid rabbit holes by creating a checklist of things you need
for the privilege escalation method to work.

Strategy
Have a quick look around for files in your user’s desktop
and other common locations (e.g. C:\ and C:\Program
Files).
Read through interesting files that you find, as they may
contain useful information that could help escalate
privileges.

Strategy
Try things that don’t have many steps first, e.g. registry
exploits, services, etc.
Have a good look at admin processes, enumerate their
versions and search for exploits.
Check for internal ports that you might be able to forward to
your attacking machine.

Strategy
If you still don’t have an admin shell, re-read your full
enumeration dumps and highlight anything that seems odd.
This might be a process or file name you aren’t familiar with
or even a username.
At this stage you can also start to think about Kernel Exploits.

Don’t Panic
Privilege Escalation is tricky.
Practice makes perfect.
Remember: in an exam setting, it might take a while to
find the method, but the exam is always intended to be
completed within a timeframe. Keep searching!
```