


![privesc_mindmap](privesc.png)

>full image [[privesc.png]] 
# Compact Privilege Escalation Mindmap


## Linux Enumeration
- **Auto Scripts:** LinEnum (`./LinEnum.sh`), LinPEAS (`./linpeas.sh`)
- **Manual:** `uname -a`, `env`, `find / -perm -4000 -type f 2>/dev/null`, `cat /etc/crontab`, `dpkg -l`

## Windows Enumeration
- **Auto:** WinPEAS (`winpeas.exe`)
- **Manual:** `systeminfo`, `whoami /priv`, `schtasks /query /fo LIST /v`, `wmic product get name,version`

## Kernel Exploits
- Linux: `uname -r` → searchsploit
- Windows: `systeminfo | findstr /B /C:"OS Name" /C:"OS Version"` → exploit-db

## Sudo (Linux)
- Check: `sudo -l`
- Full access: `sudo su -`
- GTFOBins for specific commands

## SUID (Linux)
- Find: `find / -perm -u=s -type f 2>/dev/null`
- Check GTFOBins for exploitation

## Windows Privileges
- Check: `whoami /priv`
- Tools: JuicyPotato, RoguePotato

## Scheduled Tasks
- Linux: `cat /etc/crontab`, `/var/spool/cron/`
- Windows: `schtasks /query /fo LIST /v`

## Credential Hunting
- Linux: `grep -ir "password" /etc/`, `~/.ssh/`, `~/.bash_history`
- Windows: Check `C:\Program Files`, `AppData`

## SSH
- Read keys: `cat /home/[user]/.ssh/id_rsa`
- Use key: `chmod 600 id_rsa; ssh -i id_rsa user@ip`

## Resources
- GTFOBins, LOLBAS, PEASS-ng Suite
- ExploitDB, CVE databases
