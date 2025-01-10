


![privesc_mindmap](privesc.png)

>full image [[privesc.png]] 
Here's a compact privilege escalation mindmap separated into Linux and Windows sections:

---

## ** Privilege Escalation Mindmap**
### linux
- **Enumeration**
  - **Auto Scripts**
    - LinEnum (`./LinEnum.sh`)
    - LinPEAS (`./linpeas.sh`)
  - **Manual Commands**
    - `uname -a`
    - `env`
    - `find / -perm -4000 -type f 2>/dev/null`
    - `cat /etc/crontab`
    - `dpkg -l`

- **Kernel Exploits**
  - Use `uname -r` to find kernel version
  - Search for exploits using `searchsploit`

- **Sudo**
  - Check permissions with `sudo -l`
  - Full access: `sudo su -`
  - Use GTFOBins for specific command exploitation

- **SUID**
  - Find SUID files: `find / -perm -u=s -type f 2>/dev/null`
  - Check GTFOBins for exploitation techniques

- **Scheduled Tasks**
  - Check crontab: `cat /etc/crontab`, `/var/spool/cron/`

- **Credential Hunting**
  - Search for passwords: `grep -ir "password" /etc/`, `~/.ssh/`, `~/.bash_history`

- **SSH**
  - Read keys: `cat /home/[user]/.ssh/id_rsa`
  - Use key: `chmod 600 id_rsa; ssh -i id_rsa user@ip`

- **Resources**
  - GTFOBins
  - PEASS-ng Suite
  - ExploitDB, CVE databases


### Windows

- **Enumeration**
  - **Auto Scripts**
    - WinPEAS (`winpeas.exe`)
  - **Manual Commands**
    - `systeminfo`
    - `whoami /priv`
    - `schtasks /query /fo LIST /v`
    - `wmic product get name,version`

- **Kernel Exploits**
  - Use `systeminfo | findstr /B /C:"OS Name" /C:"OS Version"`
  - Search for exploits on exploit-db

- **Windows Privileges**
  - Check privileges: `whoami /priv`
  - Tools: JuicyPotato, RoguePotato

- **Scheduled Tasks**
  - Check tasks: `schtasks /query /fo LIST /v`

- **Credential Hunting**
  - Check directories: `C:\Program Files`, `AppData`

- **Resources**
  - LOLBAS
  - PEASS-ng Suite
  - ExploitDB, CVE databases
