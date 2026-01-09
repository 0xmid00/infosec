## 1-Introduction to Linux Privilege Escalation
Root is the highest-privileged Linux account. During an assessment, you often gain a low-privileged shell and must escalate to root to fully compromise the system, access sensitive files, capture traffic, move laterally, or extract NTLM hashes if the host is domain-joined.

### Enumeration
Key step for privesc; identifies misconfigurations, vulnerable software, weak permissions, credentials, and attack paths—tools like LinEnum help, but manual enumeration is essential.
#### Operating System & Kernel
Identify the distribution and kernel version to find compatible tools and known public exploits; kernel exploits are risky and may crash production systems.
#### Running Services & Processes
Focus on services running as root, especially misconfigured or outdated ones (Nagios, Exim, Samba, ProFTPd). Vulnerable services often lead directly to privesc.  
`ps aux | grep root` , `ps au`
#### Installed Packages
Outdated packages may contain known privilege escalation vulnerabilities (e.g., screen 4.05.00).

#### Logged-In Users
Identify active users and their activity for possible lateral movement or credential reuse.
```bash
last 
```
#### User Home Directories
Check accessible home folders for config files, scripts, credentials, SSH keys, and readable `.bash_history`.  
`ls /home` , `ls -la /home/user`
#### SSH Keys
Private keys can grant stable access or lateral movement to other hosts.  
`ls -l ~/.ssh`
#### Bash History
History often leaks passwords, SSH commands, scripts, cron usage, and infrastructure details.  
`history` , `cat ~/.bash_history`
#### Sudo Privileges
Check allowed sudo commands and look for `NOPASSWD`. Some binaries can be abused to spawn a root shell.  
`sudo -l`
#### Configuration Files
Search `.conf` and `.config` files for usernames, passwords, API keys, and secrets.
#### Shadow File
if `/etc/shadow` is readable, extract hashes and crack them offline.
#### Password Hashes in /etc/passwd
Rare but dangerous; hashes here are world-readable and crackable offline.  
`cat /etc/passwd`
#### Cron Jobs
Cron jobs often run as root. Writable scripts, weak permissions, or relative paths can lead to privilege escalation.  
`ls -la /etc/cron.daily/`
#### File Systems & Additional Drives
Unmounted partitions or backup disks may contain credentials or sensitive files.  
`lsblk`
#### SUID / SGID Binaries
Allow execution as root; some binaries can be abused for shell access.  
`find / -perm -4000 -type f 2>/dev/null`
#### Writable Directories
Useful for dropping tools or abusing cron jobs.  
`find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null`
#### Writable Files
Dangerous if owned or executed by root (especially cron scripts).  
`find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null`
