## 1- Environment Enumeration
Short checklist of what to collect first after a shell: OS, kernel, PATH, running services, users/groups, mounts, network, hidden files, temp.
#### Gaining Situational Awareness
**Quick checks:** Collect identity, privileges, host, network and sudo rights.
```bash
whoami
id
hostname
ifconfig
sudo -l
```
##### OS & Kernel
- Identify distro and kernel to find public exploits or EOL status.,  **version matters**
```bash
cat /etc/os-release
  # NAME="Ubuntu" VERSION="20.04.4 LTS"
```
```bash
uname -a
  # Linux host 5.4.0-122-generic ...
```

##### PATH & Environment
- **PATH risks (binary hijack)**, and  Look for writable dirs earlier in PATH and suspicious env vars.  
```bash
echo $PATH
  # /usr/local/sbin:...:/usr/bin:/bin
```
`env` for misconfigured paths or leaked secrets.
```bash
env
  # SHELL=/bin/bash HOME=/home/user ...
```
##### System Info (CPU / Shells)
- Check CPU 
```bash
lscpu
  # AMD EPYC ... CPU(s): 2
```
and available shells to spot unusual shells (tmux/screen) 
```bash
cat /etc/shells
  # /bin/bash /usr/bin/tmux /usr/bin/screen ...
```

##### Check the Defens
check  if any defenses and  enumerate any information about them. Some things to look for include:

- [Exec Shield](https://en.wikipedia.org/wiki/Exec_Shield)
- [iptables](https://linux.die.net/man/8/iptables)
- [AppArmor](https://apparmor.net/)
- [SELinux](https://www.redhat.com/en/topics/linux/what-is-selinux)
- [Fail2ban](https://github.com/fail2ban/fail2ban)
- [Snort](https://www.snort.org/faq/what-is-snort)
- [Uncomplicated Firewall (ufw)](https://wiki.ubuntu.com/UncomplicatedFirewall)

Often we will not have the privileges to enumerate the configurations of these protections but knowing what, if any, are in place, can help us not to waste time on certain tasks.

##### Disks & drives
- Enumerate block devices  
- If we discover and can mount an additional drive or unmounted file system, we may find sensitive files, passwords, or backups that can be leveraged to escalate privileges.
```bash
lsblk
  # sda sda1 sda2 ...
```

The command `lpstat` can be used to find information about any printers attached to the system. If there are active or queued print jobs can we gain access to some sort of sensitive information?

enum **fstab** for credentials/backups.
```bash
cat /etc/fstab
  # mount entries (check for credentials)
```
##### Network & Routing
- Check routing table, ARP 
- **pivot targets**
```bash
route -n

netstat -rn # same 
```

enum the  DNS to discover internal networks and AD DNS.
```bash
cat /etc/resolv.conf
```

arp table to see what other hosts the target has been communicating with.
```bash
arp -a
```
#### Users 
- Enumerate `/etc/passwd`, identify UIDs
- Look for users with  password hashes in passwd.  
- login shells outdated versions, such as Bash version 4.1, are vulnerable to a `shellshock` exploit.
```bash
cat /etc/passwd
  # username:x:UID:GID:info:home:shell
```
**Linux hash algorithms:**

| **Algorithm** | **Hash**       |
| ------------- | -------------- |
| Salted MD5    | `$1$`...       |
| SHA-256       | `$5$`...       |
| SHA-512       | `$6$`...       |
| BCrypt        | `$2a$`...      |
| Scrypt        | `$7$`...       |
| Argon2        | `$argon2i$`... |

- Check `/home` users for sensitive data.  
- Review `.bash_history`, config files, and SSH keys (privesc, persistence, pivoting).  
- Match SSH keys with ARP hosts.
```bash
ls -la /home/<USER>
  # user home directories
```

#### Groups 
- Check `/etc/group` to find privileged groups (sudo, docker, etc.).
```bash
cat /etc/group
  # group_name:x:GID:user1,user2,...
```
- to list members of any interesting groups.
```bash
getent group sudo
  # sudo:x:27:mrb3n
```



#### Creds Discovery
- Find configs, env files, SSH keys, backups,common credential files
```bash
find / -type f \( -name "*.conf" -o -name "*.config" -o -name ".env" -o -name "id_rsa*" -o -name "*.bak" \) 2>/dev/null
  # possible creds
```

- Grep common keywords in  files Contents .
```bash
grep -R -iE "password|passwd|secret|key" / 2>/dev/null | head
  # possible secrets
  
grep -r -l 'search-query-here' /path/to/search
```

If we've gathered any passwords we should try them at this time for all users present on the system. **Password re-use** is common so we might get lucky!
  
#### Mounted File Systems
- we may find sensitive information, documentation, or applications there.
```bash
df -h
  # /dev/sda5 20G 7.9G 11G /
```

#### Unmounted File Systems 

- we we get the `root` user, we could mount and read these file systems ourselves
- **unmounted data may contain important files and must not be mounted and viewed by a standard user. **  
```bash
cat /etc/fstab | grep -v "#" | column -t
  # UUID=... / ext4 ...
```
#### Hidden Files
- Find dotfiles in home dirs (`.bash_history`, `.ssh`, `.notes`) for creds/keys.
```bash
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep <USER>
```
#### Hidden Directories
- Enumerate hidden dirs (`.ssh`, `.gnupg`, project dirs) and check permissions. we may find  **private repos / keys**  
```bash
find / -type d -name ".*" -ls 2>/dev/null
```
#### Temporary Files 
Temp paths often leak data. leftover scripts, creds 
`/tmp` cleared on reboot
`/var/tmp` persists longer
```bash
ls -l /tmp /var/tmp /dev/shm
```



---


## 2- Linux Services & Internals Enumeration
After enumerating the environment and user/group permissions, we move deeper into the host OS internals.  
This phase focuses on system-level enumeration that will guide and enable later attack techniques.

- What services and applications are installed?
- What services are running?
- What sockets are in use?
- What users, admins, and groups exist on the system?
- Who is current logged in? What users recently logged in?
- What password policies, if any, are enforced on the host?
- Is the host joined to an Active Directory domain?
- What types of interesting information can we find in history, log, and backup files
- Which files have been modified recently and how often? Are there any interesting patterns in file modification that could indicate a cron job in use that we may be able to hijack?
- Current IP addressing information
- Anything interesting in the `/etc/hosts` file?
- Are there any interesting network connections to other systems in the internal network or even outside the network?
- What tools are installed on the system that we may be able to take advantage of? (Netcat, Perl, Python, Ruby, Nmap, tcpdump, gcc, etc.)
- Can we access the `bash_history` file for any users and can we uncover any thing interesting from their recorded command line history such as passwords?
- Are any Cron jobs running on the system that we may be able to hijack?
#### Internals
the internal configuration and way of working, including integrated processes designed to accomplish specific tasks.
##### Network Interfaces
```bash
ip a 
# or ifconfig
```
##### Hosts
```bash
cat /etc/hosts
```
##### User's Last Login
It helps gauge how widely the system is used, which may indicate misconfigurations or messy directories and command histories.
```bash
lastlog
```
##### Logged In Users
 if anyone else is currently on the system with us
 ```bash
 w
 ```
##### Command History
```bash
 history
 ```
##### Finding History Files
we can also find special history files created by scripts or programs
```bash
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
```
##### Cron
we may find misconfigurations such as relative paths or weak permissions, they can leverage to escalate privileges when the scheduled cron job runs.
```bash
ls -la /etc/cron.daily/
```
##### Proc
**/proc** is a virtual Linux filesystem that provides real-time process, hardware, and kernel information and allows kernel parameter tuning.
```bash
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"

```
#### Services
##### Installed Packages
 systems may contain vulnerable packages, so we first create a list of installed packages to identify potential risks.
```bash
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
```
##### Sudo Version
sudo may vulnerable to any legacy or recent exploits.
```bash
sudo -V
```
##### Binaries
Sometimes software exists only as compiled binaries, requiring no installation and running directly on the system.
```bash
ls -l /bin /usr/bin/ /usr/sbin/
```
##### GTFObins
[GTFObins](https://gtfobins.github.io) lists exploitable binaries for privilege escalation, and a simple one-liner lets us compare them with binaries on the system to find targets to investigate.
```bash
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done
```
##### Trace System Calls
`strace` tracks system calls and signals to analyze program behavior, resource usage, and potential security issues, and its output can be saved for detailed analysis.
```bash
strace ping -c1 10.129.112.20
```
##### Configuration Files
Readable Linux configuration files can reveal service setup and sensitive data like keys or paths, even if the parent directory isn’t accessible.
```bash
find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
```
##### Scripts
Poorly secured scripts can expose internal processes and workflows, making them valuable targets even without exploitable permissions.
```shell-session
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
```
##### Running Services by User
The process list shows which scripts or binaries are running and by whom, and poorly restricted admin scripts may be executable by us.
```bash
ps aux | grep root
```


## 3-Credential Hunting
During enumeration, always collect credentials from configs, scripts, histories, backups, or files, as they can enable user or root escalation and further access.

The `/var` directory often holds the web root, which may expose credentials (e.g., MySQL creds in WordPress configs) that can be leveraged for further access.
```bash
grep 'DB_USER\|DB_PASSWORD' wp-config.php
```

Accessible mail or spool directories may contain sensitive data or credentials, similar to those often found in web root files.
```bash
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
```
#### SSH Keys
Searching for accessible SSH private keys can allow access as higher‑privileged users or to other hosts, and `known_hosts` can reveal targets for lateral movement or further escalation.
```bash
ls ~/.ssh
  # id_rsa  id_rsa.pub  known_hosts
```


---
