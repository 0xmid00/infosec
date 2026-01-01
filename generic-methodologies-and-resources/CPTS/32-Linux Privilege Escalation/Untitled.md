
## Environment Enumeration
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
  # root:x:0:0:root:/root:/bin/bash ...
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
  # sudo:x:27:user1,user2
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

