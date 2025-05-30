.# Checklist - Linux Privilege Escalation

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

**Hacking Insights**\
Engage with content that delves into the thrill and challenges of hacking

**Real-Time Hack News**\
Keep up-to-date with fast-paced hacking world through real-time news and insights

**Latest Announcements**\
Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

`curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh`
***
###  Kernel exploits
- [ ] [[linux-hardening/privilege-escalation/README#Kernel exploits| Kernel exploits]]  
`uname -a`
`searchsploit linux kernel 2.6.32 priv esc (DirtyCow?)`
### Service & softwares Exploits
- [ ] [[linux-hardening/privilege-escalation/README#Service & softwares Exploits| Service & softwares Exploits]]  
`ps aux | grep '^root'` OR `<program> --version` OR `dpkg -l`
`seachsploit <softwawre/service> priv esc`

### Weak files permissions
- [ ] [[linux-hardening/privilege-escalation/README#readable /etc/shadow| Readable /etc/shadow]]  
`ls -l /etc/shadow -> -rw-r—r-`
- [ ] [[linux-hardening/privilege-escalation/README#Writable /etc/shadow| writeable /etc/shadow]]  
`ls -l /etc/shadow -> -rw-r—w-`
- [ ] [[linux-hardening/privilege-escalation/README#Writable /etc/passwd| writeable /etc/passwd]]  
`ls -l /etc/passwd -> -rw-r—w-`
- [ ] [[linux-hardening/privilege-escalation/README#**Backups**|Backups]] `searching manuely ` 
```bash
⚠️ #  i have write permission and  still unable to write to the file ?
lsattr suid.sh  # 'i' means immutable
ls -ld /tmp  # 't' means only owners can modify
```

### Sudo,

- [ ] [[linux-hardening/privilege-escalation/README#Known Password| Known Password]]  
`sudo su`
- [ ] [[linux-hardening/privilege-escalation/README#Shell Escape Sequences(NOPASSWD)| Shell Escape Sequences]]
`sudo -l` ->  `https://gtfobins.github.io/`
- [ ] [[linux-hardening/privilege-escalation/README#Abusing Intended Functionality| Abusing Intended Functionality]]  
`sudo -l -> https://gtfobins.github.io/ -> NO shell escape sequence -> searching manuely If we can use program read/write files owned by root`
- [ ] [[linux-hardening/privilege-escalation/README#LD_PRELOAD| LD_PRELOAD]]  
`sudo -l -> env_keep+=LD_PRELOAD`
- [ ] [[linux-hardening/privilege-escalation/README#LD_LIBRARY_PATH|LD_LIBRARY_PATH]]  
`sudo -l -> env_keep+=LD_LIBRARY_PATH`
- [ ] **Writable File as Root**  
`sudo permission is given to a writable file (root) NOPASSWD: <file> => edit file`
- [ ] [[linux-hardening/privilege-escalation/README#Sudo command/SUID binary without command path| Sudo command without command path]]  
`sudo permission is given to a single command without specifying the path hacker10 ALL= (root) less`

### Cron Jobs
- [ ] [[linux-hardening/privilege-escalation/README#Cron script overwriting and symlink| Cron script overwriting and symlink]]  
`ls /etc/crontab -> writable by others: -rwxr--rw- root /usr/local/bin/overwrite.sh`
- [ ] [[linux-hardening/privilege-escalation/README#The crontab PATH environment variable| PATH Environment Variable]]  
`cat /etc/crontab -> does not use an absolute path: * * * * * root overwrite.sh & PATH=/home/user /home/user directory (which we can write to)`

- [ ] [[linux-hardening/privilege-escalation/README#Cron using a script with a wildcard (Wildcard Injection)| Wildcards]]  
`cat /etc/crontab ->  * * * * * root /usr/local/bin/compress.sh -> tar czf /tmp/backup.tar.gz *`

## SUID/GUID files
- `find / -type f \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`
- [ ] [[linux-hardening/privilege-escalation/README#Shell Escape Sequences| Shell Escape Sequences]]  `https://gtfobins.github.io/`
- [ ] [[linux-hardening/privilege-escalation/README#Known Exploits for SUID/SGID Files| Known Exploits ]]  `searchsploit <suid/sgid_file>`
- [ ] [[linux-hardening/privilege-escalation/README#Shared Object Hijacking| Shared Object Hijacking]]  
- `trace /usr/local/bin/<suid-file> 2>&1 | grep -iE "open|access|no such file"#-> The libcalc.so shared object could not be found, and the program is looking in our user’s home directory, which we can write to.`
- [ ] [[linux-hardening/privilege-escalation/README#SUID binary without command path| SUID binary  without command path]]  
`strings/strace <suid-file> look for commands that may be executed without full paths (e.g.service apache2 start`)`
- [ ] [[linux-hardening/privilege-escalation/README#SUID binary with command path (notably Bash <4.2-048)| SUID binary with command path (notably Bash <4.2-048)]] 
`Bash <4.2-048 & strings/strace <suid_file> -> /bin/<absolute_path>/excutable_file_called`
- [ ] [[linux-hardening/privilege-escalation/README#SUID binary (Abusing Shell Features Bash <4.4)| SUID binary (Abusing Shell Features Bash <4.4)]] 
`Bash <4.4`

```bash
⚠️ -p  example `/bin/bash -p` used only  on binary shells to spawn a root shell **not in all suid files
⚠️ SUID works on C programs, ignored on scripts—use a C wrapper for Bash.
```

## passwords & keys

- [ ] [[linux-hardening/privilege-escalation/README#Known files containing passwords| knows files Passwords]] ***+*** [[linux-hardening/privilege-escalation/README#Generic Creds Search/Regex| Generic Creds Search/Regex]] `just search.. `
- [ ] [[linux-hardening/privilege-escalation/README#* _history, .sudo _as _admin _successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files| History Files]] `cat $HOME/.*history| less`
- [ ] [[linux-hardening/privilege-escalation/README#Config Files| Config Files]] `just search.. `
- [ ] [[linux-hardening/privilege-escalation/README#ssh privet key| ssh keys]] `just search.. `
### NFS 
- [ ] [[nfs-no_root_squash-misconfiguration-pe]] `cat /etc/exportst -> /tmp *(rw,sync,insecure,no_root_squash,no_subtree_check) ` 
   `no_root_squash is an NFS configuration option which turns root squashing off.`