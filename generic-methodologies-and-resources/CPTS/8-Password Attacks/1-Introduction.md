###  Theory of Protection
Theory of Protection Summary

The core of InfoSec is the *CIA Triad* – *Confidentiality*, *Integrity*, and *Availability*. To protect systems, we use *Authentication* (prove identity), *Authorization* (give access), and *Accounting* (track actions).

*Authentication* uses:
- *Something you know* (password)
- *Something you have* (ID card, phone)
- *Something you are* (biometrics)

*Passwords* are still the most common method. Many users reuse weak passwords like "123456" or their names, and 66% reuse the same password on multiple sites. This makes it easier for attackers to guess or reuse them.

Tools like *HaveIBeenPwned* can show if your email/password was in a breach.

Weak authentication leads to security gaps, which attackers exploit using password guessing and reuse attacks.

---
###  Introduction to Password Cracking
```bash
echo -n Soccer06! | md5sum #  md5 hashing 
echo -n Soccer06! | sha256sum # sha-256
```

###  Credential Storage
We  know that every operating system supports these types of authentication mechanisms. The stored credentials are therefore stored locally. Let's look at how these are created, stored, and managed by Windows and Linux-based systems in more detail.
####  Linux
```bash
cat /etc/shadow # kali:$y$j9T$Fy8oue2hAzyeAjo.Km6QC/$lQcEsriPdEzy56TXE2IkYzTyFIzRLBVid7Mdy2iyyV7:20019:0:99999:7:::
# <username>:<encrypted password>:<day of last change>:<min age>:<max age>:<warning period>:<inactivity period>:<expiration date>:<reserved field>

# <encrypted password> formate : 
$<id>$<salt>$<hashed>  →  Example: $y$j9T$3QSBB6CbHEu...f8Ms

# <id> : $1$=MD5, $2a$=Blowfish, $5$=SHA-256, $6$=SHA-512, $sha1$=SHA1crypt, $y$=Yescrypt, $gy$=Gost-yescrypt, $7$=Scrypt

cat /etc/passwd # htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
# <username>:<password>:<uid>:<gid>:<comment>:<home directory>:<cmd executed after logging in> 
# The x in the password field indicates that the encrypted password is in the /etc/shadow file
```
#### Windows Authentication Process
![](https://academy.hackthebox.com/storage/modules/147/Auth_process1.png)
```bash
# Windows Authentication Process - Simplified Notes

## Main Components:
- **Winlogon.exe**: Handles secure user interactions (logon, lock, unlock).
- **LogonUI.exe**: Displays logon screen to the user.
- **Credential Providers**: Collects username/password input.
- **LSASS (lsass.exe)**: Authenticates the user, manages security policies.
- **Authentication Packages**: DLLs that perform authentication (e.g., NTLM, Kerberos).

## Authentication Flow:
1. User presses Ctrl+Alt+Del → Winlogon intercepts.
2. Winlogon launches LogonUI → UI for user input.
3. Credential Provider collects credentials.
4. Winlogon sends credentials to LSASS.
5. LSASS uses auth package (e.g., Msv1_0.dll for local login).
6. Credentials are checked against:
   - **SAM** (local accounts)
   - **Active Directory** (domain accounts)

## Important DLLs:
- `Msv1_0.dll`: Handles local logons.
- `Kerberos.dll`: Used for domain-based Kerberos auth.
- `Lsasrv.dll`: LSA service, selects NTLM/Kerberos.
- `Samsrv.dll`: Manages SAM database.
- `Netlogon.dll`: Supports network logons.
- `Ntdsa.dll`: Handles Active Directory data.

## SAM (Security Account Manager):
- Stores local account info & password hashes.
- Path: `%SystemRoot%\System32\config\SAM`
- Mounted at: `HKLM\SAM`
- Needs SYSTEM privileges to access.
- Uses LM/NTLM hashes.
- **Syskey (NT 4.0)**: Encrypts SAM data to prevent offline attacks.

## Credential Manager:
- Stores saved credentials (network, websites).
- Per-user encrypted storage.
- Path: 
  `C:\Users\[Username]\AppData\Local\Microsoft\Credentials\`
- Can be decrypted with various tools.

## NTDS.dit (Active Directory DB):
- Found on Domain Controllers.
- Stores:
  - User/computer/group accounts
  - Password hashes
  - Group Policy Objects
- Path: `%SystemRoot%\NTDS\NTDS.dit`
- Synced across DCs (except Read-Only DCs).
```

---

### John The Ripper

```bash
# John the Ripper:

- Used to crack password hashes (brute force & dictionary attacks)
- Open-source, started in 1996, mainly for UNIX
- "Jumbo" version is better (extra features + 64-bit support)
- Supports many hash formats (convert with tools if needed)
- Regularly updated for latest security standards

## Supported Encryption Types (Examples)
- UNIX crypt(3)            -> 56-bit key
- Traditional DES          -> DES algorithm
- bigcrypt                 -> Extended DES, 128-bit
- BSDI DES                 -> Extended DES, 168-bit
- FreeBSD MD5 (Linux/Cisco)-> MD5, 128-bit
- OpenBSD Blowfish         -> Blowfish, 448-bit
- Kerberos/AFS             -> Secure auth systems
- Windows LM               -> DES, 56-bit
- DES tripcodes            -> Auth based on DES
- SHA-crypt (Fedora/Ubuntu)-> 256-bit
- SHA-crypt & SUNMD5       -> Used in Solaris
## ...many more supported

# Attack Methods
## Dictionary Attack
- Tries known/common passwords
- Fast if password is weak
- Fix: use strong, unique passwords + 2FA
## Brute Force
- Tries every possible combo
- Very slow
- Fix: long + complex passwords
## Rainbow Table
- Uses pre-made hash-password list
- Fast but limited to known hashes
- Fix: use salted hashes

# Cracking Modes
## Single Crack Mode :Tries passwords from one list , Basic but slow
john --format=<hash_type> <hash_file>
## Wordlist Mode :  Uses a list of words to crack passwords ,More effective than Single Crack Mode
john --wordlist=<wordlist_file> --rules <hash_file>
## Incremental Mode : Tries all possible character combinations , Slow, but effective for weak passwords
john --incremental <hash_file>

## Hash Formats :
----------------
afs             - AFS (Andrew File System) password hashes
bfegg           - bfegg hashes used in Eggdrop IRC bots
bf              - Blowfish-based crypt(3) hashes
bsdi            - BSDi crypt(3) hashes
crypt(3)        - Traditional Unix crypt(3) hashes
des             - Traditional DES-based crypt(3) hashes
dmd5            - DMD5 (Dragonfly BSD MD5) password hashes
dominosec       - IBM Lotus Domino 6/7 password hashes
episerver       - EPiServer SID (Security Identifier) password hashes
hdaa            - hdaa password hashes used in Openwall GNU/Linux
hmac-md5        - hmac-md5 password hashes
hmailserver     - hmailserver password hashes
ipb2            - Invision Power Board 2 password hashes
krb4            - Kerberos 4 password hashes
krb5            - Kerberos 5 password hashes
LM              - LM (Lan Manager) password hashes
lotus5          - Lotus Notes/Domino 5 password hashes
mscash          - MS Cache password hashes
mscash2         - MS Cache v2 password hashes
mschapv2        - MS CHAP v2 password hashes
mskr5           - MS Kerberos 5 password hashes
mssql05         - MS SQL 2005 password hashes
mssql           - MS SQL password hashes
mysql-fast      - MySQL fast password hashes
mysql           - MySQL password hashes
mysql-sha1      - MySQL SHA1 password hashes
netlm           - NETLM (NT LAN Manager) password hashes
netlmv2         - NETLMv2 (NT LAN Manager version 2) password hashes
netntlm         - NETNTLM (NT LAN Manager) password hashes
netntlmv2       - NETNTLMv2 (NT LAN Manager version 2) password hashes
nethalflm       - NEThalfLM (NT LAN Manager) password hashes
md5ns           - md5ns (MD5 namespace) password hashes
nsldap          - nsldap (OpenLDAP SHA) password hashes
ssha            - ssha (Salted SHA) password hashes
NT              - NT (Windows NT) password hashes
openssha        - OPENSSH private key password hashes
oracle11        - Oracle 11 password hashes
oracle          - Oracle password hashes
pdf             - PDF (Portable Document Format) password hashes
phpass-md5      - PHPass-MD5 (Portable PHP password hashing framework) password hashes
phps            - PHPS password hashes
pix-md5         - Cisco PIX MD5 password hashes
po              - Po (Sybase SQL Anywhere) password hashes
rar             - RAR (WinRAR) password hashes
raw-md4         - Raw MD4 password hashes
raw-md5         - Raw MD5 password hashes
raw-md5-unicode - Raw MD5 Unicode password hashes
raw-sha1        - Raw SHA1 password hashes
raw-sha224      - Raw SHA224 password hashes
raw-sha256      - Raw SHA256 password hashes
raw-sha384      - Raw SHA384 password hashes
raw-sha512      - Raw SHA512 password hashes
salted-sha      - Salted SHA password hashes
sapb            - SAP CODVN B (BCODE) password hashes
sapg            - SAP CODVN G (PASSCODE) password hashes
sha1-gen        - Generic SHA1 password hashes
skey            - S/Key (One-time password) hashes
ssh             - SSH (Secure Shell) password hashes
sybasease       - Sybase ASE password hashes
xsha            - xsha (Extended SHA) password hashes
zip             - ZIP (WinZip) password hashes

# Cracking Files
## Step 1: Convert file to hash
<tool> <target_file> > file.hash
pdf2john secret.pdf > secret.hash # Example: Crack a PDF
john secret.hash
john --wordlist=rockyou.txt secret.hash # OR with wordlist
## Common *2john Tools:
pdf2john             → PDF documents  
ssh2john             → SSH private keys  
mscash2john          → MS Cash hashes  
keychain2john        → macOS keychains  
rar2john             → RAR archives  
pfx2john             → PKCS#12 certs (.pfx)  
truecrypt_volume2john → TrueCrypt volumes  
keepass2john         → KeePass DBs  
vncpcap2john         → VNC PCAPs  
putty2john           → PuTTY private keys  
zip2john             → ZIP archives  
hccap2john           → WPA/WPA2 handshakes  
office2john          → MS Office docs  
wpa2john             → WPA/WPA2 handshakes
## 🔍 Find all conversion tools:
locate *2john*
```

###  Hashcat
```bash
hashcat -a 0 -m 0 <hashes> [wordlist, rule, mask, ...]
  # -a attack mode
  # -m hash type
  # <hashes> string or file containing  hashes

## Hash types
  hashcat --help # list all the types 
  https://hashcat.net/wiki/doku.php?id=example_hashes # all hashes types list
  hashid -m '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1' # identify the hashcat hash type 

## Attack modes

 -a 0 # Dictionary attack
  # hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt

 -a 3 # # Mask attack (Brute forcing all possible caracters)
  # ?l abcdefghijklmnopqrstuvwxyz
  # ?u ABCDEFGHIJKLMNOPQRSTUVWXYZ
  # ?d 0123456789
  # ?h 0123456789abcdef
  # ?H 0123456789ABCDEF
  # ?s «space»!"#$%&'()*+,-./:;<=>?@[]^_`{
  # ?a ?l?u?d?s
  # ?b 0x00 - 0xff

  # example upper+4*lower+digit+symbol = ?u?l?l?l?l?d?s
  # hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'

## rules 
  ls -l /usr/share/hashcat/rules # list all rules files
  -r <ruleset>
  # hashcat -a 0 -m 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
  # Generate mutated password list with Hashcat rules 
  hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

### Password Mutation
```bash
# Basic idea: Users make predictable password mutations (e.g. Name2024!, P@ssw0rd).
# Use Hashcat rules to generate realistic mutations.

# Sample password list
cat password.list
# rawen

# Sample custom Hashcat rule file
cat custom.rule
# :
# c                 # Capitalize first letter
# so0               # Replace o with 0
# sa@               # Replace a with @
# $!                # Add '!' at the end
# combinations like:
# $! c so0 sa@      # Add '!', capitalize, o→0, a→@

# Generate mutated password list with Hashcat rules
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list

# One of the most used rules is best64.rule, which can often lead to good results
sed -ri '/^.{,9}$/d' mut_password.list  # Remove all passwords shorter than 10 with sed -ri '/^.{,9}$/d' mut_password.list 

# Use existing rules (e.g., best64.rule)
ls /usr/share/hashcat/rules/
# best64.rule, toggles1.rule, leetspeak.rule, etc.

# Extract potential keywords from a website using CeWL
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist

# Count words in generated list
wc -l inlane.wordlist
# Example output: 326



------
### search for usernames 

    # Common username conventions (example: Jane Jill Doe)
    jdoe         # first initial + last name
    jjdoe        # first + middle initial + last name
    janedoe      # first name + last name
    jane.doe     # first name dot last name
    doe.jane     # last name dot first name
    doedoehacksstuff  # nickname or custom alias
    
    # google dorks: “@inlanefreight.com” 
    # “inlanefreight.com filetype:pdf” | exiftool file.pdf (search for Author)

### Creating a Custom list of Usernames
    echo "Ben Williamson" >> names.txt
    ./username-anarchy -i /home/ltnbob/names.txt > usernames.txt

###  Launching the Attack with CrackMapExec
    crackmapexec smb 10.129.201.57 -u <username> -p /usr/share/wordlists/fasttrack.txt

###  Connecting to a DC with Evil-WinRM 
# we have the winrm service open (port 5985,5986) 
    evil-winrm -i 10.129.201.57  -u <user> -p '<password>' 
```