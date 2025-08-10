# Enumerating Security Controls
After gaining a foothold, we could use this access to get a feeling for the defensive state of the hosts,. Understanding the protections we may be up against will help inform our decisions regarding tool usage and assist us in planning our course of action by either avoiding or modifying certain tools.

>Note: This section is intended to showcase possible security controls in place within a domain, but does not have an interactive component. Enumerating and bypassing security controls are outside the scope of this module, but we wanted to give an overview of the possible technologies we may encounter during an assessment.

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

#### CME - Logged On Users
**We can also use CME to target other hosts** ==not only DC-IP== **and see the Users who logged on the host**
```bash
# <Domain-HOST-IP>: any Host on the domain (ex. server computer..) or IPs List
sudo crackmapexec smb <ANY-Domain-Host-IP> -u <USER> -p <PASS> --loggedon-users
  # [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 (Pwn3d!)
  # INLANEFREIGHT\svc_qualys
```
>we see the user `forend` is a local admin because `(Pwn3d!)` appears
>we see  the user `svc_qualys` is logged in, ho we earlier identified as a ==domain admin.==

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
bloodhound-python -h
  # -c : Which information to collect. -c all flag told the tool to run all checks

# Executing BloodHound.py
sudo bloodhound-python -u '<USER>' -p '<PASS>' -ns <DC-IP> -d <domain.local> -c all 

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

