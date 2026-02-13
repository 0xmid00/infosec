## 1- Situational Awareness
Situational awareness means understanding where you are and what’s around you so you can act correctly. In tasks like a penetration test, you need to know the system, its protections, and available access before taking next steps. This helps you plan actions, find new opportunities, and avoid using tools that won’t work.
#### Network Information
Gathering network information is essential during enumeration. A dual-homed host (connected to multiple networks) can allow lateral movement. 
Always check:
- **check routing tables**
    - understand local & nearby networks
- **Active Directory info**
    - identify domain
    - find domain controllers IPs
- **ARP cache (arp command)**
    - see recently contacted hosts
    - helps identify lateral movement targets
    - shows where admins connect (RDP / WinRM)
    - 
Network information can support privilege escalation by revealing new systems to access or enabling lateral movement after gaining higher privileges.
##### Interface(s), IP Address(es), DNS Information
```powershell
ipconfig /all
```
**ARP Table**
```powershell
arp -a
```
**Routing Table**
```powershell
route print
```
#### Enumerating Protections
Most systems run antivirus or EDR that can detect or block tools, especially public exploits. Identifying these protections early helps us choose safe methods or modify tools to avoid detection.

Organizations may also use application whitelisting (like **AppLocker**) to limit which programs users can run (e.g., blocking `cmd.exe` or `powershell.exe`). Checking these policies shows what is blocked and whether a bypass is needed.

Overall, enumerating AV, EDR, and whitelisting helps us adapt tools, avoid alerts, and save time during privilege escalation.
**Check Windows Defender Status**
```powershell
Get-MpComputerStatus # AntivirusEnabled    : True
```
**List AppLocker Rules**
```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
**Test AppLocker Policy**
```powershell
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone 
```


---

## 2-Initial Enumeration
After getting a low-privilege shell on a Windows host, we try to escalate privileges to gain more access. This can expose sensitive files, credentials, traffic, or even lead to Domain Admin access in Active Directory.

Possible privilege targets:
- **NT AUTHORITY\SYSTEM (LocalSystem)** – highest local privileges
- **Local Administrator** (built-in or another admin user)
- **Any Local user in the local Administrators group**
- **Domain user with local admin rights**
- **Domain Admin** (very high AD privileges)

Enumeration is critical. After initial access, we must identify OS version, patches, software, privileges, and group memberships. Even though tools help, knowing how to do this manually is essential when tools are blocked or restricted.
#### Key Data Points
- **OS Name**: Know if it’s Windows workstation or server and the version. This helps choose tools and find possible exploits.  
- **Version**: Some exploits work only on specific Windows versions. Be careful—exploits can crash systems.  
- **Running Services**: Check services running as SYSTEM or admin. Misconfigured services can allow easy privilege escalation.
### System Information
Checking the system shows the OS version, hardware, installed programs, and updates. This helps find missing patches and CVEs that can be used for privilege escalation.
#### Tasklist
View running processes to understand what apps and services are active.
```powershell
tasklist /svc
```
What to Look For
- **Standard Windows processes:** Know them to quickly spot **abnormal ones**
    - smss.exe, csrss.exe, winlogon.exe
    - lsass.exe, svchost.exe
**Interesting Findings:**
- `FileZilla Server / FTP:`  Check version ,  Look for public exploits or misconfigurations
- **MsMpEng.exe (Windows Defender)** Shows AV/EDR is running ,  Helps plan **evasion/bypass**
#### Display All Environment Variables
```cmd
set
```
Environment variables reveal host configuration. In Windows, the `set` command lists them, including the often-overlooked **PATH**. If PATH is modified (e.g., adding Python or Java) and points to a user‑writable folder—especially placed before `C:\Windows\System32`—it can enable attacks like DLL injection. Windows searches the current directory first, then PATH left to right.

The `set` command also shows info like **HOMEDRIVE**, often a network share in enterprises. These shares may expose sensitive files (e.g., IT inventories with passwords) and are used for roaming profiles. Malicious files placed in the user’s Startup folder `USERPROFILE\AppData\Microsoft\Windows\Start Menu\Programs\Startup` can execute when the user logs into other machines.
#### View Detailed Configuration Information
```CMD
systeminfo
```
The `systeminfo` command shows patch status and whether the system is a VM. Outdated or long‑unpatched systems may be vulnerable to known exploits. Patch level can be estimated from HotFix KBs, OS version, boot time, and long uptime (e.g., no reboot for months). Some hotfixes may be hidden from non‑admins.

Network information may hint at a dual‑homed system, but in enterprises this is usually handled by firewall rules, not multiple physical network connections.
#### Patches and Updates
If `systeminfo` doesn't display hotfixes, they may be queriable with [WMI](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) using the WMI-Command binary with [QFE (Quick Fix Engineering)](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering) to display patches.
```cmd-session
wmic qfe
```
We can do this with PowerShell as well using the [Get-Hotfix](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix?view=powershell-7.1) cmdlet.
```powershell
Get-HotFix | ft -AutoSize```
#### Installed Programs
WMI can also be used to display installed software. This information can often guide us towards hard-to-find exploits. Is `FileZilla`/`Putty`/etc installed? Run `LaZagne` to check if stored credentials for those applications are installed. Also, some programs may be installed and running as a service that is vulnerable.
```cmd
wmic product get name
```
We can, of course, do this with PowerShell as well using the [Get-WmiObject](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1) cmdlet.
```powershell
Get-WmiObject -Class Win32_Product |  select Name, Version
```
#### Display Running Processes
`netstat` shows active TCP/UDP connections and listening services. It can reveal locally accessible services that may be vulnerable and exploitable for privilege escalation.
 **Netstat**
```cmd
netstat -ano

# Step 2: Map PID to service name
tasklist /svc | findstr <PID>
```
automatically map **PORT ↔ PID ↔ PROCESS NAME**.
```powershell
Get-NetTCPConnection -State Listen |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}

  # LocalAddress   LocalPort OwningProcess Process
  # ------------   --------- ------------- -------
  # 127.0.0.1          14147          2076 FileZilla Server
```
### User & Group Information
Users are often the weakest link. Enumerating users, groups, privileges, password policies, and logged‑in users can reveal easy paths to admin access, even on well‑patched systems (e.g., exposed files with passwords in admin directories ex.`logins.xlsx`).
#### Logged-In Users
It’s important to identify logged‑in users and whether they are active or idle. This can enable user‑focused attacks for privilege escalation, but active users require caution to avoid detection.
```cmd
query user
```
#### Current User
Always check your user context after access—you may already be SYSTEM. Service accounts may have privileges like `SeImpersonatePrivilege`, which can be abused for privilege escalation (e.g., with [Juicy Potato](https://github.com/ohpe/juicy-potato)).
```cmd
echo %USERNAME%
```
#### Current User Privileges
As mentioned prior, knowing what privileges our user has can greatly help in escalating privileges. We will look at individual user privileges and escalation paths later in this module.
```cmd
whoami /priv
```
#### Current User Group Information
Has our user inherited any rights through their group membership? Are they privileged in the Active Directory domain environment, which could be leveraged to gain access to more systems?
```cmd
whoami /groups
```
#### Get All Users
Identifying other users is important. If a similar account (e.g., `bob` and `bob_adm`) exists, check for credential reuse. User profile directories may contain valuable files like scripts, passwords, or SSH keys.
```cmd
net user
```
#### Get All Groups
Identifying non‑standard groups helps reveal a host’s purpose, usage level, and misconfigurations, such as Domain Users being added to Remote Desktop or local Administrators groups.
```cmd
net localgroup

net groups /domain # domain groups
```
#### Details About a Group
It is worth checking out the details for any non-standard groups. Though unlikely, we may find a password or other interesting information stored in the group's description. During our enumeration, we may discover credentials of another non-admin user who is a member of a local group that can be leveraged to escalate privileges.
```cmd-session
net localgroup administrators
```
#### Get Password Policy & Other Account Information
```cmd-session
net accounts
```
### Moving On
- Many  enum cheat sheets are available to help us, such as [this one](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md).


---

## 3- Communication with Processes
One of the best places to look for privilege escalation is the processes that are running on the system. Even if a process is not running as an administrator, it may lead to additional privileges. The most common example is discovering a web server like IIS or XAMPP running on the box, placing an `aspx/php` shell on the box, and gaining a shell as the user running the web server. Generally, this is not an administrator but will often have the `SeImpersonate` token, allowing for `Rogue/Juicy/Lonely Potato` to provide SYSTEM permissions.

#### Access Tokens
Access tokens in Windows define the security context of a process or thread. They contain the user’s identity and privileges. After successful login, Windows assigns a token, which is used whenever the user interacts with a process to determine their access level.
### Enumerating Network Services
Users usually interact with processes through network sockets (DNS, HTTP, SMB, etc.). The `netstat` command shows active TCP/UDP connections and listening ports. This helps identify services, including vulnerable ones that may be accessible only locally and usable for privilege escalation.
#### Display Active Network Connections
```cmd
netstat -ano 
  #   TCP    [::1]:14147    [::]:0    LISTENING   3812
```
The main thing to look for with Active Network Connections are entries listening on loopback addresses (`127.0.0.1` and `::1`) that are not listening on the IP Address (`10.129.43.8`) or broadcast (`0.0.0.0`, `::/0`). The reason for this is network sockets on localhost are often insecure due to the thought that "they aren't accessible to the network." The one that sticks out immediately will be port `14147`, which is used for FileZilla's administrative interface. By connecting to this port, it may be possible to extract FTP passwords in addition to creating an FTP Share at c:\ as the FileZilla Server user (potentially Administrator).).
#### More Examples
One of the best examples of this type of privilege escalation is the `Splunk Universal Forwarder`, installed on endpoints to send logs into Splunk. The default configuration of Splunk did not have any authentication on the software and allowed anyone to deploy applications, which could lead to code execution. Again, the default configuration of Splunk was to run it as SYSTEM$ and not a low privilege user. For more information, check out [Splunk Universal Forwarder Hijacking](https://airman604.medium.com/splunk-universal-forwarder-hijacking-5899c3e0e6b2) and [SplunkWhisperer2](https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/).

Another overlooked but common local privilege escalation vector is the `Erlang Port` (25672). Erlang is a programming language designed around distributed computing and will have a network port that allows other Erlang nodes to join the cluster. The secret to join this cluster is called a cookie. Many applications that utilize Erlang will either use a weak cookie (RabbitMQ uses `rabbit` by default) or place the cookie in a configuration file that is not well protected. Some example Erlang applications are SolarWinds, RabbitMQ, and CouchDB. For more information check out the [Erlang-arce blogpost from Mubix](https://malicious.link/post/2018/erlang-arce/)
### Named Pipes
#### More on Named Pipes
Pipes are used for communication between two applications or processes using shared memory. There are two types of pipes, [named pipes](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes) and anonymous pipes. An example of a named pipe is `\\.\PipeName\\ExampleNamedPipeServer`. Windows systems use a client-server implementation for pipe communication. In this type of implementation, the process that creates a named pipe is the server, and the process communicating with the named pipe is the client. Named pipes can communicate using `half-duplex`, or a one-way channel with the client only being able to write data to the server, or `duplex`, which is a two-way communication channel that allows the client to write data over the pipe, and the server to respond back with data over that pipe. Every active connection to a named pipe server results in the creation of a new named pipe. These all share the same pipe name but communicate using a different data buffer.

We can use the tool [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist) from the Sysinternals Suite to enumerate instances of named pipes.
#### Listing Named Pipes with Pipelist
```powershell
pipelist.exe /accepteula

#  Pipe Name                                    Instances       Max Instances
# ---------                                    ---------       -------------
# lsass                                             4               -1
```
Additionally, we can use PowerShell to list named pipes using `gci` (`Get-ChildItem`).
```powershell
gci \\.\pipe\
  # Directory: \\.\pipe
  # ------       12/31/1600   4:00 PM              4 lsass
```
After obtaining a listing of named pipes, we can use [Accesschk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) to enumerate the permissions assigned to a specific named pipe by reviewing the Discretionary Access List (DACL), which shows us who has the permissions to modify, write, read, or execute a resource. Let's take a look at the `LSASS` process. We can also review the DACLs of all named pipes using the command `.\accesschk.exe /accepteula \pipe\`.
```powershell
accesschk.exe /accepteula \\.\Pipe\lsass -v
  # RW BUILTIN\Administrators
        # FILE_ALL_ACCESS
```
#### Named Pipes Attack Example
Let's walk through an example of taking advantage of an exposed named pipe to escalate privileges. This [WindscribeService Named Pipe Privilege Escalation](https://www.exploit-db.com/exploits/48021) is a great example. Using `accesschk` we can search for all named pipes that allow write access with a command such as `accesschk.exe -w \pipe\* -v` and notice that the `WindscribeService` named pipe allows `READ` and `WRITE` access to the `Everyone` group, meaning all authenticated users.
##### Checking WindscribeService Named Pipe Permissions
Confirming with `accesschk` we see that the Everyone group does indeed have `FILE_ALL_ACCESS` (All possible access rights) over the pipe.
```powershell
accesschk.exe -accepteula -w \pipe\WindscribeService -v
  # RW Everyone
       #  FILE_ALL_ACCESS
```
From here, we could leverage these lax permissions to escalate privileges on the host to SYSTEM.
