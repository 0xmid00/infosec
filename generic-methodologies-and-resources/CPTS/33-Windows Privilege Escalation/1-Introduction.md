## 1-Introduction to Windows Privilege Escalation
After initial access, privilege escalation expands persistence options and exposes sensitive local data. The goal is usually to reach Local `Administrator` or `NT AUTHORITY\SYSTEM`, though escalating to another user may suffice. It’s a critical step in most engagements, often required for lateral movement or even the final objective in workstation or gold image assessments.

That being said, we may need to escalate privileges for one of the following reasons:

|||
|---|---|
|1.|When testing a client's [gold image](https://www.techopedia.com/definition/29456/golden-image) Windows workstation and server build for flaws|
|2.|To escalate privileges locally to gain access to some local resource such as a database|
|3.|To gain [NT AUTHORITY\System](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account) level access on a domain-joined machine to gain a foothold into the client's Active Directory environment|
|4.|To obtain credentials to move laterally or escalate privileges within the client's network|

Privilege escalation tools are helpful, but understanding manual techniques is essential. In restricted environments (no internet, firewall, no USB), you must rely on PowerShell and Windows command-line knowledge to perform Windows privilege escalation checks manually.

Windows systems present a vast attack surface. Just some of the ways that we can escalate privileges are:

|||
|---|---|
|Abusing Windows group privileges|Abusing Windows user privileges|
|Bypassing User Account Control|Abusing weak service/file permissions|
|Leveraging unpatched kernel exploits|Credential theft|
|Traffic Capture|and more.|

#### Scenario 1 - Overcoming Network Restrictions
I once was given the task to escalate privileges on a client-provided system with no internet access and blocked USB ports. Due to network access control in place, I could not plug my attack machine directly into the user network to assist me. During the assessment, I had already found a network flaw in which the printer VLAN was configured to allow outbound communication over ports 80, 443, and 445. I used manual enumeration methods to find a permissions-related flaw that allowed me to escalate privileges and perform a manual memory dump of the `LSASS` process. From here, I was able to mount an SMB share hosted on my attack machine on the printer VLAN and exfil the `LSASS` DMP file. With this file in hand, I used `Mimikatz` offline to retrieve the NTLM password hash for a domain admin, which I could crack offline and use to access a domain controller from the client-provided system.
#### Scenario 2 - Pillaging Open Shares
During another assessment, I found myself in a pretty locked-down environment that was well monitored and without any obvious configuration flaws or vulnerable services/applications in use. I found a wide-open file share, allowing all users to list its contents and download files stored on it. This share was hosting backups of virtual machines in the environment. I was explicitly interested in virtual harddrive files (`.VMDK` and `.VHDX` files). I could access this share from a Windows VM, mount the `.VHDX` virtual hard drive as a local drive and browse the file system. From here, I retrieved the `SYSTEM`, `SAM`, and `SECURITY` registry hives, moved them to my Linux attack box, and extracted the local administrator password hash using the [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) tool. The organization happened to be using a gold image, and the local administrator hash could be used to gain admin access to nearly every Windows system via a pass-the-hash attack.

#### Scenario 3 - Hunting Credentials and Abusing Account Privileges
In this final scenario, I was placed in a rather locked-down network with the goal of accessing critical database servers. The client provided me a laptop with a standard domain user account, and I could load tools onto it. I eventually ran the [Snaffler](https://github.com/SnaffCon/Snaffler) tool to hunt file shares for sensitive information. I came across some `.sql` files containing low-privileged database credentials to a database on one of their database servers. I used an MSSQL client locally to connect to the database using the database credentials, enable the [xp_cmdshell](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15) stored procedure and gain local command execution. Using this access as a service account, I confirmed that I had the [SeImpersonatePrivilege](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege), which can be leveraged for local privilege escalation. I downloaded a custom compiled version of [Juicy Potato](https://github.com/ohpe/juicy-potato) to the host to assist with privilege escalation, and was able to add a local admin user. Adding a user was not ideal, but my attempts to obtain a beacon/reverse shell did not work. With this access, I was able to remote into the database host and gain complete control of one of the company's clients' databases.
#### Why does Privilege Escalation Happen?
Privilege escalation happens due to poor patching, limited staff, and budget constraints. Many organizations lack the resources for proper vulnerability management, continuous monitoring, regular assessments, and security tasks like system upgrades and file share audits, allowing flaws to go unnoticed.


---

## 2- Useful Tools
There are many tools available to us to assist with enumerating Windows systems for common and obscure privilege escalation vectors. Below is a list of useful binaries and scripts, many of which we will cover within the coming module sections.

|Tool|Description|
|---|---|
|[Seatbelt](https://github.com/GhostPack/Seatbelt)|C# project for performing a wide variety of local privilege escalation checks|
|[winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)|WinPEAS is a script that searches for possible paths to escalate privileges on Windows hosts. All of the checks are explained [here](https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html)|
|[PowerUp](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1)|PowerShell script for finding common Windows privilege escalation vectors that rely on misconfigurations. It can also be used to exploit some of the issues found|
|[SharpUp](https://github.com/GhostPack/SharpUp)|C# version of PowerUp|
|[JAWS](https://github.com/411Hall/JAWS)|PowerShell script for enumerating privilege escalation vectors written in PowerShell 2.0|
|[SessionGopher](https://github.com/Arvanaghi/SessionGopher)|SessionGopher is a PowerShell tool that finds and decrypts saved session information for remote access tools. It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information|
|[Watson](https://github.com/rasta-mouse/Watson)|Watson is a .NET tool designed to enumerate missing KBs and suggest exploits for Privilege Escalation vulnerabilities.|
|[LaZagne](https://github.com/AlessandroZ/LaZagne)|Tool used for retrieving passwords stored on a local machine from web browsers, chat tools, databases, Git, email, memory dumps, PHP, sysadmin tools, wireless network configurations, internal Windows password storage mechanisms, and more|
|[Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng)|WES-NG is a tool based on the output of Windows' `systeminfo` utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 10, including their Windows Server counterparts, is supported|
|[Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)|We will use several tools from Sysinternals in our enumeration including [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk), [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist), and [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice)|
We can also find pre-compiled binaries of `Seatbelt` and `SharpUp` [here](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries), and standalone binaries of `LaZagne` [here](https://github.com/AlessandroZ/LaZagne/releases/). It is recommended that we always compile our tools from the source if using them in a client environment.

Note: Depending on how we gain access to a system we may not have many directories that are writeable by our user to upload tools. It is always a safe bet to upload tools to `C:\Windows\Temp` because the `BUILTIN\Users` group has write access.