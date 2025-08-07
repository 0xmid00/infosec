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
 sudo crackmapexec smb <DC-IP> -u <USER> -p <PASS> --groups>
```
>Take note of key groups like `Administrators`, `Domain Admins`, `Executives`, any groups that may contain privileged IT admins, etc. These groups will likely contain users with elevated privileges worth targeting during our assessment.

#### CME - Logged On Users
**We can also use CME to target other hosts** ==not only DC-IP== **and see the Users who logged on the host**
```bash
# <Domain-HOST-IP>: any Host on the domain (ex. server computer..) or IPs List
sudo crackmapexec smb <Domain-HOST-IP> -u <USER> -p <PASS> --loggedon-users
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


