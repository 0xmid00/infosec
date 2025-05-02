# Infiltrating Windows
## Prominent Windows Exploits

Over the last few years, several vulnerabilities in the Windows operating system and their corresponding attacks are some of the most exploited vulnerabilities of our time

| **Vulnerability (ID)**              | **Description**                                                                                                           | **Affected Windows Versions (Pre-Patch)**                                               | **Impact**                              |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | --------------------------------------- |
| **MS08-067**                        | SMB flaw allowing remote code execution. Used by Conficker worm and Stuxnet malware.                                      | Windows 2000, Windows XP, Windows Server 2003                                           | Remote Code Execution via SMB           |
| **MS17-010 (EternalBlue)**          | SMBv1 vulnerability leaked by Shadow Brokers; exploited by WannaCry and NotPetya.                                         | Windows XP, Vista, 7, 8.1, RT 8.1, Server 2003, 2008/2008 R2, 2012/2012 R2, Server 2016 | Remote Code Execution via SMBv1         |
| **CVE-2021-34527 (PrintNightmare)** | Print Spooler bug allowing RCE and privilege escalation through driver installation.                                      | Windows 7, 8.1, 10 (pre-July 2021), Server 2008/2008 R2, 2012/2012 R2, 2016, 2019, 2022 | Remote Code Execution via Print Spooler |
| **CVE-2019-0708 (BlueKeep)**        | RDP vulnerability allowing unauthenticated remote code execution.                                                         | Windows XP, Vista, 7, Server 2003, Server 2008/2008 R2                                  | Remote Code Execution via RDP           |
| **CVE-2020-1350 (SigRed)**          | DNS vulnerability in Windows Server allowing attackers to run code on Domain Controllers via malicious DNS queries.       | Windows Server 2003 to 2019 (DNS role only)                                             | Remote Code Execution via DNS           |
| **CVE-2021-36934 (SeriousSAM)**     | Misconfigured ACLs allowed users to read SAM and SYSTEM registry hives from shadow copies, leading to credential theft.   | Windows 10 (1809–21H1), Windows Server 2019                                             | Local Privilege Escalation              |
| **CVE-2020-1472 (Zerologon)**       | Netlogon protocol flaw enabling domain takeover by spoofing a DC through repeated login attempts with zeroed credentials. | Windows Server 2008/2008 R2, 2012/2012 R2, 2016, 2019                                   | Domain Privilege Escalation             |



## Payload Types to Consider

- [DLLs](https://docs.microsoft.com/en-us/troubleshoot/windows-client/deployment/dynamic-link-library) A Dynamic Linking Library (DLL) is a library file used in Microsoft operating systems to provide shared code and data that can be used by many different programs at once. These files are modular and allow us to have applications that are more dynamic and easier to update. As a pentester, injecting a malicious DLL or hijacking a vulnerable library on the host can elevate our privileges to SYSTEM and/or bypass User Account Controls.
    
- [Batch](https://commandwindows.com/batch.htm) Batch files are text-based DOS scripts utilized by system administrators to complete multiple tasks through the command-line interpreter. These files end with an extension of `.bat`. We can use batch files to run commands on the host in an automated fashion. For example, we can have a batch file open a port on the host, or connect back to our attacking box. Once that is done, it can then perform basic enumeration steps and feed us info back over the open port.
    
- [VBS](https://www.guru99.com/introduction-to-vbscript.html) VBScript is a lightweight scripting language based on Microsoft's Visual Basic. It is typically used as a client-side scripting language in webservers to enable dynamic web pages. VBS is dated and disabled by most modern web browsers but lives on in the context of Phishing and other attacks aimed at having users perform an action such as enabling the loading of Macros in an excel document or clicking on a cell to have the Windows scripting engine execute a piece of code.
    
- [MSI](https://docs.microsoft.com/en-us/windows/win32/msi/windows-installer-file-extensions) `.MSI` files serve as an installation database for the Windows Installer. When attempting to install a new application, the installer will look for the .msi file to understand all of the components required and how to find them. We can use the Windows Installer by crafting a payload as an .msi file. Once we have it on the host, we can run `msiexec` to execute our file, which will provide us with further access, such as an elevated reverse shell.
    
- [Powershell](https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.1) Powershell is both a shell environment and scripting language. It serves as Microsoft's modern shell environment in their operating systems. As a scripting language, it is a dynamic language based on the .NET Common Language Runtime that, like its shell component, takes input and output as .NET objects. PowerShell can provide us with a plethora of options when it comes to gaining a shell and execution on a host, among many other steps in our penetration testing process.
#### Payload Generation

We have plenty of good options for dealing with generating payloads to use against Windows hosts.

| **Resource**                      | **Description**                                                                                                                                                                                                                                                                                                   |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MSFVenom & Metasploit-Framework` | [Source](https://github.com/rapid7/metasploit-framework) MSF is an extremely versatile tool for any pentester's toolkit. It serves as a way to enumerate hosts, generate payloads, utilize public and custom exploits, and perform post-exploitation actions once on the host. Think of it as a swiss-army knife. |
| `Payloads All The Things`         | [Source](https://github.com/swisskyrepo/PayloadsAllTheThings) Here, you can find many different resources and cheat sheets for payload generation and general methodology.                                                                                                                                        |
| `Mythic C2 Framework`             | [Source](https://github.com/its-a-feature/Mythic) The Mythic C2 framework is an alternative option to Metasploit as a Command and Control Framework and toolbox for unique payload generation.                                                                                                                    |
| `Nishang`                         | [Source](https://github.com/samratashok/nishang) Nishang is a framework collection of Offensive PowerShell implants and scripts. It includes many utilities that can be useful to any pentester.                                                                                                                  |
| `Darkarmour`                      | [Source](https://github.com/bats3c/darkarmour) Darkarmour is a tool to generate and utilize obfuscated binaries for use against Windows hosts.                                                                                                                                                                    |
| my notes                          | [[windows\| => check here]]                                                                                                                                                                                                                                                                                       |



#### Payload Transfer and Execution:

Besides the vectors of web-drive-by, phishing emails, or dead drops, Windows hosts can provide us with several other avenues of payload delivery. The list below includes some helpful tools and protocols for use while attempting to drop a payload on a target.

- `Impacket`: [Impacket](https://github.com/SecureAuthCorp/impacket) is a toolset built in Python that provides us with a way to interact with network protocols directly. Some of the most exciting tools we care about in Impacket deal with `psexec`, `smbclient`, `wmi`, Kerberos, and the ability to stand up an SMB server.
- [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Download%20and%20Execute.md): is a great resource to find quick oneliners to help transfer files across hosts expediently.
- `SMB`: SMB can provide an easy to exploit route to transfer files between hosts. This can be especially useful when the victim hosts are domain joined and utilize shares to host data. We, as attackers, can use these SMB file shares along with C$ and admin$ to host and transfer our payloads and even exfiltrate data over the links.
- `Remote execution via MSF`: Built into many of the exploit modules in Metasploit is a function that will build, stage, and execute the payloads automatically.
- `Other Protocols`: When looking at a host, protocols such as FTP, TFTP, HTTP/S, and more can provide you with a way to upload files to the host. Enumerate and pay attention to the functions that are open and available for use.
