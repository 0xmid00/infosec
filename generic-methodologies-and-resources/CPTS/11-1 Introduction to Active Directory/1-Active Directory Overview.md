## Why Active Directory?
```BASH
## What is Active Directory?
  # AD is a directory service for Windows networks.
  # Provides centralized management for users, computers, groups, policies, file shares, etc.
  # Offers authentication and authorization functions.
  # Built on LDAP, with hierarchy and scalability.

## Why It Matters
  # AD is not secure by default; easy to misconfigure.
  # Even standard domain users can enumerate domain objects.
  # AD is essentially a read-only database to all domain users.

## examples Security Risks
  # Standard domain access is often enough for full domain takeover
  noPAC (2021)
  PrintNightmare (CVE-2021-34527)
  Zerologon (CVE-2020-1472).

## History of Active Directory
  Windows Server 2000 # First AD integration
  Server 2003 # Added Forests (multi-domain grouping)
  Server 2008 # ADFS (Single Sign-On)
  Server 2016
    # Cloud migration capabilities
    # Group Managed Service Accounts (gMSA) – mitigates Kerberoasting
    # Azure AD Connect: For Office 365 SSO/cloud integration
```

##  Active Directory Research Over the Years
```bash
## AD Attacks & Tools Timeline

2013  
[Tool] Responder - Captures hashes via LLMNR/NBT-NS poisoning to perform MITM attacks

2014  
[Tool] PowerView.ps1 - PowerSploit script for AD enumeration and privilege hunting  
[Bug] Kerberoasting by Tim Medin - Extracts service account hashes from Kerberos tickets

2015  
[Tool] PowerShell Empire - Post-exploitation framework with AD attack modules  
[Bug] DCSync (Mimikatz) - Simulates a DC to extract user password data via replication  
[Tool] CrackMapExec - Swiss army knife for network pentesting and AD interaction  
[Blog] Kerberos Delegation abuse guide by Sean Metcalf - https://adsecurity.org/?p=1667  
[Tool] Impacket - Python library with tools for SMB, Kerberos, and NTLM attacks

2016  
[Tool] BloodHound - Visualizes AD trust relationships to find privilege escalation paths

2017  
[Bug] ASREPRoast - Attacks accounts with no Kerberos pre-auth to get crackable hashes  
[Talk] "ACE Up the Sleeve" - AD ACL abuse techniques by harmj0y & _wald0 - https://www.slideshare.net/harmj0y/ace-up-the-sleeve  
[Blog] Trust attacks blog by harmj0y - Explores attacking domain/forest trusts - https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/

2018  
[Bug] Printer Bug - Forces authentication via MS-RPRN to capture NTLM hashes - https://github.com/leechristensen/SpoolSample  
[Tool] Rubeus - Kerberos abuse toolkit for ticket extraction, forging, and reuse  
[Blog] Forest trust abuse guide - harmj0y shows cross-forest attack paths - https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/  
[Bug] DCShadow - Creates fake DC to push malicious AD changes - https://www.dcshadow.com  
[Tool] PingCastle - Generates detailed AD security reports to identify weaknesses

2019  
[Talk] Kerberoasting Revisited - New attack paths using constrained delegation - DerbyCon by harmj0y  
[Blog] RBCD abuse by Elad Shamir - Exploiting resource-based constrained delegation - https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html  
[Tool] Empire 3.0 - Revived version in Python3 by BC Security - https://github.com/BC-SECURITY/Empire

2020  
[Bug] ZeroLogon - Exploits Netlogon flaw to take over any unpatched DC - https://blog.malwarebytes.com/exploits-and-vulnerabilities/2021/01/the-story-of-zerologon/

2021  
[Bug] PrintNightmare - RCE via Windows Print Spooler to gain SYSTEM access - https://en.wikipedia.org/wiki/PrintNightmare  
[Bug] Shadow Credentials - Abuse of key trust mapping to impersonate users/computers - https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab  
[Bug] noPac - Combines two bugs to escalate from user to Domain Admin - https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware

```
