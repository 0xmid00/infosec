# User and Machine Accounts
User accounts allow people and programs to log into systems and access resources based on permissions. These accounts can exist locally or within Active Directory (AD). When a user logs in, a **token** is created to represent their identity and rights. Users are often grouped to simplify permission management. Active Directory is central to **user account** management and typically provides one or more accounts per person depending on their role. In addition to user accounts, **service accounts** exist for running background applications. Some accounts may be disabled rather than deleted for audit reasons.such as `FORMER EMPLOYEES` that will contain many deactivated accounts

Accounts can be granted varying levels of access, from basic read-only to full administrative control. **Misconfigurations** are common and can pose serious security risks. User accounts are a major focus in security assessments, as they represent a large attack surface and are often vulnerable due to weak passwords, poor practices, or excessive privileges. Organizations must implement strong policies and layered security to reduce these risks.
## Local Accounts
Local accounts are stored on individual machines and have rights only on that specific system. They are not valid across the domain. These accounts are considered security principals and are used to manage access to resources on standalone hosts.

Windows systems come with several default local accounts:

- **Administrator**: The first account created during Windows setup with full control over the system. It cannot be deleted or locked, but it can be disabled or renamed. Modern systems disable this account by default.
    
- **Guest**: A limited-access account intended for temporary use. It is disabled by default and poses a security risk if enabled.
    
- **SYSTEM**: A built-in service account used by the operating system for core functions. It has the highest level of permissions on the system but does not appear in user management tools and cannot be added to groups.
    
- **Network Service**: Used by services to run with limited local privileges but can authenticate to remote services with credentials.
    
- **Local Service**: Also used for running services but with minimal privileges and only anonymous access to the network.
    
## Domain Users
Domain user accounts are managed by the domain and can access resources like file servers, printers, and intranet systems based on assigned permissions or group memberships. Unlike local users, domain users can log in to any machine within the domain.

A key account in Active Directory is the **KRBTGT** account. It is a special built-in account used by the **Key Distribution Service** to handle authentication within the domain. This account is critical for Kerberos operations and is often targeted by attackers. If compromised, it can be used for privilege escalation and persistence through techniques like the **Golden Ticket** attack, granting the attacker unrestricted domain access.
### User Naming Attributes
used to identify user objects:

|||
|---|---|
|`UserPrincipalName` (UPN)|This is the primary logon name for the user. By convention, the UPN uses the email address of the user.|
|`ObjectGUID`|This is a unique identifier of the user. In AD, the ObjectGUID attribute name never changes and remains unique even if the user is removed.|
|`SAMAccountName`|This is a logon name that supports the previous version of Windows clients and servers.|
|`objectSID`|The user's Security Identifier (SID). This attribute identifies a user and its group memberships during security interactions with the server.|
|`sIDHistory`|`sIDHistory` stores the user's previous SID after a domain migration, allowing the new account with a different `objectSID` to retain access to resources in the old domain.|
#### Common User Attributes

```bash
Get-ADUser -Identity htb-student

DistinguishedName : CN=htb student,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
Enabled           : True
GivenName         : htb
Name              : htb student
ObjectClass       : user
ObjectGUID        : aa799587-c641-4c23-a2f7-75850b4dd7e3
SamAccountName    : htb-student
SID               : S-1-5-21-3842939050-3880317879-2865463114-1111
Surname           : student
UserPrincipalName : htb-student@INLANEFREIGHT.LOCAL
```
For a deeper look at user object attributes, check out this [page](https://docs.microsoft.com/en-us/windows/win32/ad/user-object-attributes). Many attributes can be set for any object in AD.

## Domain-joined vs. Non-Domain-joined Machines

- **Domain-Joined Machines** are part of an Active Directory (AD) domain, allowing centralized management via a Domain Controller (DC). They receive configurations through Group Policy and enable users to access resources across any domain-joined host—ideal for enterprise environments.
    
- **Non-Domain-Joined Machines** (i.e., workgroup computers) are independently managed without centralized policies. Resource sharing is limited to the local network, and user accounts are local to each machine—more suitable for home or small businesses.
> **NT AUTHORITY\SYSTEM** access on a domain-joined host lets you interact with AD as the **computer account** (e.g., HOSTNAME$), which has rights similar to a **low-privileged domain user**. This allows domain enumeration and recon without needing user credentials—making it a strong starting point for AD attacks.


---
# Active Directory Groups

Groups in Active Directory are used to organize users and assign permissions collectively, making them key for access control. They can inadvertently grant excessive privileges if not properly managed, making them a common target for attackers. Organizations often create custom groups in addition to built-in ones, which can lead to complex and unchecked access structures. Regular auditing of groups and their privileges is essential. Unlike groups, Organizational Units (OUs) are used for structuring and managing objects like users and computers, mainly to apply Group Policies and delegate specific admin tasks without broad privileges.
## Types of Groups
Groups in Active Directory help manage users, computers, and contacts efficiently by simplifying permission assignment and resource access. Instead of assigning access individually, admins can use groups to grant permissions collectively, making management and auditing easier.
There are **two main group types**:
- **Security Groups**: Used to assign permissions and access rights to resources like file shares or printers.
    
- **Distribution Groups**: Used for email distribution (e.g., in Microsoft Exchange); **cannot** assign permissions.
## Group Scopes

**Domain Local Group**  
- Contains members from any domain  
- Used only in the domain it was created
- nested into other local groups but `NOT` within global groups **in same domain** 

**Global Group**  
- Contains members from the same domain  
- Used in any domain
- nested into other global groups and local groups **in same domain**.

**Universal Group**  
- Contains members from any domain  
- Used in any domain
- nested into Other **Universal** and Domain Local groups in **any domain**

**AD Group Scope Example:**
```bash
Get-ADGroup  -Filter * |select samaccountname,groupscope
```
### **Group Scope Conversion Rules**

- **Global → Universal**: Only if not in another Global group
    
- **Domain Local → Universal**: Only if it doesn’t contain other Domain Local groups
    
- **Universal → Domain Local**: ✅ No restrictions
    
- **Universal → Global**: Only if it doesn’t contain other Universal groups

### Summary – Built-in vs. Custom Groups

Active Directory includes several built-in security groups with a Domain Local scope, mainly for administrative tasks. These groups typically allow only user accounts and do not support nesting. For example, **Domain Admins** is a built-in **Global group** limited to users from its own domain. To give admin rights across domains, an external user must be added to the **Administrators group**, a **Domain Local group**.

Organizations often create **custom groups** for their specific needs. Additionally, installing services like **Microsoft Exchange** automatically creates new, often privileged, security groups that must be managed carefully to avoid security risks.

## Nested Group Membership

Nested group membership in Active Directory allows a group to be a member of another group, enabling users to inherit privileges indirectly. For example, a user may receive permissions not from their direct group but from a higher-level group their group is part of. This can lead to unintended privilege escalation and is often hard to detect without deep analysis.

Tools like **BloodHound** help identify such hidden privileges by visually mapping group relationships. For instance, even if **DCorner** is not directly in **Helpdesk Level 1**, they still inherit its privileges through their membership in **Help Desk**, which is nested inside it. This inherited permission (e.g., **GenericWrite** to **Tier 1 Admins**) can allow privilege escalation, such as adding a user to an admin group and gaining local admin rights on domain hosts—making this a common focus in both **penetration testing** and **security audits**.
![[Pasted image 20250704214240.png]]

## Important Group Attributes
- **cn**: The group’s name.
    
- **member**: Lists users/groups in the group.
    
- **groupType**: Indicates the group’s type and scope.
    
- **memberOf**: Shows groups this group belongs to (nested).
    
- **objectSid**: The unique security identifier for the group.

# Active Directory Rights and Privileges
- **Rights** grant a users  permissions to `access` an object such as a file.
- **privileges** grant a user or groups  permission to `perform an action` such as run a program. 
## Built-in AD Groups Privileges

AD contains default build-in Groups members powerful rights and privileges which can be abused to escalate privileges within a domain and ultimately gain Domain Admin or SYSTEM privileges on a Domain Controller (DC).

| **Group Name**                     | **Privileges**                                                                                                                                                                      | **Restrictions**                                                                                                                                           | **Abusing / Attack**                                                                        | **Exists / Created When**                                                                                                                                   |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Account Operators                  | Create and modify most types of user and group accountsCan log on locally to domain controllers                                                                                     | Cannot manage the Administrator account or members of the Administrators, Server Operators, Account Operators, Backup Operators, or Print Operators groups | Add rogue users to sensitive groups; manipulate accounts to escalate privileges             | Security group object automatically created in the Builtin container (CN=Builtin,DC=domain) during domain creation                                          |
| Administrators                     | Members have full and unrestricted access to a computer or an entire domain if they are in this group on a Domain Controller.                                                       | None                                                                                                                                                       | Complete domain takeover; compromise of any member gives full domain control                | Security group object automatically created in the Builtin container (CN=Builtin,DC=domain) during domain creation                                          |
| Backup Operators                   | Back up and restore all files on a computer where the user has the privilege, regardless of the file <br><br>log on locally to domain controllersShould be considered Domain Admins | Cannot change file ownership or security settings                                                                                                          | Can dump shadow copies of the SAM or NTDS database for credential extraction                | Security group object automatically created in the Builtin container (CN=Builtin,DC=domain) during domain creation                                          |
| DnsAdmins                          | Manage DNS zones and records                                                                                                                                                        | No specific restrictions unless locked down via GPO                                                                                                        | Exploitable via insecure DLL loading or command execution through misconfigured DNS scripts | Security group object created in the Users container (CN=Users,DC=domain) when DNS Server role is installedMembers must be added manually                   |
| Domain Admins                      | Full access to manage all domain resourcesAutomatically part of the Administrators group on all domain-joined machines                                                              | None                                                                                                                                                       | Full domain control; any member has unrestricted access                                     | Security group object automatically created in the Users container (CN=Users,DC=domain) during domain creation                                              |
| Domain Computers                   | apply GPOs and set computer-level permissions                                                                                                                                       | Only includes non-DC machines                                                                                                                              | Can be abused by compromising a trusted computer object or targeting computer-based ACLs    | Computer objects automatically added when a host joins the domainGroup located in the CN=Computers container                                                |
| Enterprise Admins                  | Full control across all domains in the forestCan add domains, trusts, and perform forest-level configuration                                                                        | Exists only in the forest root domain                                                                                                                      | Complete forest compromise if misused                                                       | Security group object automatically created in the Users container (CN=Users,DC=forestroot) during forest root domain creationDefault member: Administrator |
| Event Log Readers                  | Read access to event logs on domain controllers                                                                                                                                     | Cannot write or clear logs                                                                                                                                 | Can be used to stealthily monitor domain controller activity                                | Security group object automatically created in the Builtin container (CN=Builtin,DC=domain) when host is promoted to a DC                                   |
| Group Policy Creator Owners        | Create, edit, and delete Group Policy Objects (GPOs)                                                                                                                                | Cannot link GPOs unless delegated                                                                                                                          | GPO abuse to push malware, persistence scripts, or misconfigurations                        | Security group object automatically created in the Users container (CN=Users,DC=domain) during domain creationInitially contains the domain creator         |
| Hyper-V Administrators             | Complete control over virtual machines and Hyper-V settingsShould be considered Domain Admins if DCs are virtualized                                                                | Local group only on Hyper-V host                                                                                                                           | Can access virtual DCs, extract VHDs, or escalate by controlling guest machines             | Security group object created in the local SAM of a system when the Hyper-V role is installedMembers must be added manually                                 |
| IIS_IUSRS                          | Used by IIS processes and application pools for resource isolation and access                                                                                                       | Cannot be used for elevation by default                                                                                                                    | May be abused if an IIS process is vulnerable or misconfigured                              | Security group object created in the local SAM of a system when the IIS role is installed                                                                   |
| Pre-Windows 2000 Compatible Access | Allows older systems to access AD without full credentials                                                                                                                          | Should be empty in modern environments                                                                                                                     | Allows unauthenticated users to query AD info (enumeration)                                 | Security group object automatically created in the Users container (CN=Users,DC=domain) during domain creation                                              |
| Print Operators                    | Manage, share, and delete printers connected to DCsCan log on locally to domain controllers                                                                                         | Cannot modify AD permissions or group memberships                                                                                                          | Load a malicious printer driver and gain SYSTEM-level code execution                        | Security group object automatically created in the Builtin container (CN=Builtin,DC=domain) during domain creation                                          |
| Protected Users                    | Enforces strict credential protections to reduce exposure (no cached creds, no NTLM, etc.)                                                                                          | Not supported by all services                                                                                                                              | Limits pass-the-hash and ticket-granting ticket abuse                                       | Security group object created in the Users container (CN=Users,DC=domain) when manually configured by an admin                                              |
| Read-only Domain Controllers       | Holds all RODCs for replication and delegation                                                                                                                                      | RODCs cannot make changes to AD                                                                                                                            | Exposed credentials if not properly filtered                                                | Computer object created when a RODC is promoted; added to this group automatically                                                                          |
| Remote Desktop Users               | Allows members to connect via Remote Desktop Protocol (RDP)                                                                                                                         | Group cannot be renamed, moved, or deleted                                                                                                                 | Enables lateral movement via RDP if access is granted                                       | Security group object automatically created in the local SAM of every system                                                                                |
| Schema Admins                      | Modify the Active Directory schema (structure of objects in AD)                                                                                                                     | Exists only in forest root domain; high-risk group                                                                                                         | Schema modification for backdoors or persistence                                            | Security group object automatically created in the Users container (CN=Users,DC=forestroot) during forest root domain creationDefault member: Administrator |
| Server Operators                   | Modify services, access shares, shut down and restart DCs                                                                                                                           | Cannot change AD permissions or user rights                                                                                                                | Service abuse or lateral movement through SMB or backup operations                          | Security group object automatically created in the Builtin container (CN=Builtin,DC=domain) during domain creationBy default, has no members                |

**example : Extract Group details command:**
```powershell
Get-ADGroup -Identity "Server Operators" -Properties *
Get-ADGroup -Identity "Domain Admins" -Properties * | select DistinguishedName,GroupCategory,GroupScope,Name,Members
```

## User Rights Assignment
Depending on their current group membership, and other factors such as privileges that administrators can assign via Group Policy (GPO), users can have various rights assigned to their account. This Microsoft article on [User Rights Assignment](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment) provides a detailed explanation of each of the user rights that can be set in Windows

Not all rights are critical from a security perspective, but some can unintentionally lead to privilege escalation or sensitive access. For instance, if an attacker gains write access to a GPO linked to an OU with controlled users, tools like [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) can be used to assign elevated rights. This can enable further actions to escalate privileges or expand domain access.

| **Privilege**                   | **Description**                                                                                                                                                                                                                                                                                   |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SeRemoteInteractiveLogonRight` | This privilege could give our target user the right to log onto a host via Remote Desktop (RDP), which could potentially be used to obtain sensitive data or escalate privileges.                                                                                                                 |
| `SeBackupPrivilege`             | This grants a user the ability to create system backups and could be used to obtain copies of sensitive system files that can be used to retrieve passwords such as the SAM and SYSTEM Registry hives and the NTDS.dit Active Directory database file.                                            |
| `SeDebugPrivilege`              | This allows a user to debug and adjust the memory of a process. With this privilege, attackers could utilize a tool such as [Mimikatz](https://github.com/ParrotSec/mimikatz) to read the memory space of the Local System Authority (LSASS) process and obtain any credentials stored in memory. |
| `SeImpersonatePrivilege`        | This privilege allows us to impersonate a token of a privileged account such as `NT AUTHORITY\SYSTEM`. This could be leveraged with a tool such as JuicyPotato, RogueWinRM, PrintSpoofer, etc., to escalate privileges on a target system.                                                        |
| `SeLoadDriverPrivilege`         | A user with this privilege can load and unload device drivers that could potentially be used to escalate privileges or compromise a system.                                                                                                                                                       |
| `SeTakeOwnershipPrivilege`      | This allows a process to take ownership of an object. At its most basic level, we could use this privilege to gain access to a file share or a file on a share that was otherwise not accessible to us.                                                                                           |

There are many techniques available to abuse user rights detailed [here](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e) and [here](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.html). Though outside the scope of this module.

## Viewing a User's Privileges
```powershell
whoami /priv #  Non-Elevated  = less Rights => SeShutdownPrivilege
whoami /priv #  Elevated (bypass UAC)  = full Rights  => SeBackupPrivilege
```
User rights increase based on the groups they are placed in or their assigned privileges 
example: 
Members of the **Backup Operators** group have some powerful rights, but **UAC restricts** their use in standard sessions. While `SeBackupPrivilege` isn't enabled by default in a standard console session , they do have `SeShutdownPrivilege`, allowing them to log onto a domain controller locally (not remotely via RDP or WinRM) and **shut down domain controllers locally**. This doesn't grant access to sensitive data but can cause **massive service interruption** to services.
>log onto a domain controller locally (not remotely via RDP or WinRM).

