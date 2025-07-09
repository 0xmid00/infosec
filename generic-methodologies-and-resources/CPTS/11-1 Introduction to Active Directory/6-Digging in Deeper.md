# Security in Active Directory

Active Directory is designed for easy access and central management, but it lacks built-in security by default.  
It prioritizes Availability and Confidentiality, making it vulnerable without proper hardening.  
Security can be improved by enabling Microsoft features and applying general hardening practices.
## General Active Directory Hardening Measures
The [Microsoft Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement.
**LAPS**  
Local Administrator Password Solution (LAPS) rotates local admin passwords on a set schedule (e.g., every 12 or 24 hours). It helps reduce the impact of host compromise when combined with other security measures.

**Audit Policy Settings (Logging and Monitoring)**  
Logging and monitoring are essential to detect suspicious activities like unauthorized account creation, password changes, password spraying, and Kerberos attacks.

#### Group Policy Security Settings

As mentioned earlier in the module, Group Policy Objects (GPOs) are virtual collections of policy settings that can be applied to specific users, groups, and computers at the OU level. These can be used to apply a wide variety of [security policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-policy-settings) to help harden Active Directory. The following is a non-exhaustive list of the types of security policies that can be applied:

- [Account Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-policies) - Manage how user accounts interact with the domain. These include the password policy, account lockout policy, and Kerberos-related settings such as the lifetime of Kerberos tickets
    
- [Local Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-options) - These apply to a specific computer and include the security event audit policy, user rights assignments (user privileges on a host), and specific security settings such as the ability to install drivers, whether the administrator and guest accounts are enabled, renaming the guest and administrator accounts, preventing users from installing printers or using removable media, and a variety of network access and network security controls.
    
- [Software Restriction Policies](https://docs.microsoft.com/en-us/windows-server/identity/software-restriction-policies/software-restriction-policies) - Settings to control what software can be run on a host.
    
- [Application Control Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control) - Settings to control which applications can be run by certain users/groups. This may include blocking certain users from running all executables, Windows Installer files, scripts, etc. Administrators use [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview) to restrict access to certain types of applications and files. It is not uncommon to see organizations block access to CMD and PowerShell (among other executables) for users that do not require them for their day-to-day job. These policies are imperfect and can often be bypassed but necessary for a defense-in-depth strategy.
    
- [Advanced Audit Policy Configuration](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/secpol-advanced-security-audit-policy-settings) - A variety of settings that can be adjusted to audit activities such as file access or modification, account logon/logoff, policy changes, privilege usage, and more.


**Update Management (SCCM/WSUS)**  
Use [WSUS](https://docs.microsoft.com/en-us/windows-server/administration/windows-server-update-services/get-started/windows-server-update-services-wsus) or SCCM for automated patching. Manual patching risks delays and missed systems.

**Group Managed Service Accounts (gMSA)**  
gMSAs offer secure, automated password management for services using long, rotated passwords across hosts without manual interaction.

**Security Groups**  
[Security groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#active-directory-default-security-groups-by-operating-system-version) simplify permission assignment. Use them for group-based resource access and privilege management.

**Account Separation**  
Admins should use separate accounts for admin tasks (e.g., `sjones_adm`) and daily work (`sjones`). Admin accounts should only be used on [secure hosts](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-secure-administrative-hosts) with unique passwords.

**Password Policies + MFA**  
Use long passphrases or random passwords via an enterprise manager. Avoid weak but complex-looking passwords like `Welcome1`. Block common patterns via filters. Use MFA—especially for Remote Desktop.

**Limiting Domain Admin Usage**  
Domain Admins should **only** log into Domain Controllers—not workstations or servers—to reduce password exposure risk.

**Removing Stale Users and Objects**  
Regularly audit and remove unused or old accounts to minimize attack vectors from forgotten, weak, or unnecessary accounts.

**Auditing Access and Privileges**  
Review and minimize user access, especially Domain/Enterprise Admin memberships. Ensure users only have what they need.

**Audit Policies & Logging**  
Monitor for anomalies (e.g., failed logins, Kerberoasting). Use Microsoft’s [Audit Policy Recommendations](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) to improve visibility and detect threats.

**Restricted Groups**  
[Restricted Groups](https://social.technet.microsoft.com/wiki/contents/articles/20402.active-directory-group-policy-restricted-groups.aspx) enforce membership in sensitive groups (e.g., local Admins, Domain Admins) via GPO, helping reduce lateral movement risk.

**Limiting Server Roles**  
Avoid installing roles like IIS on Domain Controllers. Separate roles across hosts (e.g., Exchange ≠ Web server ≠ DB server) to reduce the attack surface.

**Local Admin and RDP Rights**  
Restrict local admin and RDP rights. Avoid giving Domain Users group local admin access, as this allows low-privilege users to escalate and dump credentials.

# Examining Group Policy

Group Policy is a powerful Windows feature used by administrators to manage user and computer settings across a domain, especially within Active Directory environments. It plays a critical role in configuring systems, applications, and enforcing security policies as part of a defense-in-depth strategy. While it's essential for strengthening domain security, Group Policy can also be abused by attackers for lateral movement, privilege escalation, persistence, or even full domain compromise. Understanding its functionality is crucial for defenders and penetration testers alike to detect and prevent potential misconfigurations and attacks.

## Group Policy Objects (GPOs)

A Group Policy Object (GPO) is a virtual collection of settings used to control the configuration of user and computer environments in a Windows domain. GPOs are powerful tools for managing system behavior, enforcing security, and applying configuration at scale across Active Directory.
- GPOs can be linked to a specific OU, domain,containers , or site
- GPOs can be applied to individual users, hosts
## Example GPOs
Some examples of things we can do with GPOs may include:

- Establishing different password policies for service accounts, admin accounts, and standard user accounts using separate GPOs
- Preventing the use of removable media devices (such as USB devices)
- Enforcing a screensaver with a password
- Restricting access to applications that a standard user may not need, such as cmd.exe and PowerShell
- Enforcing audit and logging policies
- Blocking users from running certain types of programs and scripts
- Deploying software across a domain
- Blocking users from installing unapproved software
- Displaying a logon banner whenever a user logs into a system
- Disallowing LM hash usage in the domain
- Running scripts when computers start/shutdown or when a user logs in/out of their machine
#### RDP GPO Settings
Group Policy settings for Remote Desktop (RDP) and other configurations follow a **hierarchical order** in Active Directory, known as the **Order of Precedence**. This determines which policy takes effect when multiple GPOs apply the same setting.

| **Level**                    | **Description**                                                                                                                                               |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Local Group Policy**       | Policies set directly on the individual host. These are overridden by any domain-level policies.                                                              |
| **Site Policy**              | Policies applied based on the computer’s physical location (IP subnet). Useful for location-specific settings like printers or access restrictions.           |
| **Domain-wide Policy**       | Policies that apply to all users and computers across the domain. Common for enforcing global rules like password complexity or login banners.                |
| **Organizational Unit (OU)** | Policies that apply to specific users or computers within an OU. Ideal for role-specific settings (e.g., HR drive mappings or IT admin privileges).           |
| **Nested OU Policies**       | More specific policies for objects within sub-OUs. Useful for fine-tuning access and applying unique rules (e.g., tighter AppLocker rules for Security Team). |
-  **Default Domain Policy** Auto-created, linked to domain, applies to all users/computers, used for global settings.  **It has the highest precedence of all GPOs**

-  **Default Domain Controllers Policy**  Auto-created, linked to DCs, sets default security/auditing, customizable.

## GPO Order of Precedence

GPOs are applied in this order: Local → Site → Domain → OU → Child OU (last applied has highest precedence).  
If there's a conflict between Computer and User settings in a GPO, **Computer Configuration** always takes priority.

![[Pasted image 20250705174558.png]]
**1. GPO Processing Order (Highest Precedence Last):**  
- **Local → Site → Domain → OU → Child OU**

**2. Internal GPO Precedence:**  
 - **Computer Configuration** takes priority over **User Configuration** (even though User is processed last).

**3. Link Order:**  
- When multiple GPOs are linked to the same OU: GPO with **Link Order = 1** is applied **last** → has **highest precedence**.

**4. Enforced Option:**  (Used to **prevent lower-level GPOs from overriding** this GPO.)

- **4.1** If in a GPO Within OU is **Enforced** policy settings in GPOs linked to lower OU **cannot be overridden** the Enforced settings
- **4.2** If a domain-level GPO is **Enforced**, it applies to all OUs and **cannot be overridden**.
    
- **4.3** If **Default Domain Policy** is Enforced, it **overrides all other GPOs**, regardless of level.
    

**5. Block Inheritance:**  
- **5.1** if the options **Block Inheritance** set on an OU, then policies higher up (such as at the domain level) will NOT be applied to this OU
- **5.2** If a higher-level GPO is **Enforced**, it will **override Block Inheritance**.
  
  ## Group Policy Refresh Frequency
When a new GPO is created, the settings are not automatically applied right away. Windows performs periodic Group Policy updates, which by default is done every 90 minutes with a randomized offset of +/- 30 minutes for users and computers. to force/change this: 

**1-currently applied Group Policy with powershell**
```powershell
gpupdate /force
```
**2- Change Refresh Interval:**  
Go to:  
**Computer Configuration → Policies → Administrative Templates → System → Group Policy → Set Group Policy refresh interval for computers**

## Security Considerations of GPOs
