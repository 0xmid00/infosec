# 1- Hardening Active Directory
## Step One: Document and Audit
An audit of everything listed below should be done annually, if not every few months:
#### Things To Document and Track

- `Naming conventions of OUs, computers, users, groups`
- `DNS, network, and DHCP configurations`
- `An intimate understanding of all GPOs and the objects that they are applied to`
- `Assignment of FSMO roles`
- `Full and current application inventory`
- `A list of all enterprise hosts and their location`
- `Any trust relationships we have with other domains or outside entities`
- `Users who have elevated permissions`
## People, Processes, and Technology
- The organization should have a strong password policy, with a password filter that disallows the use of common words (i.e., welcome, password, names of months/days/seasons, and the company name). If possible, an enterprise password manager should be used to assist users with choosing and using complex passwords.
- Rotate passwords periodically for **all** service accounts.
- Disallow local administrator access on user workstations unless a specific business need exists.
- Disable the default `RID-500 local admin` account and create a new admin account for administration subject to LAPS password rotation.
- Implement split tiers of administration for administrative users. Too often, during an assessment, you will gain access to Domain Administrator credentials on a computer that an administrator uses for all work activities.
- Clean up privileged groups. `Does the organization need 50+ Domain/Enterprise Admins?` Restrict group membership in highly privileged groups to only those users who require this access to perform their day-to-day system administrator duties.
- Where appropriate, place accounts in the `Protected Users` group.
- Disable Kerberos delegation for administrative accounts (the Protected Users group may not do this)

### People
- The organization should have a strong password policy, with a password filter that disallows the use of common words (i.e., welcome, password, names of months/days/seasons, and the company name). If possible, an enterprise password manager should be used to assist users with choosing and using complex passwords.
- Rotate passwords periodically for **all** service accounts.
- Disallow local administrator access on user workstations unless a specific business need exists.
- Disable the default `RID-500 local admin` account and create a new admin account for administration subject to LAPS password rotation.
- Implement split tiers of administration for administrative users. Too often, during an assessment, you will gain access to Domain Administrator credentials on a computer that an administrator uses for all work activities.
- Clean up privileged groups. `Does the organization need 50+ Domain/Enterprise Admins?` Restrict group membership in highly privileged groups to only those users who require this access to perform their day-to-day system administrator duties.
- Where appropriate, place accounts in the `Protected Users` group.
- Disable Kerberos delegation for administrative accounts (the Protected Users group may not do this)
### Protected Users Group
This group can be used to restrict what members of this privileged group can do in a domain. Adding users to Protected Users prevents user credentials from being abused if left in memory on a host.

The group provides the following Domain Controller and device protections:

- Group members can not be delegated with constrained or unconstrained delegation.
- CredSSP will not cache plaintext credentials in memory even if Allow delegating default credentials is set within Group Policy.
- Windows Digest will not cache the user's plaintext password, even if Windows Digest is enabled.
- Members cannot authenticate using NTLM authentication or use DES or RC4 keys.
- After acquiring a TGT, the user's long-term keys or plaintext credentials are not cached.
- Members cannot renew a TGT longer than the original 4-hour TTL.
> Note: The Protected Users group can cause unforeseen issues with authentication, which can easily result in account lockouts. An organization should never place all privileged users in this group without staged testing.
### Processes
- Proper policies and procedures for AD asset management.
    - AD host audit, the use of asset tags, and periodic asset inventories can help ensure hosts are not lost.
- Access control policies (user account provisioning/de-provisioning), multi-factor authentication mechanisms.
- Processes for provisioning and decommissioning hosts (i.e., baseline security hardening guideline, gold images)
- AD cleanup policies
    - `Are accounts for former employees removed or just disabled?`
    - `What is the process for removing stale records from AD?`
    - Processes for decommissioning legacy operating systems/services (i.e., proper uninstallation of Exchange when migrating to 0365).
    - Schedule for User, groups, and hosts audit.

### Technology

- Run tools such as BloodHound, PingCastle, and Grouper periodically to identify AD misconfigurations.
- Ensure that administrators are not storing passwords in the AD account description field.
- Review SYSVOL for scripts containing passwords and other sensitive data.
- Avoid the use of "normal" service accounts, utilizing Group Managed (gMSA) and Managed Service Accounts (MSA) where ever possible to mitigate the risk of Kerberoasting.
- Disable Unconstrained Delegation wherever possible.
- Prevent direct access to Domain Controllers through the use of hardened jump hosts.
- Consider setting the `ms-DS-MachineAccountQuota` attribute to `0`, which disallows users from adding machine accounts and can prevent several attacks such as the noPac attack and Resource-Based Constrained Delegation (RBCD)
- Disable the print spooler service wherever possible to prevent several attacks
- Disable NTLM authentication for Domain Controllers if possible
- Use Extended Protection for Authentication along with enabling Require SSL only to allow HTTPS connections for the Certificate Authority Web Enrollment and Certificate Enrollment Web Service services
- Enable SMB signing and LDAP signing
- Take steps to prevent enumeration with tools like BloodHound
- Ideally, perform quarterly penetration tests/AD security assessments, but if budget constraints exist, these should be performed annually at the very least.
- Test backups for validity and review/practice disaster recovery plans.
- Enable the restriction of anonymous access and prevent null session enumeration by setting the `RestrictNullSessAccess` registry key to `1` to restrict null session access to unauthenticated users.

## Protections By Section
As a different look at this, we have broken out the significant actions by section and correlated controls based on the TTP and a MITRE tag. Each tag corresponds with a section of the [Enterprise ATT&CK Matrix](https://attack.mitre.org/tactics/enterprise/) found here. Any tag marked as `TA` corresponds to an overarching tactic, while a tag marked as `T###` is a technique found in the matrix under tactics.

| **TTP**                    | **MITRE Tag** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| -------------------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `External Reconnaissance`  | `T1589`       | This portion of an attack is extremely hard to detect and defend against. An attacker does not have to interact with your enterprise environment directly, so it's impossible to tell when it is happening. What can be done is to monitor and control the data you release publically to the world. Job postings, documents (and the metadata left attached), and other open information sources like BGP and DNS records all reveal something about your enterprise. Taking care to `scrub` documents before release can ensure an attacker cannot glean user naming context from them as an example. The same can be said for not providing detailed information about tools and equipment utilized in your networks via job postings.                                                                                                                                                                                                                        |
| `Internal Reconnaissance`  | `T1595`       | For reconnaissance of our internal networks, we have more options. This is often considered an active phase and, as such, will generate network traffic which we can monitor and place defenses based on what we see. `Monitoring network traffic` for any suspicious bursts of packets of a large volume from any one source or several sources can be indicative of scanning. A properly configured `Firewall` or `Network Intrusion Detection System` (`NIDS`) will spot these trends quickly and alert on the traffic. Depending on the tool or appliance, it may even be able to add a rule blocking traffic from said hosts proactively. The utilization of network monitoring coupled with a SIEM can be crucial to spotting reconnaissance. Properly tuning the Windows Firewall settings or your EDR of choice to not respond to ICMP traffic, among other types of traffic, can help deny an attacker any information they may glean from the results. |
| `Poisoning`                | `T1557`       | Utilizing security options like `SMB message signing` and `encrypting traffic` with a strong encryption mechanism will go a long way to stopping poisoning & man-in-the-middle attacks. SMB signing utilizes hashed authentication codes and verifies the identity of the sender and recipient of the packet. These actions will break relay attacks since the attacker is just spoofing traffic.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `Password Spraying`        | `T1110/003`   | This action is perhaps the easiest to defend against and detect. Simple logging and monitoring can tip you off to password spraying attacks in your network. Watching your logs for multiple attempts to login by watching `Event IDs 4624` and `4648` for strings of invalid attempts can tip you off to password spraying or brute force attempts to access the host. Having strong password policies, an account lockout policy set, and utilizing two-factor or multi-factor authentication can all help prevent the success of a password spray attack. For a deeper look at the recommended policy settings, check out this [article](https://www.netsec.news/summary-of-the-nist-password-recommendations-for-2021/) and the [NIST](https://pages.nist.gov/800-63-3/sp800-63b.html) documentation.                                                                                                                                                        |
| `Credentialed Enumeration` | `TA0006`      | There is no real defense you can put in place to stop this method of attack. Once an attacker has valid credentials, they effectively can perform any action that the user is allowed to do. A vigilant defender can detect and put a stop to this, however. Monitoring for unusual activity such as issuing commands from the CLI when a user should not have a need to utilize it. Multiple RDP requests sent from host to host within the network or movement of files from various hosts can all help tip a defender off. If an attacker manages to acquire administrative privileges, this can become much more difficult, but there are network heuristics tools that can be put in place to analyze the network constantly for anomalous activity. Network segmentation can help a lot here.                                                                                                                                                              |
| `LOTL`                     | N/A           | It can be hard to spot an attacker while they are utilizing the resources built-in to host operating systems. This is where having a `baseline of network traffic` and `user behavior` comes in handy. If your defenders understand what the day-to-day regular network activity looks like, you have a chance to spot the abnormal. Watching for command shells and utilizing a properly configured `Applocker policy` can help prevent the use of applications and tools users should not have access to or need.                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `Kerberoasting`            | `T1558/003`   | Kerberoasting as an attack technique is widely documented, and there are plenty of ways to spot it and defend against it. The number one way to protect against Kerberoasting is to `utilize a stronger encryption scheme than RC4` for Kerberos authentication mechanisms. Enforcing strong password policies can help prevent Kerberoasting attacks from being successful. `Utilizing Group Managed service accounts` is probably the best defense as this makes Kerberoasting no longer possible. Periodically `auditing` your users' account permissions for excessive group membership can be an effective way to spot issues.                                                                                                                                                                                                                                                                                                                              |

#### MITRE ATT&CK Breakdown
![[Pasted image 20250906143726.png]]
The MITRE ATT&CK framework organizes attacker behaviors into **Tactics** (high-level goals) and **Techniques** (specific methods). For example, **Kerberoasting** is part of the **Credential Access** tactic (**TA0006**) and falls under **Steal or Forge Kerberos Tickets** (**T1558**), with its own sub-technique **T1558.003**. The framework page explains the technique, real-world examples, mitigations, detections, and references. This structure (TA0006/T1558.003) shows how tactics and techniques are related and is a helpful way to research attack methods.


# 2- Additional AD Auditing Techniques
We also cover **AD auditing** to give customers clear data on potential issues, helping them prove problems, secure support, and plan fixes. The tools here provide visualizations and reports for this purpose.
## Creating an AD Snapshot with Active Directory Explorer
[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) is part of the Sysinternal Suite and is described as:
AD Explorer is a tool to **browse, edit, and search Active Directory**, take **snapshots** for offline viewing, and compare changes in objects, attributes, and permissions.

When we first load the tool, we are prompted for login credentials or to load a previous snapshot. We can log in with any valid domain user.
#### Logging in with AD Explorer
![[Pasted image 20250906144500.png]]
#### Browsing AD with AD Explorer
![[Pasted image 20250906144541.png]]
#### Creating a Snapshot of AD with AD Explorer
To take a snapshot of AD, go to File --> `Create Snapshot` and enter a name for the snapshot. Once it is complete, we can move it offline for further analysis.
![[Pasted image 20250906144621.png]]

## PingCastle
[PingCastle](https://www.pingcastle.com/documentation/) is an AD security assessment tool that maps your domain, builds a host inventory, and provides a detailed security report with [Capability Maturity Model Integration](https://en.wikipedia.org/wiki/Capability_Maturity_Model_Integration) (CMMI) based scoring, unlike tools like PowerView or BloodHound that focus mainly on enumeration.

>Note: If you are having issues with starting the tool, please change the date of the system to a date before 31st of July 2023 using the Control Panel (Set the time and date).

#### Viewing the PingCastle Help Menu
```powershell
PingCastle.exe --help
```
#### Running PingCastle
```powershell
#### run PingCastle Interactive Terminal User Interface (`TUI`).
.\PingCastle.exe

# The default option is the healthcheck run, which will establish a baseline overview of the domain
1-healthcheck-Score the risk of a domain

# Scanner Options
4-scanner    -Perform specific security checks on workstations
  1-aclcheck                                                  9-oxidbindings
  2-antivirus                                                 a-remote
  3-computerversion                                           b-share
  4-foreignusers                                              c-smb
  5-laps_bitlocker                                            d-smb3querynetwork
  6-localadmin                                                e-spooler
  7-nullsession                                               f-startup
  8-nullsession-trust                                         g-zerologon
  0-Exit 
  
# Run All Scanners Automatically  
.\PingCastle.exe --scanner
```
Now that we understand how it works and how to start scans, let's view the report.
#### Viewing The Report
Throughout the report, there are sections such as domain, user, group, and trust information and a specific table calling out "anomalies" or issues that may require immediate attention. We will also be presented with the domain's overall risk score.
![[Pasted image 20250906145941.png]]

## Group Policy
With group policy being a large portion of how AD user and computer management is done, it's only logical that we would want to audit their settings and highlight any potential holes. `Group3r` is an excellent tool for this.
### Group3r
[Group3r](https://github.com/Group3r/Group3r) is a tool purpose-built to find vulnerabilities in Active Directory associated Group Policy. Group3r must be run from a domain-joined host with a domain user (it does not need to be an administrator), or in the context of a domain user (i.e., using `runas /netonly`).
#### Group3r Basic Usage
```powershell
group3r.exe -f <filepath-name.log> 
```
#### Reading Output

![[Pasted image 20250906151345.png]]
n Group3r’s output, **indentation shows levels**:
- **No indent** = GPO name
- **One indent** = Policy setting
- **Two indents** = Finding or detail
  >Indentation is simply **spaces or tabs at the start of a line** to show hierarchy (levels of detail). Think of it like a folder tree
#### Group3r Finding
- **What was checked** (policy or registry setting, Privilege Name)
- **Who has the privilege/setting** (Trustee)
- **Severity** (Green/Yellow/Red)
- **Reason** (why it’s flagged)
- **Detail** (extra info, like SIDs or accounts)
![[Pasted image 20250906152649.png]]
`SeAssignPrimaryTokenPrivilege` is flagged because it lets accounts assign tokens to processes, which attackers could abuse for privilege escalation.
## ADRecon
Finally, there are several other tools out there that are useful for gathering a large amount of data from AD at once. In an assessment where stealth is not required, it is also worth running a tool like [ADRecon](https://github.com/adrecon/ADRecon) and analyzing the results, just in case all of our enumeration missed something minor that may be useful to us or worth pointing out to our client

#### Running ADRecon
```powershell
.\ADRecon.ps1
  # [*] Output Directory: C:\Tools\ADRecon-Report-20220328092458
ls
#   Directory: C:\Tools\ADRecon-Report-20220328092458
# CSV-Files
#  GPO-Report.htm
# GPO-Report.xml
```
- You get an **HTML report** and a folder of **CSV files**.
- If **Excel is not installed**, it won’t make the Excel report automatically; you’ll just get CSV files.
- To include **Group Policy data**, the computer you run it on must have the **GroupPolicy PowerShell module**.
- You can later create the Excel report on another machine by running ADRecon with the `-GenExcel` switch and pointing it to the saved report folder.

> the  audit a target domain , acquiring more evidence of issues will only serve to: `Make our reporting more convincing and provide the customer with the tools they need to fix & actively secure their domain`.
