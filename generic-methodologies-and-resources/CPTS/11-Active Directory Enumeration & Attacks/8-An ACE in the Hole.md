# Access Control List (ACL) Abuse Primer
## Access Control List (ACL) Overview
`Access Control List` (`ACL`)  in Active Directory is a list of permissions defining which security principals can access an object and what level of access they have. The settings themselves in an ACL are called `Access Control Entries` (`ACEs`). Each ACE maps back to a user, group, or process

**How to Access ACLs:**  ==open`Active Directory Users and Computers` (`ADUC`)(`dsa.msc`), In the ADUC menu, click **View** → check **Advanced Features**., right-click the user, select Properties, then go to Security → Advanced==

There are two types of ACLs:
- **Discretionary Access Control List** (`DACL`) - defines which security principals are granted or denied access to an object. Without a DACL everyone has full access; if DACL exist and but does not have any ACE entries all access is denied.![[Pasted image 20250815142702.png]]
- - **System Access Control Lists** (`SACL`) - allow administrators to log access attempts made to secured object . and can be seen within the `Auditing` tab. ![[Pasted image 20250815142821.png]]
## Access Control Entries (ACEs)
**ACLs contain ACE entries** that name a user or group and the level of access they have over a given securable object

**ACE Types:**
- **Access Denied ACE** – Explicitly denies access.
- **Access Allowed ACE** – Explicitly grants access.
- **System Audit ACE** – Logs access attempts for auditing.

**ACE Components:**
1. **SID** – Identifies the user/group.
2. **ACE Type** – Allow, Deny, or Audit.
3. **Inheritance Flags** – Apply to child objects or not.
4. **Access Mask** – Specific rights granted.
![[Pasted image 20250815144359.png]]
## Why are ACEs Important?
Attackers can abuse misconfigured ACEs for persistence or privilege escalation, often going unnoticed for years tools like **BloodHound  for enumerate** and **PowerView to exploit** them.

**Examples:**
- `ForceChangePassword` abused with `Set-DomainUserPassword`
- `Add Members` abused with `Add-DomainGroupMember`
- `GenericAll` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `GenericWrite` abused with `Set-DomainObject`
- `WriteOwner` abused with `Set-DomainObjectOwner`
- `WriteDACL` abused with `Add-DomainObjectACL`
- `AllExtendedRights` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `Addself` abused with `Add-DomainGroupMember`

In this module, we will cover enumerating and leveraging 4 specific ACEs to highlight the power of ACL attacks
- [ForceChangePassword](https://bloodhound.specterops.io/resources/edges/force-change-password) - gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).
- [GenericWrite](https://bloodhound.specterops.io/resources/edges/generic-write) - gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.
- [AddSelf](https://bloodhound.specterops.io/resources/edges/add-self) - shows security groups that a user can add themselves to.
- [GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all) - this grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.

This graphic, adapted from a graphic created by [Charlie Bromberg (Shutdown)](https://twitter.com/_nwodtuhs), shows an excellent breakdown of the varying possible ACE attacks and the tools to perform these attacks from both Windows and Linux (if applicable)
![[ACEs Attacks mindmap.png]]
 
 >==whenever we encounter new privileges in the wild that we may not yet be familiar with search on :==
 >Active Directory [Extended Rights](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights)
 >the [BloodHound edges](https://bloodhound.specterops.io/resources/edges/overview)

**Example:**
we may import data into BloodHound and see that a user we have control over (or can potentially take over) has the rights to read the password for a Group Managed Service Account (gMSA) through the [ReadGMSAPassword](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#readgmsapassword) edge. In this case, there are tools such as [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader) that we could use, along with other methods, to obtain the password for the service account

## ACL Attacks in the Wild

We can use ACL attacks for:
- Lateral movement
- Privilege escalation
- Persistence

Some common attack scenarios may include:
- **Abusing Forgot Password** – Take over an account with reset rights to change passwords for higher-privilege accounts.
- **Abusing Group Management** – Add our account to privileged groups via group membership rights.
- **Excessive Rights** – Exploit unintended or legacy ACL permissions from software installs or misconfigurations.

---
# ACL Enumeration
## Manuel 
without using tools (ex.powerview)
```powershell
# Creating a List of Domain Users
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
# A Useful foreach Loop
foreach($line in [System.IO.File]::ReadLines("<C:\ad_users.txt>")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match '<DOAMIN>\\<USER>'}}

# Convert GUID-RIGHT to human readable
$guid= "<ObjectAceType-GUID>"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
```

## Enumerating ACLs with PowerView
```powershell
Find-InterestingDomainAcl # a lote of output hard to enum !!!

# ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL      # WHERE: target object (domain root)
# ObjectAceType         : ab721a53-1...                  # WHAT: Extended Right GUID = "Send As"
# ActiveDirectoryRights : ExtendedRight                  # TYPE: special AD control right
# AceQualifier          : AccessAllowed                  # EFFECT: allow (not deny)
# InheritanceFlags      : ContainerInherit               # SCOPE: inherits to child objects
# IdentityReferenceName : Exchange Windows Permissions   # WHO: principal granted the right
# IdentityReferenceClass: group                          # WHO-TYPE: group
# SecurityIdentifier    : S-1-5-21-384...-5189           # WHO-SID: unique ID of that group

``` 

>- Standard rights (always in `ActiveDirectoryRights`)
>- Extended rights (always in `ObjectAceType`)
>- Object* = the Target object (WERE)
>- *Identifier = who have the right
```
```


==results will be extremely time-consuming and likely inaccurate.==
let  performing targeted enumeration starting with a user that we have control over:

```powershell
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid <USER>
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid} # ObjectAceType IN GUID formate

# -ResolveGUIDs Flag to convert ActiveDirectoryRights to human readable.
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 

# or manuel with buidin tools 
$guid = '<ObjectAceType-GUID>'
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Properties * |
Where-Object { $_.ObjectClass -eq 'controlAccessRight' -and $_.rightsGuid -eq $guid } |
Select-Object Name,DisplayName,DistinguishedName,rightsGuid |
Format-List
```


==Result:==
>Our user  has  **GenericWrite** rights over `<GROUP-A>`, allowing us to add ourselves to it.  

### Analyzing Right to Escalate Privileges

==Result:==
>Our user has **GenericWrite** rights over `<GROUP-A>`, allowing us to add ourselves to it.  

 **1-Investigating the GROUP-A Group**
[?] let search if can `<GROUP-A>` group do anything interesting ??
```powershell
$itgroupsid = Convert-NameToSid "<GROUP-A>"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
```
==[!] A search for rights conferred upon this group `<GROUP-A>` does not return any interesting right !! .==

[?]Now let’s check if `<GROUP-A>` is nested inside any other groups:
```powershell
Get-DomainGroup -Identity "<GROUP-A>" | select memberof
# memberof => GROUP-B                                                           
```
[+] ==The `<GROUP-A>` group is nested into the `<GROUP-B>` group, which grants members of that group==


**2-Investigating the GROUP-B Group with Get-DomainGroup:**
[?] let search if can `<GROUP-B>` group do anything interesting ??
```powershell
$itgroupsid = Convert-NameToSid "<GROUP-A>"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
```
[+]  ==`<GROUP-B>` group have `GenericAll` rights over the user `<USER-B>`== 

which means we could:
- Modify group membership
- Force change a password
- Perform a targeted Kerberoasting attack and attempt to crack the user's password if it is weak

**3- Looking for Interesting Access**
[?] Finally, let's see if the `<USER-B>` user has any type of interesting access that we may be able to leverage to get closer to our goal.
```powershell
$adunnsid = Convert-NameToSid <USER-B>
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose

# ObjectDN  : DC=INLANEFREIGHT,DC=LOCAL
# ObjectAceType : DS-Replication-Get-Changes-In-Filtered-Set
# ObjectAceType : DS-Replication-Get-Changes
```

[+]  ==our `<USER-B>` user has `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-In-Filtered-Set` rights over the domain object==
**This means that this user can be leveraged to perform a DCSync attack.**

## Enumerating ACLs with BloodHound
Now that we've enumerated the attack path using more manual methods like PowerView and built-in PowerShell cmdlets, let's look at how much easier this would have been to identify using the extremely powerful BloodHound tool. Let's take the data we gathered earlier with the SharpHound ingestor and upload it to BloodHound. Next, we can set the `wley` user as our starting node, select the `Node Info` tab and scroll down to `Outbound Control Rights`. This option will show us objects we have control over directly, via group membership, and the number of objects that our user could lead to us controlling via ACL attack paths under `Transitive Object Control`. If we click on the `1` next to `First Degree Object Control`, we see the first set of rights that we enumerated, `ForceChangePassword` over the `damundsen` user.

#### Viewing Node Info through BloodHound

![BloodHound interface showing node info for WLEY@INLANEFREIGHT.LOCALl with execution and control rights, connected to DAMUNDSEN@INLANEFREIGHT.LOCAL via ForceChangePassword.](https://academy.hackthebox.com/storage/modules/143/wley_damundsen.png)

If we right-click on the line between the two objects, a menu will pop up. If we select `Help`, we will be presented with help around abusing this ACE, including:

- More info on the specific right, tools, and commands that can be used to pull off this attack
- Operational Security (Opsec) considerations
- External references.

We'll dig into this menu more later on.

#### Investigating ForceChangePassword Further

![Popup window in BloodHound showing ForceChangePassword capability for WLEY@INLANEFREIGHT.LOCAL to change DAMUNDSEN@INLANEFREIGHT.LOCAL's password without knowing the current password.](https://academy.hackthebox.com/storage/modules/143/help_edge.png)

If we click on the `16` next to `Transitive Object Control`, we will see the entire path that we painstakingly enumerated above. From here, we could leverage the help menus for each edge to find ways to best pull off each attack.
#### Viewing Potential Attack Paths through BloodHound

![BloodHound graph showing WLEY@INLANEFREIGHT.LOCAL's connections to various groups and users, including CONTRACTORS, FILE SHARE, and DOMAIN USERS, with relationships like MemberOf and ForceChangePassword.](https://academy.hackthebox.com/storage/modules/143/wley_path.png)

Finally, we can use the pre-built queries in BloodHound to confirm that the `adunn` user has DCSync rights.
#### Viewing Pre-Build queries through BloodHound

![BloodHound graph showing ADUNN@INLANEFREIGHT.LOCAL's connections to various groups and users, including DOMAIN ADMINS and ENTERPRISE DOMAIN CONTROLLERS, with relationships like MemberOf and GetChangesAll.](https://academy.hackthebox.com/storage/modules/143/adunn_dcsync.png)

We've now enumerated these attack paths in multiple ways.