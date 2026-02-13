The archive share is writeable by all Domain Users.

```bash

╰─$ crackmapexec smb 172.16.5.5 -u asmith -p Welcome1 --shares --smb-timeout 1000000     2 ↵
SMB         172.16.5.5      445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    DC01             [+] INLANEFREIGHT.LOCAL\asmith:Welcome1 
SMB         172.16.5.5      445    DC01             [+] Enumerated shares
SMB         172.16.5.5      445    DC01             Share           Permissions     Remark
SMB         172.16.5.5      445    DC01             -----           -----------     ------
SMB         172.16.5.5      445    DC01             ADMIN$                          Remote Admin
SMB         172.16.5.5      445    DC01             C$                              Default share
SMB         172.16.5.5      445    DC01             Department Shares READ            
SMB         172.16.5.5      445    DC01             IPC$            READ            Remote IPC
SMB         172.16.5.5      445    DC01             NETLOGON        READ            Logon server share 
SMB         172.16.5.5      445    DC01             SYSVOL          READ            Logon server share 
SMB         172.16.5.5      445    DC01             User Shares     READ            
SMB         172.16.5.5      445    DC01             ZZZ_archive     READ,WRITE      

```

![[Pasted image 20260126144459.png]]