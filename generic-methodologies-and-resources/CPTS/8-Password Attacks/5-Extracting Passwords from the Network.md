## Credential Hunting in Network Traffic
```bash
# hunt for credentials in cleartext network traffic

  # |Unencrypted Protocol|Encrypted Counterpart|Description|
  HTTP | HTTPS  # Used for transferring web pages and resources over the internet
  FTP | FTPS/SFTP # |Used for transferring files between a client and a server.
  SNMP | SNMPv3 (with encryption) # Used for monitoring and managing network devices like routers and switches
  POP3 | POP3S # Retrieves emails from a mail server to a local client.
  IMAP | IMAPS # Accesses and manages email messages directly on the mail server.
  SMTP | SMTPS # Sends email messages from client to server or between mail servers.
  LDAP | LDAPS # Queries and modifies directory services like user credentials and roles.
  RDP |RDP (with TLS) # Provides remote desktop access to Windows systems
  DNS (Traditional) | DNS over HTTPS (DoH) # Resolves domain names into IP addresses.
  SMB | SMB over TLS (SMB 3.0) # Shares files, printers, and other resources over a network.
  VNC | VNC with TLS/SSL # Allows graphical remote control of another computer.
  
## Wireshark
  ip.addr == 56.48.210.13 # Filters packets with a specific IP address
  tcp.port == 80 # Filters packets by port (HTTP in this case).
  http # Filters for HTTP traffic.
  dns # Filters DNS traffic, which is useful to monitor domain name resolution.
  tcp.flags.syn == 1 && tcp.flags.ack == 0 # Filters SYN packets (used in TCP handshakes), useful for detecting scanning or connection attempts.
  icmp # Filters ICMP packets (used for Ping), which can be useful for reconnaissance or network issues.
  http.request.method == "POST" # Filters for HTTP POST requests. In the case that POST requests are sent over unencrypted HTTP, it may be the case that passwords or other sensitive information is contained within.
  tcp.stream eq 53 # Filters for a specific TCP stream. Helps track a conversation between two hosts.
  eth.addr == 00:11:22:33:44:55 # Filters packets from/to a specific MAC address.
  ip.src == 192.168.24.3 && ip.dst == 56.48.210.3 # Filters traffic between two specific IP addresses. Helps track communication between specific hosts.

## Pcredz (https://github.com/lgandx/PCredz)
  /Pcredz -f <file.pcapng> -t -v
  # Credit card numbers
  # POP credentials
  # SMTP credentials
  # IMAP credentials
  # SNMP community strings
  # FTP credentials
  # Credentials from HTTP NTLM/Basic headers, as well as HTTP Forms
  # NTLMv1/v2 hashes from various traffic including DCE-RPC, SMBv1/2, LDAP, MSSQL, and HTTP
  # Kerberos (AS-REQ Pre-Auth etype 23) hashes
```


## Credential Hunting in Network Shares
```bash
# hunt for credentials across network shares:
  passw, user, token, key, secret # keywords
  .ini, .cfg, .env, .xlsx, .ps1, .bat # files extensions
  config, user, passw, cred, or initial # files names
  INLANEFREIGHT\ #  keyword (if the domain INLANEFREIGHT.LOCAL)
  Benutzer # if the target is German company (User=Benutzer in Germany)

  # basic command-line searches (the best !)
  gci "\\DC01.inlanefreight.local\HR" -r -File -ea SilentlyContinue | sls 'passw'

  Get-ChildItem "\\DC01.inlanefreight.local\HR" -Recurse -File -ErrorAction SilentlyContinue |
Where-Object { $_.Extension -match '\.cfg|\.ini|\.env|\.xlsx|\.bat' } |
Select-String 'password' 

## Hunting from Windows
  ### Snaffler (run on domain-joined machine) (https://github.com/SnaffCon/Snaffler)
  Snaffler.exe -s -o out.txt
    # -u retrieves a list of users from Active Directory and searches for references to them in files
    #  -i and -n allow you to specify which shares should be included in the search
  
  ### PowerHuntShares  (https://github.com/NetSPI/PowerHuntShares)
  Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public

## Hunting from Linux
 
 ### MANSPIDER (remotly search)(https://github.com/blacklanternsecurity/MANSPIDER)
 #  A basic scan for files containing the string passw
 docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider 10.129.234.121 -c 'passw' -u 'mendres' -p 'Inlanefreight2025!' 

  ### NetExec (https://www.netexec.wiki/smb-protocol/spidering-shares)
    #### basic scan of network shares for files containing the string `"passw"`
    crackmapexec smb 10.129.234.173 -u mendres -p Inlanefreight2025!  --spider IT --content --pattern "passw"
```