### [[Exfiltration#Copy &Paste Base64|PowerShell Base64 Encode & Decode]]
not require network communication. If we have access to a terminal, we can encode a file to a base64 string, copy its contents from the terminal and perform the reverse operation, decoding the file in the original content.

### [[Exfiltration#HTTP|PowerShell Web Downloads]]
Most companies allow `HTTP` and `HTTPS` outbound traffic through the firewall to allow employee productivity.
### [[Exfiltration#SMB|SMB Download]]
The Server Message Block protocol (SMB protocol) that runs on port TCP/445 is common in enterprise networks where Windows services are running
### [[Exfiltration#FTP|FTP Download]]
Another way to transfer files is using FTP (File Transfer Protocol), which use port TCP/21 and TCP/20. We can use the FTP client or PowerShell Net.WebClient to download files from an FTP server.
### [[Exfiltration#Copy &Paste Base64|PowerShell Base64 Encode & Decode (upload)]]

### [[Exfiltration#Upload files|PowerShell Web Upload]]

### [[Exfiltration#SMB|SMB Upload]]
Commonly enterprises don't allow the SMB protocol (TCP/445) out of their internal network because this can open them up to potential attacks.An alternative is to run SMB over HTTP with `WebDav`, The `WebDAV` protocol enables a webserver to behave like a fileserver, supporting collaborative content authoring. `WebDAV` can also use HTTPS.
### [[Exfiltration#FTP|FTP Upload]]