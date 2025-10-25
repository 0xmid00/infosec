## 1- medusa
Medusa is a fast, massively parallel, modular login brute-forcer for many remote auth services. Useful for pentesting authentication resilience.
#### 1-Command Syntax and Parameter Table
```bash
# Basic syntax
medusa [target_options] [credential_options] -M module [module_options]
# -h HOST | -H FILE   # target host or hosts file
# -u USER | -U FILE   # single user or user file
# -p PASS | -P FILE   # single pass or pass file
# -M MODULE           # module/service (ssh, ftp, http, rdp, ...)
# -t TASKS            # parallel attempts
# -f / -F             # stop after first success (host / any host)
# -n PORT             # non-default port
# -v LEVEL            # verbosity

#  modules option '-M <module> ''
  #  ftp   ssh   http/http-form   imap   pop3   mysql   rdp   vnc
```
#### 2- usage example
```bash
# SSH brute-force (single host)
medusa -h 192.168.0.100 -U usernames.txt -P passwords.txt -M ssh

# http (Basic HTTP Authentication with multiple Web Servers)
medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET

# http (POST req with additional parameters)
medusa -M http -m "POST /login.php HTTP/1.1\r\nContent-Length: 30\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=^USER^&password=^PASS^"...

# Web Form (Web Login Forms HTTP with POST requests)
medusa -M web-form -h www.example.com -U users.txt -P passwords.txt -m FORM:"username=^USER^&password=^PASS^:F=Invalid"

# Check empty/default passwords (try '' and user-as-pass)
medusa -h 10.0.0.5 -U usernames.txt -e ns -M ssh
# -e n (empty) and -e s (password = username) checks on SSH for weak accounts

# RDP 
medusa -M rdp -h 192.168.1.100 -u admin -P passwords.txt

#  SSH  (target SSH with known user)
medusa -h <IP> -n <PORT> -u sshuser -P 2023-200_most_used_passwords.txt -M ssh -t 3

#  FTP brute (target local FTP with guessed username)
medusa -h <IP> -u ftpuser -P 2020-200_most_used_passwords.txt -M ftp -t 5

# Stop-after-first-success 
medusa -h 192.168.0.100 -U users.txt -P passwords.txt -M ssh -F
```

