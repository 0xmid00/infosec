## 1-DNS Records
Browser can't resolve academy.htb because it's an internal HTB hostname (not in public DNS). Add an `/etc/hosts` entry to map the server IP to academy.htb:  
```bash
sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'  
```
Then visit http://academy.htb:PORT to reach the same site as the IP. Next: enumerate subdomains under *.academy.htb.

## 2- Sub-domain Fuzzing

Use ffuf with a subdomain wordlist to fuzz subdomains:  
```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb/ 
```
> Hits appear for public domains (inlanefreight.com). No hits for academy.htb because it’s internal (not in public DNS); ffuf queries public DNS unless subdomains are added to /etc/hosts or your DNS.

## 2- Vhost Fuzzing
VHost fuzzing changes the Host header to discover virtual hosts on the same IP (no DNS needed). 
```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'  
```
##  3- Filtering Results
Use VHost fuzzing (change Host header) and filter results by response size to find real VHosts:  
```bash
#   -fs Filter HTTP response size. Comma separated list of sizes and ranges
#   -fc Filter HTTP status codes from response. Comma separated list of codes and ranges

ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs 900  
```
**Explanation: -H injects FUZZ into Host,  -fs 900 filters (exclude) out the default 900-byte fake responses so real VHosts show different sizes. Example found: admin -> add "SERVER_IP admin.academy.htb" to /etc/hosts and visit `http://admin.academy.htb:PORT/` to confirm (then run a recursive scan).**
