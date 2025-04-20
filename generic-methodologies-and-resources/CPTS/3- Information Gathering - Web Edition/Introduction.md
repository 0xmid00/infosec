
## Introduction
- First step in penetration testing.
- Gathers info on target websites/apps.
- Prepares for later exploitation.

## Goals
- **Identify Assets**: Web pages, subdomains, IPs, tech.
- **Find Hidden Info**: Backups, configs, docs.
- **Attack Surface**: Look for weak points.
- **Intel**: Emails, employee names, behavior.

## Recon Types

### Active Recon
- **Direct interaction** with the target.
- Risk of detection is **high**.

| Technique         | Tools                     | Notes                                 |
|------------------|---------------------------|----------------------------------------|
| Port Scanning     | Nmap, Masscan             | Find open ports/services               |
| Vuln Scanning     | Nessus, Nikto             | Detect known vulnerabilities           |
| Network Mapping   | Traceroute, Nmap          | Map network paths                      |
| Banner Grabbing   | Netcat, curl              | Get service info                       |
| OS Fingerprinting | Nmap -O                   | Identify target OS                     |
| Service Enum      | Nmap -sV                  | Get service versions                   |
| Web Spidering     | Burp, ZAP, Scrapy         | Crawl site for pages/files             |

### Passive Recon
- **No interaction** with the target.
- **Very low** risk of detection.

| Technique          | Tools                    | Notes                                  |
|-------------------|--------------------------|-----------------------------------------|
| Search Queries     | Google, Shodan           | Find public info                        |
| WHOIS              | whois cmd, online tools  | Domain owner, contact info              |
| DNS Analysis       | dig, nslookup, dnsenum   | Subdomains, mail servers                |
| Web Archives       | Wayback Machine          | Old site versions                       |
| Social Media       | LinkedIn, Twitter        | Employee names, roles                   |
| Code Repos         | GitHub, GitLab           | Look for secrets in code                |
