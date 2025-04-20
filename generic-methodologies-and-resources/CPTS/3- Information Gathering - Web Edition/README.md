# Information Gathering - Web Edition
## [[Introduction]]
## [[generic-methodologies-and-resources/external-recon-methodology/README#WHOIS|WHOIS]]
## subdomains & DNS 
 ### [[DNS|DNS ]]
 ### [[generic-methodologies-and-resources/external-recon-methodology/README#**DNS**|DIGGING DNS ]]
 
DNS reconnaissance involves utilizing specialized tools designed to query DNS servers and extract valuable information. Here are some of the most popular and versatile tools in the arsenal of web recon professionals.

| Tool                       | Key Features                                                                                            | Use Cases                                                                                                                               |
| -------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `dig`                      | Versatile DNS lookup tool that supports various query types (A, MX, NS, TXT, etc.) and detailed output. | Manual DNS queries, zone transfers (if allowed), troubleshooting DNS issues, and in-depth analysis of DNS records.                      |
| `nslookup`                 | Simpler DNS lookup tool, primarily for A, AAAA, and MX records.                                         | Basic DNS queries, quick checks of domain resolution and mail server records.                                                           |
| `host`                     | Streamlined DNS lookup tool with concise output.                                                        | Quick checks of A, AAAA, and MX records.                                                                                                |
| `dnsenum`                  | Automated DNS enumeration tool, dictionary attacks, brute-forcing, zone transfers (if allowed).         | Discovering subdomains and gathering DNS information efficiently.                                                                       |
| `fierce`                   | DNS reconnaissance and subdomain enumeration tool with recursive search and wildcard detection.         | User-friendly interface for DNS reconnaissance, identifying subdomains and potential targets.                                           |
| `dnsrecon`                 | Combines multiple DNS reconnaissance techniques and supports various output formats.                    | Comprehensive DNS enumeration, identifying subdomains, and gathering DNS records for further analysis.                                  |
| `theHarvester`             | OSINT tool that gathers information from various sources, including DNS records (email addresses).      | Collecting email addresses, employee information, and other data associated with a domain from multiple sources.                        |
| Online DNS Lookup Services | User-friendly interfaces for performing DNS lookups.                                                    | Quick and easy DNS lookups, convenient when command-line tools are not available, checking for domain availability or basic information |
### subdomain
Subdomains often host valuable information and resources that aren't directly linked from the main website. This can include:
    `Development and Staging Environments`
    `Hidden Login Portals`
    `Legacy Applications`
    `Sensitive Information`

There are two main approaches to subdomain enumeration:
 1. Active Subdomain Enumeration : dns zone transfer,  brute-force enumeration (fuff, gobuster 
2. Passive Subdomain Enumeration: Certificate Transparency (CT) logs , search engines, online databases 

 #### [[generic-methodologies-and-resources/external-recon-methodology/README#**DNS Brute force**|DNS Brute forcing ]]
 A DNS query is performed for each potential subdomain to check if it resolves to an IP address. This is typically done using the A or AAAA record type.
There are several tools available that excel at brute-force enumeration:

|Tool|Description|
|---|---|
|[dnsenum](https://github.com/fwaeytens/dnsenum)|Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains.|
|[fierce](https://github.com/mschwager/fierce)|User-friendly tool for recursive subdomain discovery, featuring wildcard detection and an easy-to-use interface.|
|[dnsrecon](https://github.com/darkoperator/dnsrecon)|Versatile tool that combines multiple DNS reconnaissance techniques and offers customisable output formats.|
|[amass](https://github.com/owasp-amass/amass)|Actively maintained tool focused on subdomain discovery, known for its integration with other tools and extensive data sources.|
|[assetfinder](https://github.com/tomnomnom/assetfinder)|Simple yet effective tool for finding subdomains using various techniques, ideal for quick and lightweight scans.|
|[puredns](https://github.com/d3mondev/puredns)|Powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively.|
