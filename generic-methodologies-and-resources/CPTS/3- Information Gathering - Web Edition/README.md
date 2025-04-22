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

 ### [[generic-methodologies-and-resources/external-recon-methodology/README#**DNS Brute force**|DNS Brute forcing ]]
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
 ### [[generic-methodologies-and-resources/external-recon-methodology/README#DNS Zone Transfer|DNS Zone Transfer]]
 ### [[generic-methodologies-and-resources/external-recon-methodology/README#**VHosts / Virtual Hosts**|Virtual Hosts]]
`virtual hosting` is the ability of web servers to distinguish between multiple websites or applications sharing the same IP address. This is achieved by leveraging the `HTTP Host` header.

**Types of Virtual Hosting:**
1. `Name-Based Virtual Hosting`
2. `IP-Based Virtual Hosting`
3. `Port-Based Virtual Hosting`

There are a couple of things you need to prepare to brute force `Host` headers:
1. Target Identification: find the domain ip add add it to /etc/hosts
2. `Wordlist Preparation`
 ### [[generic-methodologies-and-resources/external-recon-methodology/README#Certificate Transparency Logs|Certificate Transparency Logs]]

## Fingerprinting

>Information about web technologies can be gathered by banner grabbing, analyzing HTTP headers, probing for specific responses, and examining page content. These methods help identify server software, versions, and technologies in use.

[[network-services-pentesting/pentesting-web/README#Banner Grabbing|Banner Grabbing]]
 [[network-services-pentesting/pentesting-web/README#Check if any WAF|Check if any WAF]]
 [[network-services-pentesting/pentesting-web/README#General purpose automatic scanners|automatic scanners]]
## Crawling
### [[network-services-pentesting/pentesting-web/README#spidering|Crawling]]
`Crawling`, often called `spidering`, is the `automated process of systematically browsing the World Wide Web`, Crawlers can extract : links , comments , metadata sensitive files
### [[network-services-pentesting/pentesting-web/README#Initial checks|robots.txt]]
it a file  contains instructions in the form of "directives" that tell bots which parts of the website they can and cannot crawl, can serves as a valuable source of intelligence:
`Uncovering Hidden Directories`,`Mapping Website Structure`, `Detecting Crawler Traps`
### [[network-services-pentesting/pentesting-web/README#Initial checks|robots.txt]]
### [[network-services-pentesting/pentesting-web/README#Initial checks|well-known]]
accessible via the `/.well-known/` path on a web server, centralizes a website's critical metadata, including configuration files and information related to its services, protocols, and security mechanisms.(ex. `/.well-known/openid-configuration`)

the `.well-known` URIs can be invaluable for discovering endpoints and configuration details that can be further tested during a penetration test. One particularly useful URI is `openid-configuration`.
-> `https://example.com/.well-known/openid-configuration`
```json
{
  "issuer": "https://example.com",
  "authorization_endpoint": "https://example.com/oauth2/authorize",
  "token_endpoint": "https://example.com/oauth2/token",
  "userinfo_endpoint": "https://example.com/oauth2/userinfo",
  "jwks_uri": "https://example.com/oauth2/jwks",
  "response_types_supported": ["code", "token", "id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"]
}
```

The information obtained from the `openid-configuration` endpoint provides multiple exploration opportunities:
1. `Endpoint Discovery`:
    - `Authorization Endpoint`: Identifying the URL for user authorization requests.
    - `Token Endpoint`: Finding the URL where tokens are issued.
    - `Userinfo Endpoint`: Locating the endpoint that provides user information.
2. `JWKS URI`: The `jwks_uri` reveals the `JSON Web Key Set` (`JWKS`), detailing the cryptographic keys used by the server.
3. `Supported Scopes and Response Types`: Understanding which scopes and response types are supported helps in mapping out the functionality and limitations of the OpenID Connect implementation.
4. `Algorithm Details`: Information about supported signing algorithms can be crucial for understanding the security measures in place.
### [[network-services-pentesting/pentesting-web/README#Spidering|Creepy Crawlies]]
### [[network-services-pentesting/pentesting-web/README#Google Dorking|Search Engine Discovery]]
### Web Archives
```bash
https://web.archive.org/
```
a unique opportunity to revisit the past and explore the digital footprints of websites as they once were, providing valuable insights that may not be readily apparent in its current state:

1. `Uncovering Hidden Assets and Vulnerabilities`
2. `Tracking Changes and Identifying Patterns`
3. `Gathering Intelligence`
4. `Stealthy Reconnaissance`
