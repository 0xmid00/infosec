
## FootPrinting
### Enumeration Principles
- Enumeration = Info gathering (active & passive)
- OSINT is passive and done separately
- Loop: gather info → analyze → gather more
- Targets: Domains, IPs, ports, services, vendors, structure
- Avoid brute-forcing early (noisy & weak understanding)
- Think like a treasure hunter: plan, study, don’t guess
- Key Questions:
  > What do we see? Why? What does it tell us?
  > How can we use it? What’s hidden? Why hidden? What does that mean?
- 3 Principles:
  1. More than meets the eye – look deeper
  2. Know what’s visible vs hidden
  3. Always find more – understand the target

## enumeration methodology 
![](https://academy.hackthebox.com/storage/modules/112/enum-method3.png)

***enumeration levels:***
### Infrastructure-based
#### [[Domain Information]]
gather comprehensive domain and online presence data by examining SSL certificates, DNS records, and subdomain information through tools like crt.sh and Shodan. It emphasizes understanding a company's infrastructure and the technologies behind its services
#### [[Cloud Resource]]
Many companies rely on cloud services like AWS, Azure, and GCP for flexibility, but misconfiguration especially in storage like S3 bucket can expose sensitive data. Attackers often use tools like Google Dorks, GrayHatWarfare, and source code analysis to discover publicly accessible cloud resources and leaked credentials.
#### [[Staff]]
### Host-based
#### [[network-services-pentesting/pentesting-ftp/README|FTP]] (21)
#### [[network-services-pentesting/pentesting-smb/README|SMB]] (139,445)
#### [[nfs-service-pentesting|NFS]] (2049)
#### [[network-services-pentesting/pentesting-dns|DNS]] (53)

#### [[network-services-pentesting/pentesting-smtp/README|SMTP]] (25)
#### [[pentesting-imap|imap]]  /  [[pentesting-pop| POP3]] (143,993 / 110,995)
#### [[network-services-pentesting/pentesting-snmp/README|SNMP]] (161,162)
#### [[pentesting-mysql|MySQL]] (3306)
#### [[network-services-pentesting/pentesting-mssql-microsoft-sql-server/README|MSSQL]] (1433)

#### [[network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/README|Oracle TNS]] (1521)
#### [[623-udp-ipmi|IPMI]] (623)
#### Linux remote management system
##### [[pentesting-ssh| SSH]] (22)
##### [[873-pentesting-rsync|Rsync]] (873)
##### R-Services
###### [[512-pentesting-rexec|rexec]] (512)
###### [[pentesting-rlogin|rlogin]] (513)
###### [[pentesting-rsh|rsh]] (514)
### OS-based








## [[Legal Considerations]]

