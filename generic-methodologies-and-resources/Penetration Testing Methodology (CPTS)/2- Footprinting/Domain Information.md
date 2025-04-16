Domain info is key in pentesting — not just subdomains, but the full online presence. 
We gather passive intel to stay hidden, acting like visitors/customers.

Start by analyzing the company's main site:
- Read content carefully.
- Identify services (e.g., app dev, IoT, hosting).
- Think about the tech and structure needed behind those services.

Use third-party tools/services to gather more passive data.
Always consider both what you see and what you don’t.
Take a developer's view to understand the tech behind the services.

This passive OSINT phase offers critical insights without alerting the target.
## Online Presence
#### Certificate Transparency

Start with passive recon after understanding the company.
Check SSL certs for subdomains:
- crt.sh shows domains from cert transparency logs

```bash
curl -s "https://crt.sh/?q=inlanefreight.com&output=json" | jq .
# Extract subdomains
curl -s "https://crt.sh/?q=inlanefreight.com&output=json" \
| jq . | grep name | cut -d: -f2 | grep -v "CN=" | cut -d'"' -f2 | sort -u > subdomainlist
```
#### Company Hosted Servers
```bash

for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
```
Once we see which hosts can be investigated further, we can generate a list of IP addresses with a minor adjustment to the `cut` command and run them through `Shodan`.
#### Shodan - IP List
```bash
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done
# 
for i in $(cat ip-addresses.txt);do shodan host $i;done
```
#### DNS Records
```bash
dig any inlanefreight.com
# example outpu:
...SNIP... TXT     "MS=ms92346782372"
...SNIP... TXT     "atlassian-domain-verification=IJdXMt1rKCy68JFszSdCKVpwPN"
...SNIP... TXT     "google-site-verification=O7zV5-xFh_jn7JQ31"
...SNIP... TXT     "google-site-verification=bow47-er9LdgoUeah"
...SNIP... TXT     "google-site-verification=gZsCG-BINLopf4hr2"
...SNIP... TXT     "logmein-verification-code=87123gff5a479e-61d4325gddkbvc1-b2bnfghfsed1-3c789427sdjirew63fc"
...SNIP... TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.24.8 ip4:10.129.27.2 ip4:10.72.82.106 ~all
```
 We get an IP record, some mail servers, some DNS servers, TXT records, and an SOA record.
 - `A` records: We recognize the IP addresses that point to a specific (sub)domain through the A record. Here we only see one that we already know.
    
- `MX` records: The mail server records show us which mail server is responsible for managing the emails for the company. Since this is handled by google in our case, we should note this and skip it for now.
    
- `NS` records: These kinds of records show which name servers are used to resolve the FQDN to IP addresses. Most hosting providers use their own name servers, making it easier to identify the hosting provider.
    
- `TXT` records: this type of record often contains verification keys for different third-party providers and other security aspects of DNS, such as [SPF](https://datatracker.ietf.org/doc/html/rfc7208), [DMARC](https://datatracker.ietf.org/doc/html/rfc7489), and [DKIM](https://datatracker.ietf.org/doc/html/rfc6376), which are responsible for verifying and confirming the origin of the emails sent. Here we can already see some valuable information if we look closer at the results. 

  For example, [Atlassian](https://www.atlassian.com/) states that the company uses this solution for software development and collaboration. If we are not familiar with this platform, we can try it for free to get acquainted with it.

  [Google Gmail](https://www.google.com/gmail/) indicates that Google is used for email management. Therefore, it can also suggest that we could access open GDrive folders or files with a link.

  [LogMeIn](https://www.logmein.com/) is a central place that regulates and manages remote access on many different levels. However, the centralization of such operations is a double-edged sword. If access as an administrator to this platform is obtained (e.g., through password reuse), one also has complete access to all systems and information.

  [Mailgun](https://www.mailgun.com/) offers several email APIs, SMTP relays, and webhooks with which emails can be managed. This tells us to keep our eyes open for API interfaces that we can then test for various vulnerabilities such as IDOR, SSRF, POST, PUT requests, and many other attacks.

  [Outlook](https://outlook.live.com/owa/) is another indicator for document management. Companies often use Office 365 with OneDrive and cloud resources such as Azure blob and file storage. Azure file storage can be very interesting because it works with the SMB protocol.

  The last thing we see is [INWX](https://www.inwx.com/en). This company seems to be a hosting provider where domains can be purchased and registered. The TXT record with the "MS" value is often used to confirm the domain. In most cases, it is similar to the username or ID used to log in to the management platform.