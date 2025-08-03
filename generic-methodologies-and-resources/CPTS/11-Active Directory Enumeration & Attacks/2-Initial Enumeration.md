# External Recon and Enumeration Principles

| **What (Data Point)**  | **Description**                                                                                                                                                                                                                                                                                                          | **Where (Sources & Tools)**                                                                                                                                                                                                   |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **IP Space**           | Valid ASN for our target, netblocks in use for the organization's public-facing infrastructure, cloud presence and the hosting providers, DNS record entries, etc.                                                                                                                                                       | [IANA](https://www.iana.org/), [ARIN](https://www.arin.net/), [RIPE](https://www.ripe.net/), [BGP Toolkit](https://bgp.he.net/)                                                                                               |
| **Domain Information** | Based on IP data, DNS, and site registrations. Who administers the domain? Are there any subdomains tied to our target? Are there any publicly accessible domain services present (Mailservers, DNS, Websites, VPN portals, etc.)? Can we determine what kind of defenses are in place? (SIEM, AV, IPS/IDS in use, etc.) | [Domaintools](https://www.domaintools.com/), [PTRArchive](http://ptrarchive.com/), [ICANN Lookup](https://lookup.icann.org/lookup), Manual DNS queries (e.g., `dig`, `nslookup`, `host`) to public DNS servers like `8.8.8.8` |
| **Schema Format**      | Can we discover the organization's email accounts, AD usernames, and even password policies? Anything that will give us information to build a valid username list for testing external-facing services (password spraying, credential stuffing, brute forcing, etc.)                                                    | Social media sites (LinkedIn, Twitter, Facebook), company blogs, documents or presentations leaked online, employee pages, OSINT tools ex. [[[https://github.com/initstring/linkedin2username\|linkedin2username]]            |
| **Data Disclosures**   | Looking for publicly accessible files (`.pdf`, `.ppt`, `.docx`, `.xlsx`, etc.) that reveal internal data such as `intranet` URLs, usernames, shares, or software/hardware in use (e.g., metadata in documents, credentials exposed in public code).                                                                      | Company websites, embedded documents, [GitHub](https://github.com/), [GrayhatWarfare](https://grayhatwarfare.com/), Google Dorking ([GHDB](https://www.exploit-db.com/google-hacking-database))                               |
| **Breach Data**        | Any publicly released usernames, passwords, or other critical information that can help gain a foothold.                                                                                                                                                                                                                 | [HaveIBeenPwned](https://haveibeenpwned.com/), [Dehashed](https://www.dehashed.com/), leaks on forums, paste sites, dark web indexes                                                                                          |

---


# Initial Enumeration of the Domain
## Setting Up
- A penetration testing distro (typically Linux) as a virtual machine in their internal infrastructure that calls back to a jump host we control over VPN, and we can SSH into.
- A physical device plugged into an ethernet port that calls back to us over VPN, and we can SSH into.
- A physical presence at their office with our laptop plugged into an ethernet port.
- A Linux VM in either Azure or AWS with access to the internal network that we can SSH into using public key authentication and our public IP address whitelisted.
- VPN access into their internal network (a bit limiting because we will not be able to perform certain attacks such as LLMNR/NBT-NS Poisoning).
- From a corporate laptop connected to the client's VPN.
- On a managed workstation (typically Windows), physically sitting in their office with limited or no internet access or ability to pull in tools. They may also elect this option but give you full internet access, local admin, and put endpoint protection into monitor mode so you can pull in tools at will.
- On a VDI (virtual desktop) accessed using Citrix or the like, with one of the configurations described for the managed workstation typically accessible over VPN either remotely or from a corporate laptop.
#### Key Data Points

|**Data Point**|**Description**|
|---|---|
|`AD Users`|We are trying to enumerate valid user accounts we can target for password spraying.|
|`AD Joined Computers`|Key Computers include Domain Controllers, file servers, SQL servers, web servers, Exchange mail servers, database servers, etc.|
|`Key Services`|Kerberos, NetBIOS, LDAP, DNS|
|`Vulnerable Hosts and Services`|Anything that can be a quick win. ( a.k.a an easy host to exploit and gain a foothold)|
## TTPs
### Identifying Hosts

#### Passive Checks 
##### Capturing Network Traffic

```bash
sudo -E wireshark
sudo tcpdump -i ens224 -w capture.pcap # If we are on a host without a GUI

# on windows
pktmon start --capture --comp ens225 --pkt-size 0 --file-name capture.etl # --comp <NIC> 
pktmon format capture.etl -o capture.txt # convert output file to .pcapng
```
 **==RESULTS:==**
- **==ARP== packets make us aware of the hosts: 172.16.5.5, 172.16.5.25 172.16.5.50, 172.16.5.100, and 172.16.5.125.**
- **==MDNS== makes us aware of the ACADEMY-EA-WEB01 host.**

##### Starting Responder

Responder is a tool used for LLMNR, NBT-NS, and mDNS poisoning on local networks. It listens for unresolved hostname requests, replies with fake responses, and captures NTLMv1/v2 hashes. It supports credential harvesting, SMB/HTTP spoofing, and NTLM relay (when used with other tools), allowing attackers to crack or relay credentials for lateral movement.
```bash
sudo responder -I ens224 -A 
# -A: Enables analyze mode — passively listens for LLMNR/NBT-NS requests without responding.
```
 **==RESULTS:==**
- **found a few unique hosts not previously mentioned in our Wireshark captures**
#### Active Checks
##### ICMP sweep

```bash
fping -asgq 172.16.5.0/23
# -a  → Show only alive (responsive) hosts  
# -s  → Show summary statistics at the end  
# -g  → Generate IPs from a CIDR range  
# -q  → Quiet mode: hide per-host output

# ping  
for i in {5..6}; do for j in {1..254}; do ping -c1 -W1 172.16.$i.$j &>/dev/null && echo 172.16.$i.$j; done; done

# ping - windows 
for /l %i in (1,1,254) do @ping -n 1 -w 1000 172.16.5.%i | find "TTL=" # 5.x
for /l %i in (1,1,254) do @ping -n 1 -w 1000 172.16.6.%i | find "TTL=" # 6.x

```
 **==RESULTS:==**
 - **9 LIVE Hosts**

### Nmap Scanning

Now that we have a list of active hosts within our network, we can enumerate those hosts further. We are looking to determine what services each host is running, identify critical hosts such as `Domain Controllers` and `web servers`, and identify potentially vulnerable hosts to probe later.
```bash
sudo nmap -v -A -iL hosts.txt -oN host-enum
# use the -oA flag as a best practice when performing Nmap scans.
```
 **==RESULTS:==**
- ==88/tcp  OPEN - kerberos==: **Domain Controllers Host**
-  outdated operating system ( ==Windows 7, 8, or Server 2008==): **EternalBlue, MS08-067**

### Identifying Users

To establish a foothold in a domain, obtain valid user credentials (cleartext or NTLM hash), a SYSTEM shell on a domain-joined host, or a shell as a domain user. Even low-privilege access enables valuable enumeration and further attacks.

#### Kerbrute - Internal AD Username Enumeration

To enumerate usernames, Kerbrute sends TGT requests with no pre-authentication. If the KDC responds with a `PRINCIPAL UNKNOWN` error, the username does not exist. However, if the KDC responds with a **pre-authentication failed** , we know the username exists and we move on. This does not cause any login failures so it will not lock out any accounts. This generates a Windows event ID [4768](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4768) if Kerberos logging is enabled.

 **Setup:**
we can download [precompiled binaries](https://github.com/ropnop/kerbrute/releases/latest) for the tool for testing from Linux, Windows, and Mac, or we can compile it ourselves.
```bash
sudo git clone https://github.com/ropnop/kerbrute.git
make help
# help:            Show this help.
# windows:  Make Windows x86 and x64 Binaries
# linux:  Make Linux x86 and x64 Binaries
# all:  Make Windows, Linux and Mac x86/x64 Binaries
make linux 
make windows
ls dist/ # kerbrute_linux_amd64, kerbrute_windows_amd64.exe
cd dist ; sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
kerbrute
```

 **Enumerating Users with Kerbrute**
```bash
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```
 **==RESULTS:==**
- **We confirmed 56 valid users in the  domain. Now we can use this list for targeted password spraying attacks.**

### Identifying Potential Vulnerabilities

The [local system](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account) account `NT AUTHORITY\SYSTEM` is a built-in account in Windows operating systems. It has the highest level of access in the OS and is used to run most Windows services. It is also very common for third-party services to run in the context of this account by default. A `SYSTEM` account on a `domain-joined` host will be able to enumerate Active Directory by impersonating the `computer account`, which is essentially just another kind of user account. Having SYSTEM-level access within a domain environment is nearly equivalent to having a domain user account.

There are several ways to gain SYSTEM-level access on a host, including but not limited to:

- Remote Windows exploits such as MS08-067, EternalBlue, or BlueKeep.
- Abusing a service running in the context of the `SYSTEM account`, or abusing the service account `SeImpersonate` privileges using [Juicy Potato](https://github.com/ohpe/juicy-potato). This type of attack is possible on older Windows OS' but not always possible with Windows Server 2019.
- Local privilege escalation flaws in Windows operating systems such as the Windows 10 Task Scheduler 0-day.
- Gaining admin access on a domain-joined host with a local account and using Psexec to launch a SYSTEM cmd window

By gaining SYSTEM-level access on a domain-joined host, you will be able to perform actions such as, but not limited to:

- Enumerate the domain using built-in tools or offensive tools such as BloodHound and PowerView.
- Perform Kerberoasting / ASREPRoasting attacks within the same domain.
- Run tools such as Inveigh to gather Net-NTLMv2 hashes or perform SMB relay attacks.
- Perform token impersonation to hijack a privileged domain user account.
- Carry out ACL attacks.