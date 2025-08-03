# Kerberos, DNS, LDAP, MSRPC
## Kerberos

Kerberos has been the default **authentication protocol** for domain accounts in AD
run port **88** (both TCP and UDP) on **domain controllers** 
Kerberos is a stateless authentication protocol based on tickets.
Domain Controllers have a Kerberos Key Distribution Center (KDC) that issues tickets

#### Kerberos Authentication Process

||
|---|
|1. When a user logs in, their password is used to encrypt a timestamp, which is sent to the Key Distribution Center (KDC) to verify the integrity of the authentication by decrypting it. The KDC then issues a Ticket-Granting Ticket (TGT), encrypting it with the secret key of the krbtgt account. This TGT is used to request service tickets for accessing network resources, allowing authentication without repeatedly transmitting the user's credentials. This process decouples the user's credentials from requests to resources.|
|2. The KDC service on the DC checks the authentication service request (AS-REQ), verifies the user information, and creates a Ticket Granting Ticket (TGT), which is delivered to the user.|
|3. The user presents the TGT to the DC, requesting a Ticket Granting Service (TGS) ticket for a specific service. This is the TGS-REQ. If the TGT is successfully validated, its data is copied to create a TGS ticket.|
|4. The TGS is encrypted with the NTLM password hash of the service or computer account in whose context the service instance is running and is delivered to the user in the TGS_REP.|
|5. The user presents the TGS to the service, and if it is valid, the user is permitted to connect to the resource (AP_REQ).|

```bash
Client             KDC                Service
  |                 |                   |
  |-- AS-REQ ------>|                   |  # Request TGT (includes username, timestamp(encrypted w/ User hash))
  |<-- AS-REP ------|                   |  # Response:
  |                 |                   |     - TGT (encrypted w/ krbtgt hash)
  |                 |                   |     - Session Key (encrypted w/ user's NT hash)
  |-- TGS-REQ ----->|                   |  # Send TGT + request for service ticket
  |<-- TGS-REP -----|                   |  # Response:
  |                 |                   |     - Service Ticket (encrypted w/ service account NT hash)
  |                 |                   |     - Session Key (encrypted w/ user's session key)
  |-- AP-REQ ------------------------->|  # Send Service Ticket + authenticator (timestamp)
  |<-- Access Granted (if valid) ------|  # Service validates and grants access


```

![Kerberos authentication process: Client requests TGT from KDC, receives TGT, requests TGS, receives TGS, and accesses database server. Includes steps for user login and ticket encryption.](https://academy.hackthebox.com/storage/modules/74/Kerb_auth.png)

## DNS 
- **DNS is essential for AD DS**: It helps clients (PCs, servers) find Domain Controllers (DCs) and enables DCs to communicate. 
- run port **53** (both TCP and UDP) on **domain controllers**,UDP port 53 is the default, but it falls back to TCP when no longer able to communicate and DNS messages are larger than 512 bytes.
    
- **DNS resolves hostnames to IP addresses** on both internal networks and the internet.
    
- **AD uses service records (SRV)** stored in the **DNS database** to help clients find services (like DCs, printers, file servers).
    
- **Dynamic DNS (DDNS)** automatically updates DNS records when IPs change, avoiding manual errors.
    
- When a client joins the domain:
    
    - It queries DNS for an **SRV record** of a DC.
        
    - DNS returns the **DC’s hostname**, then the client gets the **IP address**.

**examples:**
```bash
# Forward DNS Lookup
# perform a nslookup for the domain name
nslookup INLANEFREIGHT.LOCAL#=> <IP> retrieve the Domain Controller ip addr 

# Reverse DNS Lookup
nslookup <IP> #=> ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL , obtain the DNS name of a single host

# Finding IP Address of a Host
nslookup <HOSTNAME/FQDN Name> #=> <IP>
```

## LDAP
 LDAP(RFC 4511 for  LDAPV3 ) is how systems in the network environment can "speak" to AD.
 run on port **389**, and LDAP over SSL (LDAPS) communicates over port **636**.
 
 An LDAP session begins by first connecting to an LDAP server, also known as a Directory System Agent. The Domain Controller in AD actively listens for LDAP requests, such as security authentication requests.
 ![Diagram showing LDAP process: Client application requests user info from API Gateway, which queries Active Directory via LDAP, and returns user info.](https://academy.hackthebox.com/storage/modules/74/LDAP_auth.png)
 
 you may come across organization while performing an assessment that do not have AD but are using LDAP, meaning that they most likely use another type of LDAP server such as [OpenLDAP](https://en.wikipedia.org/wiki/OpenLDAP).
#### AD LDAP Authentication

In **Active Directory environments**, when a **Windows user logs in**, authentication is **done by Kerberos**, **not LDAP**.However, when an **application or non-Windows system** connects to AD using LDAP
LDAP is set up to authenticate credentials against AD using a "BIND" operation to set the authentication state for an LDAP session. There are two types of LDAP authentication.

**1- Simple Authentication:**  
Basic LDAP bind method. Can be anonymous, unauthenticated, or use username and password. Common in legacy or non-Windows systems. Sends credentials directly to the LDAP server.

**2- SASL Authentication:**  
Uses external auth methods like Kerberos to authenticate to LDAP. LDAP sends challenge-response messages via the chosen method. More secure because it separates authentication from the LDAP protocol.
> LDAP authentication messages are sent in cleartext by default so anyone can sniff out LDAP messages on the internal network. It is recommended to use TLS encryption or similar to safeguard this information in transit.

## MSRPC

RPC (Remote Procedure Call) is  an interprocess communication technique used for client-server model-based applications. Windows systems use MSRPC to access systems in Active Directory using four key RPC interfaces:

|Interface Name|Description|
|---|---|
|`lsarpc`|A set of RPC calls to the [Local Security Authority (LSA)](https://networkencyclopedia.com/local-security-authority-lsa/) system which manages the local security policy on a computer, controls the audit policy, and provides interactive authentication services. LSARPC is used to perform management on domain security policies.|
|`netlogon`|Netlogon is a Windows process used to authenticate users and other services in the domain environment. It is a service that continuously runs in the background.|
|`samr`|Remote SAM (samr) provides management functionality for the domain account database, storing information about users and groups. IT administrators use the protocol to manage users, groups, and computers by enabling admins to create, read, update, and delete information about security principles. Attackers (and pentesters) can use the samr protocol to perform reconnaissance about the internal domain using tools such as [BloodHound](https://github.com/BloodHoundAD/) to visually map out the AD network and create "attack paths" to illustrate visually how administrative access or full domain compromise could be achieved. Organizations can [protect](https://stealthbits.com/blog/making-internal-reconnaissance-harder-using-netcease-and-samri1o/) against this type of reconnaissance by changing a Windows registry key to only allow administrators to perform remote SAM queries since, by default, all authenticated domain users can make these queries to gather a considerable amount of information about the AD domain.|
|`drsuapi`|drsuapi is the Microsoft API that implements the Directory Replication Service (DRS) Remote Protocol which is used to perform replication-related tasks across Domain Controllers in a multi-DC environment. Attackers can utilize drsuapi to [create a copy of the Active Directory domain database](https://attack.mitre.org/techniques/T1003/003/) (NTDS.dit) file to retrieve password hashes for all accounts in the domain, which can then be used to perform Pass-the-Hash attacks to access more systems or cracked offline using a tool such as Hashcat to obtain the cleartext password to log in to systems using remote management protocols such as Remote Desktop (RDP) and WinRM.|