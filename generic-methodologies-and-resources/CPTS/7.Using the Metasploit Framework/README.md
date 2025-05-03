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
