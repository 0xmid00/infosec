```bash
# in Windows Plink used to create dynamic port forwards and SOCKS proxies if SSH not available.
# HACKER : 10.10.x.x, M1:10.10.x.x/172.16.x.x, M2:172.16.x.x
# HACKER(windows):9050==>M1(ubuntu):SOCKS==>M2(windows)

cmd > plink -ssh -D 9050 M1-USER@<M1-ip> # dynamic port frw

# then use Proxifier.exe (https://www.proxifier.com) to confige SOCKS server for 127.0.0.1 and port 9050, video https://www.youtube.com/watch?v=ujsb2pLZUiw
mstsc.exe # RDP 
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