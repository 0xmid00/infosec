## Dynamic/Local Port Forwarding with SSH and SOCKS Tunneling
**Local Port Forwarding**
![local port forwarding](https://academy.hackthebox.com/storage/modules/158/11.png)

**Dynamic Port Forwarding**
![dynamic port forwarding](https://academy.hackthebox.com/storage/modules/158/22.png)
```bash
#1- SSH Local Port Forwarding
  
  # attack host (10.10.15.x) , target host (10.129.x.x) (ex.10.129.202.64)

  nmap -sT -p22,3306 10.129.202.64 # 22 ssh open, [3306] mysql close
  # port 3036 mysql hosted localy , we want access mysql from our attack host

  # Executing the Local Port Forward
  ssh -L 1234:localhost:3306 ubuntu@10.129.202.64 
  # Forward local port 1234 → target's localhost:3306
  
  # Confirming Port Forward with Netstat
  netstat -antp | grep 1234

  # Confirming Port Forward with Nmap
  nmap -v -sV -p1234 localhost
  
  # Forwarding Multiple Ports
  ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
------------------------------------------------------------------------------
#2- dynamic port forwarding

  # attack host (10.10.15.x) , target host (10.129.x.x) & (172.16.x.x)
  # SSH listens on localhost:9050 and forwards data to 172.16.5.0/23 over the tunnel.
  
  #  Enabling Dynamic Port Forwarding with SSH
  ssh -D 9050 ubuntu@10.129.202.64
  tail -4 /etc/proxychains4.conf #=> socks4  127.0.0.1 9050

  # Using Nmap with Proxychains
  proxychains nmap -v -sn 172.16.5.1-200 # scan for alive hosts to pivot
  [!] # proxychains can handel only full TCP connect scan
  [!] # Windows Defender firewall blocks ICMP requests (traditional pings) by default
  proxychains nmap -v -Pn -sT 172.16.5.19 # enum , 3389 open (rdp)

  ## Using Metasploit with Proxychains
  use scanner/rdp/rdp_scanner 
  set rhosts 172.16.5.19
  run #=> Detected RDP on 172.16.5.19:3389

  # Using xfreerdp with Proxychains
  proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123

```