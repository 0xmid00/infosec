## Introduction to Pivoting, Tunneling, and Port Forwarding

```bash
# Pivoting, Tunneling, and Port Forwarding

1. Pivoting = Use a compromised host to reach new network segments.
2. Tunneling = Hide/route traffic through protocols (e.g., SSH, HTTP) to bypass detection.
3. Lateral Movement = Move across systems in the same network to escalate access.
```
## The Networking Behind Pivoting
```bash
## IP Addressing & NICs
NICs #  betwork interface cards
# ifconfig :
lo # loop back interface
tun0 # vertual network interface
eth0 # ethernet network interface

## Routing
### Displays current routing table 
ip route 
netstat -r 
```