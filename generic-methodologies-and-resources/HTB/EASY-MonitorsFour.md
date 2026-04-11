0) 
╰─$ nmap -sV -sC 10.129.10.182 -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-03-04 23:13 CET
Stats: 0:13:08 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 91.77% done; ETC: 23:28 (0:01:11 remaining)
Nmap scan report for 10.129.10.182
Host is up (0.23s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx
|_http-title: Did not follow redirect to http://monitorsfour.htb/
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows


1)  http://monitorsfour.htb/.env

DB_HOST=mariadb
DB_PORT=3306
DB_NAME=monitorsfour_db
DB_USER=monitorsdbuser
DB_PASS=f37p2j8f4t0r

  mysql -u monitorsdbuser -p f37p2j8f4t0r -h monitorsfour.htb -P 3306 monitorsfour_db --skip-ssl  no work
http://monitorsfour.htb/controllers/*****  INTERSTING 
,
curl 'http://monitorsfour.htb/api/v1/auth' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://monitorsfour.htb' -H 'Connection: keep-alive' -H 'Referer: http://monitorsfour.htb/login' -H 'Cookie: PHPSESSID=5f2daf0772918f0408f50757f39c1206' -H 'Upgrade-Insecure-Requests: 1' -H 'Priority: u=0, i' --data-raw 'username=admin&password=admin'