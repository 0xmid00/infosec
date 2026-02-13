```bash
ldapsearch -x \                                                                                                                                                                      127 ↵
  -H ldap://172.16.5.5 \
  -D 'asmith@INLANEFREIGHT.LOCAL' \
  -w 'Welcome1' \
  -b 'DC=INLANEFREIGHT,DC=LOCAL' \
  '(sAMAccountName=solarwindsmonitor)' description

# extended LDIF
#
# LDAPv3
# base <DC=INLANEFREIGHT,DC=LOCAL> with scope subtree
# filter: (sAMAccountName=solarwindsmonitor)
# requesting: description 
#

# SOLARWINDSMONITOR, Service Accounts, Corp, INLANEFREIGHT.LOCAL
dn: CN=SOLARWINDSMONITOR,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
description: *** DO NOT CHANGE ***  8/3/2014: S0lar:S0lar14!

```

![[Pasted image 20260126151856.png]]

