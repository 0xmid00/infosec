
## Protected Files

```bash
# Protected Files

#### Hunting for Files
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\

grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1" # Hunting for SSH Keys

cat /home/cry0l1t3/.ssh/SSH.private # Encrypted SSH Keys
--------------------------------------------------------------------------------
## Cracking with John

locate *2john*  # ssh2john # John Hashing Scripts
ssh2john ssh.privet > sshhash  
john --wordlist=rockyou.txt ssh.hash
john ssh.hash --show # show the cracked hash
---------------------------------------------------------------------------------
## Cracking Documents

#### Cracking Microsoft Office Documents
office2john.py Protected.docx > protected-docx.hash
john --wordlist=rockyou.txt protected-docx.hash
john protected-docx.hash --show

#### Cracking PDFs
pdf2john.py PDF.pdf > pdf.hash
john --wordlist=rockyou.txt pdf.hash
```
## Protected Archives
```bash
#### Download All File Extensions
 curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt

## Cracking Archives

### Cracking ZIP
zip2john ZIP.zip > zip.hash
john --wordlist=rockyou.txt zip.hash

### Cracking OpenSSL Encrypted Archives
file GZIP.gzip # openssl enc'd data with salted password
for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done

### Cracking BitLocker Encrypted Drives
bitlocker2john -i Backup.vhd > backup.hashes
grep "bitlocker\$0" backup.hashes > backup.hash
cat backup.hash
hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked
#### mount the vhd file and copy it to local machine
sudo mkdir /media/backup_bitlocker /media/mount
sudo losetup -P /dev/loop100 /mnt/smb_share/backup.vhd
sudo dislocker -v -V /dev/loop100p2 -u /media/backup_bitlocker
sudo mount -o loop,rw /media/backup_bitlocker/dislocker-file /media/mount
ls -la /media/mount
#### clear mounted file
sudo umount /media/mount /media/backup_bitlocker 2>/dev/null
sudo losetup -d /dev/loop100
sudo rm -rf /media/backup_bitlocker /media/mount
mount | grep /media
losetup -a
```