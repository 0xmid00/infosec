## Interacting with Common Services

```bash
## Server Message Block (SMB)
# cmd
[WINKEY] & [R] + \\192.168.220.129\Finance\
dir \\192.168.220.129\Finance\ # Windows CMD - DIR
net use n: \\192.168.220.129\Finance  # map shared folder to n local drive
net use n: \\192.168.220.129\Finance /user:plaintext Password123
dir n: /a-d /s /b | find /c ':\' # count the files on the n maped drive
dir n:\*cred* /s /b # search for *cred* files
findstr /s /i cred n:\*.* # search on the file contetnt for any "cred" word

# Powershell
Get-ChildItem \\192.168.220.129\Finance\ # list the shared folder
New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" #  map n driver to the shared folder
## with user:password 
$username = 'plaintext'
$password = 'Password123'
$secpassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
N:
(Get-ChildItem -File -Recurse | Measure-Object).Count # count all files
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File # search for *cred* file
Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List # search in file content for cred word
# linux
sudo mkdir /mnt/Finance
sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance 
mount -t cifs //192.168.220.129/Finance /mnt/Finance -o username=USER,password=PASS # with authentication
find /mnt/Finance/ -name *cred* # search for file name 
grep -rn /mnt/Finance/ -ie cred # search for file content

# Other Services
## email
thunderbird
evolution # https://www.youtube.com/watch?v=xelO2CiaSVs

## Databases

### MSSQL
sqsh -S 10.129.20.13 -U username -P Password123 ### Linux - SQSH
sqlcmd -S 10.129.20.13 -U username -P Password123 #### Windows - SQLCMD

### MySQL
mysql -u username -pPassword123 -h 10.129.20.13 #  Linux - MySQL
mysql.exe -u username -pPassword123 -h 10.129.20.13 # Windows - MySQL

### GUI Application
https://www.youtube.com/watch?v=gU6iQP5rFMw # dbeaver #  Video - Connecting to MSSQL DB using dbeaver
https://www.youtube.com/watch?v=PeuWmz8S6G8 # Video - Connecting to MySQL DB using dbeaver
```

## Latest Email Service Vulnerabilities
```bash



```