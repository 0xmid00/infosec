 Defense techniques to prevent SQLi attacks
### Input Sanitization

Escape dangerous characters before using input in SQL.
```php
// Use mysqli_real_escape_string() to escape ' " \ etc.
$username = mysqli_real_escape_string($conn, $_POST['username']);
$password = mysqli_real_escape_string($conn, $_POST['password']);
$query = "SELECT * FROM logins WHERE username='$username' AND password='$password'";
```
**Prevents breaking out of string literals and injection.**
### Input Validation

Whitelist expected characters and reject the rest.
```php
$pattern = "/^[A-Za-z\s]+$/"; // letters + spaces only
$code = $_GET["port_code"];
if(!preg_match($pattern, $code)) die("Invalid input!");
$q = "SELECT * FROM ports WHERE port_code ILIKE '%$code%'";
```
**Rejects malformed or crafted payloads early.**
### Least-Privilege DB Users
Use DB accounts limited to required permissions.
```sql
CREATE USER 'reader'@'localhost';
GRANT SELECT ON ilfreight.ports TO 'reader'@'localhost' IDENTIFIED BY 'p@ssw0Rd!!';

SELECT * FROM ilfreight.credentials; -- denied to user 'reader'@'localhost' for table 'credentials'
```
The snippet above confirms that the `reader` user cannot query other tables in the `ilfreight` database. The user only has access to the `ports` table that is needed by the application.
**Avoid using admin/superuser accounts for web apps.**

#### Web Application Firewall (WAF)

Deploy a WAF (ModSecurity, Cloudflare, etc.) to filter known malicious patterns such as `INFORMATION_SCHEMA`.  
**Provides an additional defensive layer when code has gaps.**
### Parameterized Queries

Use placeholders so the driver handles escaping and typing.
```php
$query = "SELECT * FROM logins WHERE username=? AND password=?";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, 'ss', $username, $password);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
```
**Removes direct concatenation of user input into SQL.**
#### Conclusion
The list above is not exhaustive, and it could still be possible to exploit SQL injection based on the application logic. The code examples shown are based on PHP, but the logic applies across all common languages and libraries.