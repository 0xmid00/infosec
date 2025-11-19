## 1- Intro to Command Injections

A Command Injection vulnerability allows attackers to execute system commands on the back-end server due to improper handling of user input. If user-supplied data is passed into a system command without sanitization, it can be abused to run arbitrary commands and compromise the system.

#### What are Injections
Injection vulnerabilities occur when user input is interpreted as part of a query or code. This allows attackers to alter the intended behavior of the application.

### Common Injection Types
- **OS Command Injection** – user input becomes part of an operating system command
- **Code Injection** – user input is evaluated as code
- **SQL Injection** – user input is inserted into an SQL query
- **XSS/HTML Injection** – user input is rendered directly in HTML

 **Other Injection Types:**
- LDAP Injection
- NoSQL Injection
- HTTP Header Injection
- XPath Injection
- IMAP Injection
- ORM Injection

### OS Command Injections
Occurs when user input directly or indirectly affects a system command executed by the back-end. Web languages provide functions that execute OS commands, and improper use of these functions leads to command injection.

**PHP Example Vulnerability**:
```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```
- `system()`, `exec()`, `shell_exec()` and others can be misused if user input is not sanitized.
- Example vulnerable code uses `$_GET['filename']` directly inside a `touch` command.

**NodeJS Example Vulnerability**:
```javascript
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```
- Functions like `child_process.exec()` and `spawn()` execute OS commands.
- Example vulnerable code places `req.query.filename` directly in a command string.

