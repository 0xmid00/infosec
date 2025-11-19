## 1- Command Injection Prevention

####  System Commands

Using functions that execute system commands is dangerous, especially when combined with user input. Even indirect influence on these functions may result in command injection.  
We should avoid system command execution and instead use safe built-in language functions.  
Example: in PHP, use `fsockopen` instead of `system("ping ...")`.

When system commands are absolutely required:
- **Never use raw user input**
- **Always validate and sanitize user input**
- **Use these functions only when no safer alternative exists**



#### Input Validation
All user input must be validated to ensure it matches the expected format.  
Validation must happen **both on the front-end and back-end**.

Example – PHP built-in filter
```php
if (filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
    // call function
}
```
 Example – Regex validation (JavaScript)
```javascript
if(/^(25[0-5]...SNIP...$/.test(ip)){
    // call function
}
```

Both PHP and NodeJS have libraries to validate inputs (e.g., `is-ip`).



#### Input Sanitization
The most critical defense against injection vulnerabilities.  
Sanitization removes unnecessary special characters **after** validation.

PHP example
```php
$ip = preg_replace('/[^A-Za-z0-9.]/', '', $_GET['ip']);
```

JavaScript example
```javascript
var ip = ip.replace(/[^A-Za-z0-9.]/g, '');
```

 NodeJS example (DOMPurify)
```javascript
var ip = DOMPurify.sanitize(ip);
```
Escaping functions (e.g., `escapeshellcmd`) can be used, but **escaping is not reliable**, as shown during the module.
#### Server Configuration

Secure server configuration reduces the impact of command injection even if vulnerabilities exist.

**Recommended configurations**

- Enable WAF features (e.g., Apache `mod_security`, Cloudflare, Fortinet, Imperva)
- Run services under **least privilege** (e.g., user `www-data`)
- Disable dangerous functions (`disable_functions = system, …` in php.ini)
- Restrict file access scope (e.g., `open_basedir = /var/www/html`)
- Reject double encoding and non-ASCII URLs
- Avoid using outdated server modules/libraries (e.g., PHP CGI)

Even with all protections, penetration testing remains necessary.  
Large applications may contain millions of lines of code—**one mistake is enough** to introduce a command injection vulnerability.
