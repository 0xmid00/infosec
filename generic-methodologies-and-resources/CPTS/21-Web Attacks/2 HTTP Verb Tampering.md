## 1- Intro to HTTP Verb Tampering

The HTTP protocol supports multiple methods (“verbs”) that define how a request should be processed. Although developers typically focus on `GET` and `POST`, any HTTP method can be sent to a server. If a server is configured to only accept expected methods, unsupported ones will simply trigger an error page. However, if the server or application accepts additional methods it does not properly handle (like `HEAD` or `PUT`), an attacker may exploit this to bypass security controls or access restricted functionality.

Misconfigurations or incomplete handling of HTTP methods can lead to:
- Authorization bypass
- Access to unintended functionality
- Potential server compromise
### HTTP Verb Tampering

To understand this attack, we must first look at the available HTTP methods. There are nine standard HTTP verbs. Besides `GET` and `POST`, some commonly used methods include:

- **HEAD** – Same as `GET` but returns only headers.
- **PUT** – Writes data to a specified location.
- **DELETE** – Removes a resource.
- **OPTIONS** – Shows supported methods.
- **PATCH** – Applies partial updates.

Some verbs, such as `PUT` and `DELETE`, are highly sensitive because they can modify or remove server-side resources. If a server is not correctly configured to restrict these methods, attackers can use them to manipulate backend files or escalate access. Verb Tampering often arises due to mistakes in either server configuration or application logic.

#### Insecure Configurations

- **Issue**: A server may restrict authentication to specific methods (e.g., only `GET` and `POST`).
- **Impact**: If the server accepts other methods like `HEAD`, an attacker may bypass authentication entirely.

example of A configuration that limits authentication only to `GET` and `POST`:
```xml
<Limit GET POST>
    Require valid-user
</Limit>
```
Even though authentication is applied, methods not included in the `<Limit>` directive may remain unprotected, allowing unauthorized access to protected content.
#### Insecure Coding

**Cause**: Developers apply security filters to only certain HTTP methods, leaving others unfiltered.
example of A sanitization check only validates `GET` parameters:
```php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```
**Sanitization Mismatch**: The filter checks only `GET`, but the query uses `$_REQUEST`, allowing `POST` data to bypass validation.  
**SQL Injection Risk**: Attackers can send malicious input via `POST`, bypassing the filter entirely and exploiting the vulnerability.
**This type of flaw is more common because it stems from developer oversight, while insecure server configurations are generally well-documented and easier to avoid.**


---

## 2- Bypassing Basic Authentication

Exploiting HTTP Verb Tampering is generally straightforward: attackers try alternative HTTP methods to see how the server responds. Automated scanners can usually detect server‑misconfiguration–based Verb Tampering, but they often miss coding‑related issues that require manual testing.  
The most common and easily exploited case involves **insecure web server configurations**, which can enable attackers to bypass HTTP Basic Authentication on protected pages.

 **Why This Happens**
- Web servers may only restrict certain HTTP methods (e.g., `GET` and `POST`).
- Other allowed methods such as `HEAD` may remain unprotected.
- Attackers take advantage of this inconsistency to access restricted functionality without credentials.
#### Identify

When interacting with the provided **File Manager** application, users can create files normally. However, attempting to delete all files via the **Reset** button triggers a **Basic Authentication prompt**. Without valid credentials, the server returns a `401 Unauthorized` response.
![[Pasted image 20251121173652.png]]
![[Pasted image 20251121173656.png]]
To determine what is protected, we inspect the Reset button’s request and find that it targets `/admin/reset.php`. Visiting `/admin` directly also triggers authentication, confirming the entire directory is restricted.

#### Exploit

- The Reset function uses a `GET` request.
- First, attackers test a `POST` request to see if the authentication restriction only applies to `GET`.
- Authentication still triggers, meaning both `GET` and `POST` are protected.

Next, attackers test other allowed HTTP methods. Sending an `OPTIONS` request reveals:
```bash
curl -i -X OPTIONS http://SERVER_IP:PORT/ # Allow: POST,OPTIONS,HEAD,GET
```
- `Allow: POST, OPTIONS, HEAD, GET`
This confirms that `HEAD` requests are permitted.
By intercepting the Reset request and changing the method to `HEAD`, the attacker discovers:
![[Pasted image 20251121173848.png]]
![[Pasted image 20251121173909.png]]
- No authentication prompt appears. and  The response is empty (expected for `HEAD`).
- Returning to the File Manager shows that **all files were deleted**, meaning the Reset action executed successfully without credentials.

---
## 3- Bypassing Security Filters

A common form of HTTP Verb Tampering arises from **insecure coding practices**, where developers create security filters that only inspect specific HTTP methods. If a filter checks only `POST` parameters or only evaluates `GET` variables, attackers can send the same payload using an unfiltered method (e.g., switching from `POST` to `GET`) to bypass the protection entirely.

 Why This Happens:
- Security filters often validate only one request method.
- Switching methods bypasses the filters, allowing malicious payloads through.
- This is frequently seen in filters for injection attacks.

#### Identify

In the **File Manager** application, submitting a filename with special characters (e.g., `test;`) returns:
![[Pasted image 20251121181551.png]]
**“Malicious Request Denied!”**

This means:

- The backend uses input filters to block suspicious patterns.
- Injection attempts appear fully prevented.
- Normal attempts fail regardless of the payload.
However, this protection may only apply to one HTTP metho, making it a candidate for Verb Tampering.
#### Exploit

To test this, we intercept the request in Burp Suite and change the HTTP method.

- The original request is a `POST` or `GET` (depending on the implementation), but the filter may checks only one method.
- Changing the request to another method (e.g., switching from `POST` to `GET`) successfully bypasses the security filter.
![[Pasted image 20251121181729.png]]
![[Pasted image 20251121181800.png]]
- After sending the modified request, the file is created without triggering the **Malicious Request Denied!** message.

To confirm an actual vulnerability bypass, we attempt **Command Injection** using the payload:
```
file1; touch file2;
```
![[Pasted image 20251121181809.png]]
After changing the request method again and sending the request:
![[Pasted image 20251121181820.png]]
- Both `file1` **and** `file2` appear in the File Manager.
- This proves that the filter did **not** process the new HTTP method.
- The backend executed the injected shell command successfully.

---
## 4- Verb Tampering Prevention
To protect against HTTP Verb Tampering vulnerabilities, it's essential to address both **insecure configurations** and **insecure coding practices**. These vulnerabilities often arise from improper handling of HTTP methods, which can leave parts of a web application exposed to unauthorized access. This section outlines how to prevent such attacks by configuring web servers securely and writing consistent, secure code.

 Prevention Focus
- **Insecure Server Configurations**: Incorrect method restrictions can expose sensitive functionality.
- **Inconsistent Coding**: Not handling HTTP methods uniformly across the application opens doors for attacks.

### Insecure Configuration
HTTP Verb Tampering vulnerabilities can occur in any modern web server, like **Apache**, **Tomcat**, and **ASP.NET**, when access is only restricted to specific HTTP methods, leaving other methods unprotected.
#### Apache Example
In Apache, if the configuration restricts only `GET` requests to authorized users, other methods such as `POST` or `HEAD` remain unprotected. Here’s an insecure configuration:
```xml
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>
        Require valid-user
    </Limit>
</Directory>
```
- **Problem**: The `<Limit GET>` directive restricts only `GET`, leaving other methods unprotected (e.g., `POST`, `HEAD`).
- **Fix**: Use `<LimitExcept>` to cover all methods except the ones you want to exclude.
#### Tomcat Example
In Tomcat, a similar vulnerability can occur when restricting only specific HTTP methods, like `GET`:
```xml
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```
- **Problem**: Only `GET` is restricted, leaving other methods unprotected (e.g., `POST`, `HEAD`).
- **Fix**: Avoid restricting methods by `http-method` and use a more comprehensive security setup.

#### ASP.NET Example
In ASP.NET, restricting methods like `GET` leads to a similar vulnerability:
```xml
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin">
            <deny verbs="GET" users="*">
        </deny>
        </allow>
    </authorization>
</system.web>
```
- **Problem**: The `allow` and `deny` rules only apply to `GET`, leaving other methods unprotected.
- **Fix**: Explicitly specify all methods using `add/remove` attributes to control access properly.
#### General Prevention for Server Configurations:
- **Avoid limiting access to specific HTTP methods**. Restrict all methods where possible, using directives like `<LimitExcept>` in Apache or similar options in other servers.
- **Consider disabling/denying `HEAD` requests** unless specifically needed, as they can be used for attacks without triggering certain security filters.
### Insecure Coding
While fixing server configurations is straightforward, preventing **inconsistent use of HTTP methods** in code is trickier. This vulnerability arises when security filters only check one type of HTTP method (e.g., `POST`), but other methods (e.g., `GET`) are still processed by vulnerable code.
#### PHP Example:
In the **File Manager** application, the following PHP code improperly checks input from only `POST` parameters:
```php
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
        system("touch " . $_REQUEST['filename']);
    } else {
        echo "Malicious Request Denied!";
    }
}
```
- **Problem**: The `preg_match` filter only checks `$_POST['filename']`, but the `system` command uses `$_REQUEST['filename']`, which includes both `GET` and `POST` parameters. If a malicious `GET` request is sent (with a harmful payload like `file1; touch file2;`), it bypasses the `preg_match` check and gets executed.
- **Fix**: Ensure consistent use of HTTP methods. Use `$_POST` or `$_GET` (but not both) consistently in your code, and always check all HTTP parameters.

#### General Prevention for Insecure Coding:
- **Consistent HTTP Method Handling**: Ensure that security filters apply to all HTTP methods uniformly. For example, use `$_REQUEST` for all parameters, but ensure your validation checks cover both `GET` and `POST`.
- **Expand Scope in Security Filters**: Don’t limit filters to one method (e.g., `POST`). Test all input across all HTTP methods to ensure no method is bypassed.
#### Common Functions to Test All HTTP Methods:

| Language | Function                        |
| -------- | ------------------------------- |
| PHP      | `$_REQUEST['param']`            |
| Java     | `request.getParameter('param')` |
| C#       | `Request['param']`              |
By testing all request parameters, regardless of the method, you can avoid vulnerabilities that result from inconsistent method handling.

