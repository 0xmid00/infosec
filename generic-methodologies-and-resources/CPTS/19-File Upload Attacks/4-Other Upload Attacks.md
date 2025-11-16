## 1- Limited File Uploads

Even if a file upload form **doesn’t allow arbitrary files**, it can still be abused.  
Some allowed file types (SVG, HTML, XML, images, documents) can introduce **new vulnerabilities**, such as XSS or CSRF.
####  XSS 
##### HTML File Uploads

If the application allows uploading `.html` files:
- They cannot execute PHP , But **JavaScript inside the HTML runs in the victim’s browser**
- Useful for **Stored XSS** and **CSRF** attacks 
##### Image Metadata XSS
If the site displays image metadata after upload:
- You can insert XSS payloads into metadata fields like `Comment`, `Artist`, etc.
```bash
exiftool -Comment='"><img src=1 onerror=alert(window.origin)>' HTB.jpg
```
If the metadata is rendered unsafely, XSS triggers.
>  Changing the image's MIME type to `text/html` may cause some servers to render it as an HTML page → XSS triggers even if metadata is not shown.
##### SVG XSS
- SVG files are **XML-based** and fully capable of containing JavaScript.
==file : HTB.svg:==
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" 
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green"/>
    <script>alert(window.origin);</script>
</svg>
```
#### XXE
- SVG/XML files can include external entities, **we can use it to  read the internal server files** 
==file image.svg==
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

- Reading Application Source Code with PHP filters to extract source files: 
==file image.svg==
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```


- Many formats contain XML internally: like `PDF`, `Word Documents`, `PowerPoint Documents`, among many others. All of these documents include XML data within themOthers
-  We may utilize the XXE vulnerability to enumerate the internally available services or even call private APIs to perform private actions.
#### DoS
Use entity expansion or file references to exhaust memory.
 **ZIP Decompression Bomb:**
- Upload a ZIP containing nested ZIPs → extract to terabytes/petabytes → server crash.

**Pixel Flood (Image Bomb):**
Modify JPG/PNG compression metadata:
- Real image: 500×500
- Fake metadata: 0xffff × 0xffff (4 gigapixels)
Web app tries to allocate huge memory → crash.

**Oversized File Upload**
If the server has no upload size limit  
    → uploading huge files fills storage and kills the server.
**Directory Traversal Upload DoS**
If upload path is vulnerable:(e.g. `../../../etc/passwd`), which may also cause the server to crash



---

## 2- Other Upload Attacks
#### Injections in File Name

- Using malicious file names can trigger command execution if the server uses file names in OS commands.
- Examples: `file$(whoami).jpg`, ``file`whoami`.jpg``, `file.jpg||whoami`.
- If executed inside commands like `mv`, this becomes **Command Injection**.
- File names can also be used for **XSS** (e.g., `<script>alert(1)</script>`) if reflected on the page.
- SQL Injection is possible if file names are used in SQL queries (e.g., `file';select+sleep(5);--.jpg`).
#### Upload Directory Disclosure

- When the application doesn't show the file path, find the upload directory using fuzzing or other vulnerabilities (like **LFI** or **XXE**).
- Triggering errors can leak the upload directory.
- Techniques:
    - Uploading a file with an existing name.
    - Sending two upload requests at the same time.
    - Uploading a very long file name (e.g., 5000 chars).

- Errors may reveal:
    - Upload directory
    - Application paths
    - Additional useful debugging info


#### Windows-Specific Attacks

- Use **reserved characters** (`|`, `<`, `>`, `*`, `?`) to break file operations and leak upload paths.
- Use **reserved names** (`CON`, `COM1`, `LPT1`, `NUL`) — these cannot be created as files → errors disclose paths.
- Exploit **Windows 8.3 short filenames** to overwrite sensitive files.
    - Long filename: `hackthebox.txt`
    - Short equivalent: `HAC~1.TXT`
- Example attack:
    - Upload `WEB~1.CON` to overwrite `web.conf`
- Possible results:
    - Information leakage
    - DoS
    - Overwriting sensitive system files
#### Advanced File Upload Attacks
Some processing steps can be abused when the server automatically handles uploaded files:  Video encoding, Compression,  Renaming,  Thumbnail generation ,Parsing libraries

These may introduce vulnerabilities in specific libraries or custom implementations.
- Example: `ffmpeg` AVI file → XXE exploit
- Custom code = higher chance of unique vulnerabilities
- Bug bounty reports are great resources to learn such advanced attack scenarios
