## 1- Preventing File Upload Vulnerabilities
#### Extension Validation

- File extension validation is the first layer of defense.
- Best practice: **use both a whitelist and a blacklist**
- Whitelist = allowed safe extensions.
- Blacklist = block dangerous extensions in case whitelist is bypassed (`shell.php.jpg`).
- Backend + frontend validation should both be used.
- Blacklist checks for the extension **anywhere** in the filename.
- Whitelist checks for extension **only at the end** of the filename.

**Key Point**: Whitelist + blacklist provides maximum safety  
**Key Point**: Frontend validation reduces mistakes but backend is mandatory

#### Content Validation

- Extension alone is not enough — file content must match the expected type.
- Validate:
    - File extension
    - File signature (magic bytes)
    - MIME type (from header and server-side detection)
- Both MIME type values must match the expected type.
- Prevents uploading files like `image.png` that actually contain PHP code.

**File Signature**: Helps detect true file type  
**MIME Type**: Cross-checks header vs server detection

#### Upload Disclosure

- Do **not** expose upload directories.
- Users should only download files through a controlled script (e.g., `download.php`).
- This prevents direct execution of malicious scripts.
- Add strict **authorization checks** to avoid IDOR.
- Validate file paths strictly to prevent **LFI**.
- Block direct access to uploads directory (return **403 Forbidden**).


- Use secure HTTP headers:
    - **Content-Disposition**: force download
    - **Content-Type**: correct MIME type
    - **X-Content-Type-Options: nosniff**: prevent MIME sniffing
- Randomize stored filenames; store original names in a database.
- Helps prevent injection attacks through filenames.
- Ideally store uploaded files on a **separate server or container**.
- Use isolation mechanisms such as `open_basedir`.

**Randomization**: Prevents guessing file names  
**Authorization**: Prevents IDOR  
**Isolation**: Limits RCE impact

#### Further Security
- Disable dangerous system-execution functions (e.g., `exec`, `shell_exec`, `system`).
- Disable detailed error messages — avoid leaking:
    - File paths
    - Upload folder names
    - Raw server errors

- Additional measures:
    - Limit file size
    - Keep libraries updated
    - Scan uploads for malware
    - Use a WAF as a secondary defense layer
