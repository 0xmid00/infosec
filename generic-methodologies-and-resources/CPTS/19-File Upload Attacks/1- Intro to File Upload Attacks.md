

# Intro to File Upload Attacks
Uploading user files is a common feature in modern web applications, allowing users to upload images, documents, or other files. However, if the uploaded files are not properly filtered or validated, attackers can exploit this functionality to execute malicious code and compromise the back-end server.

File upload vulnerabilities are among the most common in web and mobile applications and are often rated as **High** or **Critical** in CVE reports due to their severe impact.

## Types of File Upload Attacks

The main cause of file upload vulnerabilities is **weak or missing file validation**. When validation fails, attackers can upload harmful files, potentially leading to full server compromise.

### Unauthenticated Arbitrary File Upload

- Occurs when users can upload **any file type** without authentication.
- Allows attackers to directly upload malicious scripts and gain **remote command execution** (RCE).
### Common Exploits

Attackers may upload:
- **Web shells** to execute arbitrary commands.
- **Reverse shells** to gain interactive access to the server.
### Limited Upload Scenarios

Even if the application restricts upload types, other attacks may still be possible if security controls are weak. 
#### Example Attacks

- **XSS (Cross-Site Scripting)**
- **XXE (XML External Entity)**
- **DoS (Denial of Service)**
- **Overwriting system files or configurations**

## Root Causes

- **Insecure coding practices**
    
- **Outdated or vulnerable libraries** used for file handling
    
