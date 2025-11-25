## 1- Introduction to Web Attacks

Modern web applications are widely used and increasingly complex, expanding the attack surface for businesses. Because of this, web attacks are among the most common threats and can lead to internal network compromise, data theft, service disruption, and major financial loss. Even internal applications and exposed APIs face similar risks.  
This module introduces three important web attacks, explaining how to detect, exploit, and prevent them.

The module focuses on:

- HTTP Verb Tampering
- Insecure Direct Object References (IDOR)
- XML External Entity (XXE) Injection
#### Web Attacks

##### HTTP Verb Tampering

- **Attack Description**: Exploits web servers that accept unexpected or alternative HTTP methods.
- **Impact**: Can bypass authorization or security controls by using non-standard verbs like `HEAD`, `PUT`, or `DELETE`.
- **Key Idea**: Manipulating the HTTP method may reveal hidden functionality or bypass restrictions.

##### Insecure Direct Object References (IDOR)

- **Attack Description**: Occurs when an application exposes direct references (IDs, file names, sequential numbers) without proper access control.
- **Impact**: Attackers can access other users’ data simply by modifying object identifiers.
- **Key Idea**: Lack of strong authorization checks leads to unauthorized data access.

##### XML External Entity (XXE) Injection

**Vulnerability Origin**: Applications using outdated or misconfigured XML parsers.  
**Attack Potential**:

- **File Disclosure**: Attackers can retrieve sensitive server files, such as configuration files or source code.
- **Credential Theft**: Malicious XML can extract server credentials.
- **Severe Outcomes**: Can escalate to full server compromise or remote code execution.
**Local File Disclosure**: Using external entities to read internal server files.  
**Server Compromise**: Leveraging XXE to gain further access and execute malicious actions.