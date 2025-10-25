## 1- Introduction
**Brute forcing :**
- Trial-and-error method to crack passwords/keys by trying many combinations.
- Like testing every key on a huge keyring until one opens the lock.
#### How it works 

1. Start attack (tool/software).
2. Generate candidate (wordlist or charset + length).
3. Apply candidate to target (login, encrypted file).
4. Check result — success → access; fail → repeat.

#### Factors that affect success

- Password complexity (length, mixed chars).
- Attacker compute power (CPUs/GPUs/FPGAs).
- Defenses (lockouts, MFA, CAPTCHAs, rate-limiting)
## Common types (one-line)

- **Simple brute force** — try all combos (no prior info).
- **Dictionary attack** — use common passwords list (e.g., rockyou).
- **Hybrid** — dictionary + mutations (add numbers/symbols).
- **Credential stuffing** — reuse leaked username:password pairs.
- **Password spraying** — few common passwords against many users.
- **Rainbow tables** — precomputed hash→password lookups.
- **Reverse brute force** — one leak password against many usernames.
- **Distributed brute force** — spread work across multi machines.
#### When used in pentesting

- When other access methods fail.
- To test weak password policies / password reuse.
- To target high-value accounts for privilege escalation.

## 2- Password Security Fundamentals

The effectiveness of brute-force attacks depends on password strength. Strong passwords make brute forcing exponentially harder by increasing the combinations attackers must try.

#### The Importance of Strong Passwords

Passwords are the first line of defense. Longer and more random passwords greatly increase the time and resources required for an attacker to succeed.

#### The Anatomy of a Strong Password

Length: aim for 12+ characters; each extra character multiplies combinations.  
Complexity: mixed cases, numbers, symbols help, but long passphrases are often best.  
Uniqueness: use a distinct password for each account to limit breach impact.  
Randomness: avoid dictionary words, personal info, and common phrases.
#### Common Password Weaknesses

Short passwords under eight characters are easy to brute-force.  
Dictionary words, common phrases, and names are vulnerable to dictionary attacks.  
Personal info (birthdays, pet names) can be guessed from public data.  
Reusing passwords across sites amplifies damage if one account is breached.  
Predictable patterns like 123456, qwerty, or simple substitutions are widely known to attackers.
#### Password Policies

Minimum length, complexity rules, expiration, and password history are common controls.  
Poorly designed policies can produce insecure workarounds; balance security with usability.
#### The Perils of Default Credentials

Default passwords and usernames on devices are easy targets and often compiled into attacker lists.  
Trying a few common defaults can grant access without heavy brute forcing.  
Default credentials are low-hanging fruit that frequently lead to breaches.

| Device/Manufacturer | Default Username | Default Password | Device Type     |
| ------------------- | ---------------: | ---------------: | --------------- |
| Linksys Router      |            admin |            admin | Wireless Router |
| D-Link Router       |            admin |            admin | Wireless Router |
```bash
https://github.com/ihebski/DefaultCreds-cheat-sheet 
creds search D-Link # admin:admin
```

Default usernames like admin or root are widely known and reduce attacker effort.  
Even if passwords are changed, keeping default usernames narrows the attack surface.
### Brute-forcing and Password Security

Weak passwords are the main barrier attackers must overcome.  
Pentesters evaluate password policies and likely user behavior to estimate brute-force success.  
Tool choice and resource planning depend on password complexity.  
Default credentials are prioritized as quick entry points and should be checked first.