## 1- Brute Force Attacks
Understanding the math shows why length and charset matter. Small increases in length or adding character types explode the search space and make brute forcing far harder.
**Possible Combinations = Character Set Size^Password Length**
==The Importance of Length and Charset==
Examples:
*6 chars (a-z) = 26^6 = 308,915,776*
*8 chars (a-z) = 26^8 = 208,827,064,576*
*8 chars (a-z,A-Z) = 52^8 = 53,459,728,531,456*
*12 chars (all ASCII ~94) = 94^12 ≈ 4.76e20*

Even powerful hardware is limited: more guesses per second reduces time, but huge search spaces remain impractical to brute force.
==Hardware impact (illustrative)==
*Basic computer ≈ 1 million guesses/sec — suitable for simple passwords*
*Supercomputer ≈ 1 trillion guesses/sec — speeds up cracking but complex passphrases still take impractical time*

==PIN brute-force demo== 
Try all 0000–9999 (10,000 combos) by sending requests to /pin endpoint
Script example iterates every PIN, checks response, stops when correct PIN found
Demonstrates how small keyspaces like 4-digit PINs are trivial to brute force

---

## 2- Dictionary Attacks
#### The Power of Words

Dictionary attacks exploit how people choose memorable passwords instead of secure ones. Attackers use wordlists of common words, names, and phrases to try likely passwords quickly. A targeted wordlist tailored to the audience or system greatly raises success rates.

#### Brute Force vs. Dictionary Attack

**Brute Force** tests every possible character combination and can succeed given enough time and resources.  
**Dictionary Attack** tests a precompiled list of likely passwords and is much faster when users pick common or predictable passwords.

#### Feature comparison

- **Efficiency:** Dictionary attacks are faster and less resource-heavy than brute force.
- **Targeting:** Dictionary attacks can be customized to the victim (company names, employees, hobbies).
- **Effectiveness:** Very effective against weak or reused passwords; brute force works against any 
- **Limitations:** Dictionary attacks fail on high-entropy, random passwords.

#### Building and Utilizing Wordlists

Sources and methods to obtain wordlists:

- **Public lists:** Many available online (e.g., SecLists, rockyou.txt).
- **Custom lists:** Built from reconnaissance (names, products, jargon, leaked data).
- **Specialized lists:** Tailored for industries, apps, or a specific company to improve hit rate.
- **Pre-existing tool lists:** Many pentest distributions include common wordlists for quick use.
#### Useful wordlists 

- `rockyou.txt` — large leaked-password list, common for attacks
- `top-usernames-shortlist.txt` — short common username list (for username attempts)
- `xato-net-10-million-usernames.txt` — extensive username list for thorough forcing
- `2023-200_most_used_passwords.txt` — frequently reused passwords as of 2023
- `Default-Credentials/default-passwords.txt` — default device and software creds

---

## 3- Hybrid Attacks
Users often make small predictable changes when forced to update passwords, for example "**Summer2023**" → "**Summer2023!**" or "**Summer2024**". Attackers exploit this behavior.

#### Hybrid Attacks in Action

Start with a dictionary attack using tailored wordlists. If that fails, modify words (append numbers, symbols, increment years) and try those variations. This narrows the search space versus pure brute force but covers likely user choices.

#### The Power of Hybrid Attacks

They combine dictionary precision with targeted brute-force mutations, making them efficient against policy-driven but predictable passwords.

**Example: Filtering Passwords by Policy:**

```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/darkweb2017_top-10000.txt
grep -E '^.{8,}$' wordlist > min8.txt
grep -E '[A-Z]' min8.txt > hasUpper.txt
grep -E '[a-z]' hasUpper.txt > hasLower.txt
grep -E '[0-9]' hasLower.txt > hasNumber.txt
wc -l hasNumber.txt  # e.g., 89
```

==Result: a small, focused list for faster cracking.==
### Credential Stuffing
Attackers use leaked username:password pairs against other services. If users reuse passwords, automation can quickly find valid matches.
#### The Password Reuse Problem
One breach can compromise many accounts. Mitigation: unique passwords, MFA, and password managers.

