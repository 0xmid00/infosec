## 1- Directory Fuzzing
Key options:
- `-w` wordlist (use `:FUZZ` to name it)
- `-u` target URL with `FUZZ` placeholder
- `-t` threads (default 40 in example; don't overload targets)
- `-mc` match status codes (default includes 200/301/403 etc.)
- `-fs` / `-fc` filter by size/status
- `-ic` ignore comment lines in wordlists
- `-o` output to file
Example :
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ  -u http://SERVER_IP:PORT/FUZZ -t 40 -ic
```

## 2- Page Fuzzing 
- Goal: Find hidden files/pages inside a directory by fuzzing filename + extension.
####  Step 1  Find extension:
  - Use extensions wordlist (**web-extensions.txt**) and fuzz index:  
    ```bash
    ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ  -u http://SERVER_IP:PORT/blog/indexFUZZ
    ```
  > the lists include the leading dot (e.g., `.php`) so don’t add an extra dot.
####  Step 2  Fuzz filenames with discovered extension:
  - the `.php` is valid, fuzz names from directory list:  
    ```bash
    ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ  -u http://SERVER_IP:PORT/blog/FUZZ.php -ic
    ```
- Read results:
  - Hits with `Status: 200` (or different Size/Words) indicate accessible pages.
  - `Size: 0` often = empty page; non-zero size likely has content to inspect.

#### full fuzzing (mine method)
```bash
ffuf -w names.txt:FUZZ -u http://TARGET/FUZZ -e ".php,.inc,.env,.bak,.old,.backup,.sql,.db,.log,.zip,.tar,.tar.gz,.7z,.html,.htm,.jsp,.jspx,.asp,.aspx,.xml,.json,.yml,.yaml,.ini,.toml,.config,.conf,cnf,.crt,.git,.war,.jar,.txt"
```

## 3- Recursive Fuzzing
Recursive fuzzing automatically scans discovered directories and their subdirectories to find files, but can explode in time/requests so set a depth limit. In ffuf use `-recursion` plus `-recursion-depth` to control how deep it goes, `-e .php` to test PHP pages, and `-v` to show full URLs. Result: more requests (larger wordlist with extensions) but you gather main site + selected subdirectories in one command.

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e ".php,.inc,.env,.bak,.old,.backup,.sql,.db,.log,.zip,.tar,.tar.gz,.7z,.html,.htm,.jsp,.jspx,.asp,.aspx,.xml,.json,.yml,.yaml,.ini,.toml,.config,.conf,cnf,.crt,.git,.war,.jar,.txt" -v -ic
```
