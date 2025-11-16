## 1- Parameter Fuzzing - GET
Fuzz GET params with ffuf using a parameter wordlist:  
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs <default_response_size> 
``` 
**Explanation: FUZZ replaces parameter names; -fs filters out the default/false-response size so real parameters show. The found parameter returned a "deprecated" message (no active access).**
## 2- Parameter Fuzzing - POST
Fuzz POST params with ffuf using a parameter wordlist:  
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs <default_response_size>
```
Found hits (e.g., same deprecated param and "id"). Verify with curl:  
```bash
curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'
```
**Response: "Invalid id!" — server recognizes the id parameter.**

or using the file  request
```bash
ffuf -request req.txt -request-proto http -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
```
## 3- Value Fuzzing
Create numeric wordlist:  
```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```
Fuzz parameter values with ffuf (POST):  
```bash
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs <default_response_size>
```
Verify found value with curl:  
```bash
curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FOUND_VALUE' -H 'Content-Type: application/x-www-form-urlencoded'
```
**Explanation: FUZZ replaces the parameter value; filter out the default/noise size so the real id that returns the flag stands out.**
