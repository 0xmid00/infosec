## 1- Introduction
XSS happens when a website does not sanitize user input and allows attackers to inject JavaScript into a page. The script executes in the victim’s browser and can steal cookies, modify content, or perform actions on behalf of the user.
#### What is XSS
User input is inserted into a webpage without proper filtering. When victims open the page, the browser executes the injected JavaScript. XSS is executed only in the browser, not directly on the server. It is high probability and medium impact, so it must be fixed.
#### XSS Attacks

JavaScript can:

- Steal cookies or tokens
- Change user settings
- Perform malicious actions using the victim’s session (make posts ...)
- Redirect users
- Display fake login forms
- Attackers are limited by browser protections (sandbox, same-origin), but advanced exploitation can bypass them.
#### Types of XSS
**Stored XSS**: Input saved in DB and shown to users (comments, profiles)  
**Reflected XSS**: Input returned immediately (URL parameters, search fields)  
**DOM XSS**: Executed purely on client side (JavaScript manipulates data in DOM)


---
## 2- Stored XSS

Stored (persistent) XSS occurs when injected payloads are saved on the server (database) and executed every time a page is viewed. It affects any visitor of the page and is high-impact because removal requires fixing stored data.
#### XSS Testing Payloads

Basic verification payload that shows where the script runs:
```html
<script>alert(window.origin)</script>
```
View page source (Ctrl+U) to confirm the payload is stored and rendered.

Alternative checks:
```html
<plaintext>test
```

```html
<script>print()</script>
```
```html
<script>alert(document.cookie)</script>
```
#### Notes

- If the payload appears after refresh and triggers for other users, it is Stored XSS.
> Many modern web applications utilize cross-domain IFrames to handle user input, so that even if the web form is vulnerable to XSS, it would not be a vulnerability on the main web application. This is why we are showing the value of `window.origin` in the alert box, instead of a static value like `1`. In this case, the alert box would reveal the URL it is being executed on, and will confirm which form is the vulnerable one, in case an IFrame was being used.

---

## 3- Reflected XSS

Reflected XSS is a non-persistent XSS where input sent to the server is returned in the response without proper sanitization. The payload executes only for the requesting user (or anyone who visits a crafted URL) and does not persist across page reloads.
#### How it works
The attacker crafts input that the server reflects back (error message, search result, confirmation). When a victim opens the URL or submits the request containing the payload, the browser executes the injected JavaScript. Because the payload is not stored, the attack is temporary and typically delivered via a crafted link or form.
#### Testing payload
```html
<script>alert(window.origin)</script>
```
#### Delivering to victims
- GET parameter: include payload in URL and send the link to the victim.
- Copy URL from browser or Network panel and share it.
- POST parameter: deliver via a form or phishing page that performs a POST on the victim’s behalf.
- Headers or other reflected locations: some sites reflect values from Referer, User-Agent, or other headers—these can be targeted if attacker can induce the victim to make the request.

---

## 4- DOM XSS

DOM-based XSS is a non-persistent XSS type where the payload is processed entirely in the browser by JavaScript manipulating the DOM. The input never (or not meaningfully) reaches the server; the vulnerability happens when client-side code takes attacker-controlled data and writes it into the page insecurely.

#### Source & Sink

Source: where the attacker-controlled data originates (URL fragment, query param, form input, etc.)  
Sink: where that data is written to the DOM without sanitization (functions that can introduce HTML/JS).
Common sinks:

- `document.write()`
- `element.innerHTML` / `element.outerHTML`
- jQuery methods that insert HTML (`append()`, `after()`, `add()`)

Example extracting a URL param (source):
```javascript
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
```

Example insecure sink:
```javascript
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

### DOM Attacks

Use payloads that execute without `<script>` tags, since many sinks block raw `<script>` insertion.
Payload examples:
```html
<img src=x onerror=alert(window.origin)>
```

```html
<svg onload=alert(window.origin)>
```
#### Delivery to Victime:
we can once again copy the URL from the browser and share it with them, and once they visit it, the JavaScript code should execute.

---
## 5- XSS Discovery

Detect XSS using automated scanners, manual testing, payload lists, and code review. Automated tools speed up discovery; manual review and tailored payloads increase accuracy.
#### Automated Discovery

Scanners perform passive (client-side/DOM) and active (payload injection) checks. Common open-source tools: XSStrike, BruteXSS, XSSer.
```bash
# git clone https://github.com/s0md3v/XSStrike.git
python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"
```
Scanners may return reflections or DOM hits, always manually verify reported findings.
### Manual Discovery
Test inputs and headers (URL params, POST body, Cookie, User-Agent, Referer). Use browser devtools to observe requests and responses. Automate repetitive tests with a custom script when many inputs exist.
#### XSS Payloads
Use curated payload lists ([PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md) or [PayloadBox](https://github.com/payloadbox/xss-payload-list)) and adapt payloads to the injection context (HTML body, attributes, event handlers, CSS). Try small, high-signal payloads first (alerts, onerror) then more obfuscated ones for bypasses.
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```
### Code Review
Review server-side and client-side flows. Identify sources (where attacker input comes from) and sinks (where input is written into DOM). Prioritize paths that:
- Echo user input into HTML or JavaScript
- Use insecure sinks (innerHTML, document.write, outerHTML, jQuery HTML insertion)
- Build DOM from URL fragments or client-side state

Focus on understanding exact handling so you can craft minimal, reliable payloads rather than blind fuzzing.