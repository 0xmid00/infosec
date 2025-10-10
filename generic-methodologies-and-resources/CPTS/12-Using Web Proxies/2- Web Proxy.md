##  1-Proxy Setup

- Purpose: Route an application's web requests through Burp/ZAP to capture, inspect, modify, and replay HTTP/HTTPS traffic.
- Pre-configured browsers: Both Burp and ZAP include a browser with proxy settings and CA certs pre-installed — fastest way to start testing.
- Manual browser use: Configure Firefox proxy to point to the proxy listener (default localhost:8080). Change port in Burp (Proxy → Proxy Listeners) or ZAP (Tools → Options → Network).
- Quick switching: Use FoxyProxy extension to add a proxy (IP 127.0.0.1, port 8080) and toggle between proxies quickly.
- CA certificates: Install the proxy CA in Firefox (visit [http://burp](http://burp) or export ZAP cert → import in Preferences → Certificates → Authorities) and trust for websites.
- Result: After proxy + CA install, Firefox traffic routes through the proxy allowing seamless interception of HTTPS and HTTP requests.

## 2- Intercepting Web Requests
- Purpose: Use the proxy to capture, pause, inspect, modify, and forward HTTP/HTTPS requests from the app to the server.
- Burp: Intercept is on by default (Proxy → Intercept). Use Forward to send the request onward; keep forwarding until you reach the target request.
- ZAP: Interception off by default. Toggle with the top-bar button or Ctrl+B. HUD can intercept requests inside the pre-configured browser.
- Workflow: Open the proxied browser → perform action → request stops at proxy → inspect/change headers/body → Forward/Step/Continue/Drop.
- Manipulation: Change parameters (e.g., `ip=1` → `ip=;ls;`) to test for backend validation issues like command injection, SQLi, XSS, auth bypass, upload bypass, XXE, deserialization, etc.
- Tip: Use Step to examine each request sequence; use Continue when you only need to intercept a single request.

Example intercepted request (simple form):  
POST /ping HTTP/1.1  
Host: example:32306  
Content-Type: application/x-www-form-urlencoded

ip=1

After manipulation:  
ip=;ls;

Result: Forwarding the manipulated request shows how the server responds — useful to discover and validate vulnerabilities.
## 3- Intercepting Responses
Intercepting Responses (Summary)

- Purpose: Capture server responses before the browser renders them to inspect or modify HTML/JS (e.g., enable inputs, reveal hidden fields).
- Burp: Enable "Intercept Response" (Proxy → Proxy settings → Response interception rules). Intercept request → Forward → edit response HTML → Forward again.
- ZAP: Use Break/Step to intercept response; HUD can modify page (Show/Enable fields, reveal hidden inputs) without intercepting.
- Common uses: enable disabled fields, show hidden inputs, remove client-side restrictions, reveal HTML comments, and test how altered pages accept malicious input.
- Tip: After editing response HTML, refresh or continue to see changes in the browser; use automation rules (response modification) if repeating the same edit.

Example HTML change (make number field accept free text):
Original:
`<input type="number" id="ip" name="ip" min="1" max="255" maxlength="3" required>`
Edited:
`<input type="text"   id="ip" name="ip"              maxlength="100" required>`
## 4-  Automatic Modification

- Purpose: Apply rules to modify HTTP requests/responses automatically (headers or body) so changes persist without manual interception.

Automatic Request Modification
- Burp (Match & Replace): Proxy → Proxy settings → HTTP match & replace.
  Example: Type=Request header, Match=^User-Agent.*$, Replace=User-Agent: HackTheBox Agent 1.0 (regex on).
- ZAP (Replacer): Options → Replacer (Ctrl+R). Add rule (Request Header) to replace User-Agent with "HackTheBox Agent 1.0".
  - Can scope via Initiators (default: apply to all HTTP(S) messages).

Automatic Response Modification
- Burp: Proxy → Options → Match & Replace → add Response body rule.
  Example: Match=`type="number"` → Replace=`type="text"` (no regex). Also change `maxlength="3"` → `maxlength="100"`.
- Result: After refresh (Ctrl+Shift+R) the page accepts edited inputs persistently; command-injection tests can run without manual editing each time.

## 5- Repeating Requests
- Purpose: Quickly resend and edit past HTTP requests to test different payloads fast.
- Find request: Proxy → HTTP History (Burp) / History pane (ZAP).
- Burp: select → Ctrl+R → Repeater → edit → Send.
- ZAP: right-click → Open/Resend (or use HUD) → edit → Send.
- Use to iterate commands/payloads without intercepting each time.
## 6- Encoding/Decoding
- Why: Modify/send requests correctly — special chars must be encoded (space, &, #) or server may error.
- URL-encoding:
  - Burp: select text → right-click Convert Selection → URL → URL-encode key characters (or Ctrl+U).
  - ZAP: request data is usually URL-encoded automatically.
- Common encoders: URL, HTML, Unicode, Base64, ASCII hex.
- Burp: use the Decoder tab to encode/decode and chain encodings.
- ZAP: open Encoder/Decoder/Hash (Ctrl+E) to encode/decode; add custom tabs if needed.
- Example: Base64 cookie `eyJ1c2VybmFtZSI6Imd1ZXN0IiwgImlzX2FkbWluIjpmYWxzZX0=` → decode → `{"username":"guest","is_admin":false}` → edit → re-encode → use in request.
## 7- Proxying Tools
- Purpose: Route CLI/thick-client app HTTP(S) traffic through Burp/ZAP to inspect, modify, and replay requests.
- Tip: Proxying adds latency—only enable when debugging.

Proxychains (Linux)
- Edit /etc/proxychains.conf: add at end
  http 127.0.0.1 8080
- Run command via proxychains (quiet):
  proxychains -q curl http://SERVER_IP:PORT

Metasploit
- Start msfconsole, set proxy for module:
  set PROXIES HTTP:127.0.0.1:8080
- Then set RHOST/RPORT and run the module. Requests appear in Burp/ZAP history.
