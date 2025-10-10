## Intro to Web Proxies
Modern apps constantly connect to back-end servers to send and receive data. 
To test and secure these communications, pentesters use web proxies to capture, 
inspect, and modify HTTP/HTTPS traffic between clients and servers.

Web Proxies act as man-in-the-middle (MITM) tools, showing all requests and responses.
They’re key for web pentesting — much easier than raw packet sniffers like Wireshark.

Main Uses:
- Capture & replay HTTP requests
- Scan for vulnerabilities
- Fuzzing & crawling
- Analyze and map web apps
- Test configurations

Common Tools:
- Burp Suite: Most popular proxy with free (Community) and paid (Pro/Enterprise) versions.
  Paid version adds features like active scanning and fast Intruder.
- OWASP ZAP: Free, open-source alternative with similar features and no restrictions.

**Tip: Learn both — Burp for advanced/corporate work, ZAP for free/open-source testing.**

---
##  Setting Up

- Burp and ZAP run on Windows, macOS, and Linux (preinstalled on PwnBox, Kali, Parrot).
- Install via each tool's using download pages,  [[https://portswigger.net/burp/releases/| Downlaod Burp]] [[https://www.zaproxy.org/download/| Downlaod ZAP ]] or use the cross-platform JAR and a JRE.
Launch examples:
- Burp: `burpsuite`  or  `java -jar /path/to/burpsuite.jar`
- ZAP:   `zaproxy`   or  `java -jar /path/to/zaproxy.jar`

