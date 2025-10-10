## 1- Burp Scanner
- What: Burp's full web scanner (Crawler + Passive + Active). Pro-only feature (not in Community).
- When to use: Automated discovery + vulnerability verification across a target scope.

Quick workflow:
1. Define scope: Target → Site map → right-click → Add to scope (use advanced include/exclude if needed).
2. Start scan:
   - From Proxy History: right-click request → Scan (or Passive/Active Scan).
   - Or Dashboard → New Scan → choose Crawl or Crawl & Audit.
3. Crawler: maps site by following links/forms to build the site map (does NOT fuzz unlinked pages).
4. Passive Scan: analyzes existing responses (no extra requests) → flags potential issues with confidence levels.
5. Active Scan: Crawl → Passive scan → verify issues by sending test requests, JS analysis, fuzzing insertion points (more thorough, slower).
6. Monitor: Dashboard → Tasks / Logger to view requests, progress and errors.
7. Review: Issue activity → filter by Severity/Confidence (look for High + Firm/Certain).
8. Report: Target → Site map → right-click → Issue → Report issues for this host → export customizable report.
## 2- ZAP Scanner

- What: ZAP's scanner = Spider (crawl) + Passive + Active scans. Builds site tree and finds vulnerabilities.
- Start Spider: right-click request → Attack → Spider (or HUD Spider). Adds site to scope if needed.
- Ajax Spider: use after normal Spider to find JS/AJAX-discovered links.
- Passive Scan: runs automatically on responses while crawling; shows alerts (no extra requests).
- Active Scan: sends test requests/fuzzes params to verify issues (slower, more thorough).
- Monitor: check Sites tree, Alerts tab, and Active Scan progress to review findings.
- Alert details: open an alert to see evidence, request/response, and reproduction steps.
- Reporting: Report → Generate HTML (or XML/Markdown) to export findings.

## 3- Extensions 
- Purpose: Extend Burp/ZAP with community plugins for extra features (decoders, scanners, wordlists, helpers).

Burp (BApp Store / Extender)
- Extender → BApp Store → install extensions; installed add new tabs/features.
- Example: Decoder Improved (more encoders/hashes). Some extensions need runtimes (e.g., Jython).
- Useful: extra scanners, payload builders, header tools, JS analyzers.

||||
|---|---|---|
|.NET Beautifier|J2EEScan|Software Vulnerability Scanner|
|Software Version Reporter|Active Scan++|Additional Scanner Checks|
|AWS Security Checks|Backslash Powered Scanner|Wsdler|
|Java Deserialization Scanner|C02|Cloud Storage Tester|
|CMS Scanner|Error Message Checks|Detect Dynamic JS|
|Headers Analyzer|HTML5 Auditor|PHP Object Injection Check|
|JavaScript Security|Retire.JS|CSP Auditor|
|Random IP Address Header|Autorize|CSRF Scanner|
|JS Link Finder|

ZAP (Marketplace)
- Manage Add-ons → Marketplace → install add-ons (FuzzDB, scripts, scanners).
- Example: FuzzDB adds command-injection lists usable by the Fuzzer.
- Use add-ons to add wordlists, processors, spiders, or custom checks.


