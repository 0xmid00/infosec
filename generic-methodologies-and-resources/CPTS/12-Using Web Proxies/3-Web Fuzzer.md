## 1- Burp Intruder
- Purpose: Powerful web fuzzer/brute-forcer for dirs, params, values, passwords, etc.
- Note: Community version is throttled (≈1 req/sec). Pro removes limits.

Quick steps:
1. Send request → Right-click → Send to Intruder (Ctrl+I).
2. Positions: mark payload spot(s) with § (e.g., DIRECTORY).
3. Payloads: choose payload set → Simple list or Runtime file (large lists use Runtime).
4. Payload processing: add rules (e.g., skip lines starting with `.` -> regex `^\..*$`).
5. Payload encoding: enable URL-encode if needed.
6. Settings: set Grep - Match (e.g., `200 OK`) to flag hits; adjust resource pool if needed.
7. Start Attack → review results (sort by Status / Length / Grep hits) → visit promising paths (e.g., /admin/).
## 2- ZAP Fuzzer
- Purpose: Fast, unlimited web fuzzing for endpoints, directories, params, and more (no throttle like Burp Community).

Quick steps:
1. Capture request → right-click → Attack → Fuzz.
2. Locations: select text (e.g., "test") → Add (sets fuzz marker).
3. Payloads: Add → choose File / File Fuzzers (built-in lists) / numbers / etc.
4. Processors: (optional) e.g., URL Encode, Prefix/Postfix, Base64, Script — preview payloads.
5. Options: set threads (e.g., 20), strategy (Depth/Breadth), retries, delay.
6. Start Fuzzer → monitor results → sort by HTTP code / size / RTT to find hits (e.g., 200 OK).
