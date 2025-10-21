## 1- Introduction
- What: ffuf = fast web fuzzer for directories, files, vhosts, params, and values.
- Use cases:
  - Fuzz directories (discover hidden paths)
  - Fuzz files & extensions (index.php, .bak, .old)
  - Find hidden vhosts (Host header fuzzing)
  - Fuzz PHP parameters and parameter values
- How it works: send requests from a wordlist → check responses (e.g., 200, size, RTT) → investigate hits manually.
- Why use ffuf: fast, reliable, scriptable — ideal for large lists and automation.
## 2- Web Fuzzing

- Tool: ffuf (fast web fuzzer) automates sending requests and checks responses (status, size, RTT).
- Goal: Find hidden directories/pages (200 = exists; 404 = not found).
- Wordlists: use curated lists (SecLists). Example path in PwnBox:
`  /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt`


