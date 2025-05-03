

## 1. Overview
- Focuses on detecting and preventing attacks involving shells and payloads.
- Covers system monitoring, identifying threats, and applying defenses.

## 2. MITRE ATT&CK Framework
- A framework that outlines tactics and techniques used by real-world attackers.
- **Key tactics related to shells & payloads:**
  - **Initial Access:** Exploiting web apps or misconfigured services to gain entry.
  - **Execution:** Running malicious code (e.g., PowerShell, Metasploit, scripts).
  - **Command & Control (C2):** Maintaining access using common protocols (HTTP, DNS, Slack, etc.).

## 3. Events to Watch For
- **File uploads:** Look for unexpected or suspicious files, especially in web apps.
- **Suspicious user actions:** 
  - Normal users running admin-level commands like `whoami`.
  - Unusual SMB share access.
- **Anomalous network activity:** 
  - Traffic on non-standard ports (e.g., 4444),
  - Bulk HTTP requests,
  - Unfamiliar remote logins.

## 4. Network Visibility
- Keep updated network diagrams using tools like **Draw.io** or **NetBrain**.
- Use devices with Layer 7 visibility (e.g., Cisco Meraki, Palo Alto).
- Know your network’s baseline behavior to detect anomalies faster.

## 5. Payload Detection
- Payloads usually communicate over the network — especially if successful.
- Tools like **Wireshark** can capture and inspect this traffic (especially if unencrypted).
- **Deep Packet Inspection (DPI)** helps detect or block malicious traffic.

## 6. Protecting Endpoints
- Endpoints = PCs, servers, NAS, printers, smart devices, etc.
- Best practices:
  - Use antivirus (e.g., **Windows Defender**).
  - Enable firewalls for Domain, Private, and Public networks.
  - Apply patches and security updates regularly.
  - Monitor for unusual behavior.

## 7. Mitigation Strategies
- **Application Sandboxing:** Limits what an exploited app can do.
- **Least Privilege Access:** Only give users the access they need.
- **Host Segmentation & Hardening:** Use DMZs, follow STIGs, isolate exposed systems.
- **Firewalls & NAT:** Control inbound/outbound traffic, block unused ports, and prevent shell connectivity.

## 8. Summary
- No single tool or method can stop all attacks.
- A **defense-in-depth** approach (multiple security layers) is the best defense strategy.
