## Detection & Prevention
```bash
# 🔒 Detection & Prevention

# ⚙️ Set a Baseline:
# - Track DNS, DHCP, app inventory, host locations, admin users
# - Use visual network diagrams (e.g. diagrams.net)
# - Know critical assets & monitor them

# 👥 People:
# - Users are weakest link
# - Enforce security practices, train users
# - Use MFA (password + token/biometric/etc.)
# - Secure BYOD devices; bad hygiene = network risk
# - Build/use SOC, plan incident response

# 📋 Processes:
# - Define & enforce policies (asset mgmt, MFA, provisioning)
# - Baseline configs, gold images, change management logs

# 🧰 Technology:
# - Patch systems, review misconfigs
# - Balance CIA triad: Confidentiality, Integrity, Availability

# 🌐 Perimeter Defense:
# - Know what’s public-facing
# - Block unknown IPs, control VPN access
# - Monitor alerts, define responsibilities
# - Use OOB mgmt, plan for disaster recovery

# 🧱 Internal Defense:
# - Harden exposed hosts, use DMZ
# - Use IDS/IPS, separate networks (prod/admin)
# - Track remote access, log correlation
# - Segment networks, restrict user access
# - Use SIEM for log analysis & alerting

# 🧠 MITRE TTP Breakdown:
# - T1133: Block unauthorized external services w/ firewall, VPN
# - T1021: MFA + restrict remote access (SSH/RDP)
# - T1571: Detect non-standard ports, use NIDS
# - T1572: Block protocol tunneling (e.g. DNS over SSH)
# - T1090: Detect proxy usage by flow analysis
# - LOTL (Living Off the Land): Detect abnormal behavior, baseline users

#  Enterprise tactics (more)
https://attack.mitre.org/tactics/enterprise/
```

