![](https://academy.hackthebox.com/storage/modules/112/enum-method3.png)


Goal: Gather info to find ways into a system (vulnerabilities)

3 Levels:
- Infrastructure-based
- Host-based
- OS-based

6 Layers:
1. Internet Presence: Domains, Subdomains, IPs, ASN, Cloud, etc. 
>`The goal of this layer is to identify all possible target systems and interfaces that can be tested.`
>
2. Gateway: Firewalls, IDS/IPS, VPNs, DMZ, EDR, NAC
>`The goal is to understand what we are dealing with and what we have to watch out for.`
3. Accessible Services: Ports, Services, Versions, Configs
>`This layer aims to understand the reason and functionality of the target system and gain the necessary knowledge to communicate with it and exploit it for our purposes effectively.`
4. Processes: PIDs, Tasks, Data Flow, Sources/Destinations
>`The goal here is to understand these factors and identify the dependencies between them.`
5. Privileges: Users, Groups, Permissions, Restrictions
`It is crucial to identify these and understand what is and is not possible with these privileges.`
6. OS Setup: OS Type, Patch Level, Config Files, Network Setup
>`The goal here is to see how the administrators manage the systems and what sensitive internal information we can glean from them.`

Notes:
- Not all findings give access
- Time-limited; can’t find everything
- Enumeration = dynamic, tools vary
- Methodology = structured thinking, not fixed steps

Analogy: Each layer = wall in a maze. Look for entry points (vulns), not all paths go deeper.

Practice: Start from outermost layer, move inward, adapt based on environment.
