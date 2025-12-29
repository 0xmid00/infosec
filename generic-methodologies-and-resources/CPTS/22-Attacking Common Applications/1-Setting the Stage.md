## 1- Introduction to Attacking Common Applications
Web apps are widely used and often repeated across environments. Each instance may have different vulnerabilities or misconfigurations. As penetration testers, we must know how to enumerate and exploit these applications.  
They follow a client–server model and commonly contain issues like SQLi, XSS, RCE, and file upload flaws.  
Because many organizations expose apps to the internet, these systems often become initial footholds. Many companies report breaches caused by application vulnerabilities.

Applications often expose useful functionality or known exploits that allow RCE, credential theft, or sensitive data access. Understanding how apps work (not just copying exploits) helps find attack paths even in unfamiliar applications.
## Application Data
We may encounter many categories of apps that can lead to compromise, such as:

|**Category**|**Applications**|
|---|---|
|[Web Content Management](https://enlyft.com/tech/web-content-management)|Joomla, Drupal, WordPress, DotNetNuke, etc.|
|[Application Servers](https://enlyft.com/tech/application-servers)|Apache Tomcat, Phusion Passenger, Oracle WebLogic, IBM WebSphere, etc.|
|[Security Information and Event Management (SIEM)](https://enlyft.com/tech/security-information-and-event-management-siem)|Splunk, Trustwave, LogRhythm, etc.|
|[Network Management](https://enlyft.com/tech/network-management)|PRTG Network Monitor, ManageEngine Opmanger, etc.|
|[IT Management](https://enlyft.com/tech/it-management-software)|Nagios, Puppet, Zabbix, ManageEngine ServiceDesk Plus, etc.|
|[Software Frameworks](https://enlyft.com/tech/software-frameworks)|JBoss, Axis2, etc.|
|[Customer Service Management](https://enlyft.com/tech/customer-service-management)|osTicket, Zendesk, etc.|
|[Search Engines](https://enlyft.com/tech/search-engines)|Elasticsearch, Apache Solr, etc.|
|[Software Configuration Management](https://enlyft.com/tech/software-configuration-management)|Atlassian JIRA, GitHub, GitLab, Bugzilla, Bugsnag, Bitbucket, etc.|
|[Software Development Tools](https://enlyft.com/tech/software-development-tools)|Jenkins, Atlassian Confluence, phpMyAdmin, etc.|
|[Enterprise Application Integration](https://enlyft.com/tech/enterprise-application-integration)|Oracle Fusion Middleware, BizTalk Server, Apache ActiveMQ, etc.|

#### A Quick Story

A tester found Nexus Repository OSS with default credentials (`admin:admin123`).  
They gained RCE using the API and later using script execution features.  
Other apps like ManageEngine OpManager can also run scripts as privileged users. Never ignore applications—they may be the only attack vector.
#### Common Applications

|Application|Description|
|---|---|
|WordPress|[WordPress](https://wordpress.org/) is an open-source Content Management System (CMS) that can be used for multiple purposes. It's often used to host blogs and forums. WordPress is highly customizable as well as SEO friendly, which makes it popular among companies. However, its customizability and extensible nature make it prone to vulnerabilities through third-party themes and plugins. WordPress is written in PHP and usually runs on Apache with MySQL as the backend.|
|Drupal|[Drupal](https://www.drupal.org/) is another open-source CMS that is popular among companies and developers. Drupal is written in PHP and supports using MySQL or PostgreSQL for the backend. Additionally, SQLite can be used if there's no DBMS installed. Like WordPress, Drupal allows users to enhance their websites through the use of themes and modules.|
|Joomla|[Joomla](https://www.joomla.org/) is yet another open-source CMS written in PHP that typically uses MySQL but can be made to run with PostgreSQL or SQLite. Joomla can be used for blogs, discussion forums, e-commerce, and more. Joomla can be customized heavily with themes and extensions and is estimated to be the third most used CMS on the internet after WordPress and Shopify.|
|Tomcat|[Apache Tomcat](https://tomcat.apache.org/) is an open-source web server that hosts applications written in Java. Tomcat was initially designed to run Java Servlets and Java Server Pages (JSP) scripts. However, its popularity increased with Java-based frameworks and is now widely used by frameworks such as Spring and tools such as Gradle.|
|Jenkins|[Jenkins](https://jenkins.io/) is an open-source automation server written in Java that helps developers build and test their software projects continuously. It is a server-based system that runs in servlet containers such as Tomcat. Over the years, researchers have uncovered various vulnerabilities in Jenkins, including some that allow for remote code execution without requiring authentication.|
|Splunk|Splunk is a log analytics tool used to gather, analyze and visualize data. Though not originally intended to be a SIEM tool, Splunk is often used for security monitoring and business analytics. Splunk deployments are often used to house sensitive data and could provide a wealth of information for an attacker if compromised. Historically, Splunk has not suffered from a considerable amount of known vulnerabilities aside from an information disclosure vulnerability ([CVE-2018-11409](https://nvd.nist.gov/vuln/detail/CVE-2018-11409)), and an authenticated remote code execution vulnerability in very old versions ([CVE-2011-4642](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-4642)).|
|PRTG Network Monitor|[PRTG Network Monitor](https://www.paessler.com/prtg) is an agentless network monitoring system that can be used to monitor metrics such as uptime, bandwidth usage, and more from a variety of devices such as routers, switches, servers, etc. It utilizes an auto-discovery mode to scan a network and then leverages protocols such as ICMP, WMI, SNMP, and NetFlow to communicate with and gather data from discovered devices. PRTG is written in [Delphi](https://en.wikipedia.org/wiki/Delphi_\(software\)).|
|osTicket|[osTicket](https://osticket.com/) is a widely-used open-source support ticketing system. It can be used to manage customer service tickets received via email, phone, and the web interface. osTicket is written in PHP and can run on Apache or IIS with MySQL as the backend.|
|GitLab|[GitLab](https://about.gitlab.com/) is an open-source software development platform with a Git repository manager, version control, issue tracking, code review, continuous integration and deployment, and more. It was originally written in Ruby but now utilizes Ruby on Rails, Go, and Vue.js. GitLab offers both community (free) and enterprises versions of the software.|

---

## 2- Application Discovery & Enumeration

- Organizations must maintain an updated asset inventory of all devices and applications.
- Pen testers help find forgotten apps, weak/default credentials, shadow IT, and vulnerable services.
- Enumeration starts with identifying live hosts, scanning ports, and mapping services.
- Tools like **Nmap**, **EyeWitness**, and **Aquatone** speed up processing large amounts of data.

#### Nmap - Web Discovery
- Scan common web ports to discover web applications:
```shell-session
nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
```
- Use deeper scans (e.g., `-sV`, top ports, full TCP) iteratively.
#### Getting Organized
- Use a notetaking tool (OneNote, Notion, Cherrytree).
- Create sections for: Scope → Scans → Live Hosts → Application Discovery → Interesting Hosts → Exploitation.
An example OneNote (also applicable to other tools) structure may look like the following for the discovery phase:
```bash
External Penetration Test - <Client Name>

    Scope (including in-scope IP addresses/ranges, URLs, any fragile hosts, testing timeframes, and any limitations or other relative information we need handy)

    Client Points of Contact

    Credentials

    Discovery/Enumeration

        Scans

        Live hosts

    Application Discovery
        Scans
        Interesting/Notable Hosts

    Exploitation

        <Hostname or IP>

        <Hostname or IP>

    Post-Exploitation

        <Hostname or IP>

        <Hostname or IP>
```
- Timestamp scans, save outputs, and note syntax.
- Helps with reporting and avoids missing key findings.

#### Initial Enumeration
- Start with Nmap scans on common ports.
- Run EyeWitness/Aquatone on results.
Example initial scan:
```shell-session
sudo nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
```
- Follow up with service scans (`-sV`) to identify software (e.g., IIS, Splunk, PRTG).

 #### Using EyeWitness
 Captures screenshots and fingerprints apps from Nmap/Nessus XML.
```bash
# sudo apt install eyewitness (-d Directory Name)
eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```
#### Using Aquatone
 Another screenshot/reporting tool; takes Nmap XML input.
```bash
# install
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip

# run
cat web_discovery.xml | ./aquatone -nmap
  # Wrote HTML report to: aquatone_report.html
```
#### Interpreting Results
![[Pasted image 20251126215857.png]]
- Review screenshots for high-value targets (e.g., Tomcat, Jenkins, osTicket, GitLab).
- Reports save significant time even with many hosts (26–5,000+).
- Reports are organized by categories; **High Value Targets** appear first.
- Always review the entire report—important hosts may be buried deep.
- Example: Found **ManageEngine OpManager** with default creds `admin:admin`; gained RCE via PowerShell → Domain Admin compromise.
- **Tomcat** is a high‑value find; test default creds on `/manager` and `/host-manager` to upload a malicious WAR (JSP) for RCE.
- Check main sites like `http://inlanefreight.local` for custom apps or CMS (WordPress, Joomla, Drupal).
- `http://support-dev.inlanefreight.local` runs **osTicket**, known for severe vulns; can leak sensitive info and aid social engineering (e.g., registering internal emails).
- HTB "Delivery" box shows how osTicket functionality can be abused.
- Continue reviewing and noting URLs + app versions; stay in discovery phase—don’t attack too early.
- Expect to see: custom apps, CMS, Tomcat, Jenkins, Splunk, RDS, SSL VPNs, OWA/O365, and edge device logins.
- Some apps should **never** be exposed—example: unrestricted file upload; uploaded `.aspx` test file → found `/files` dir with listing → uploaded web shell → internal foothold.
- Internal tests often reveal printer logins (sometimes leaking LDAP creds), ESXi/vCenter, iLO/iDRAC, network/IoT devices, phones, repos, SharePoint, intranet portals, security appliances, etc.
#### Moving On
- Next steps: dive into common applications & misconfigurations.
- Strong methodology, organization, and documentation are as important as technical skills.