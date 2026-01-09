Proper Linux hardening can eliminate most, if not all, opportunities for local privilege escalation. The following steps should be taken, at a minimum, to reduce the risk of an attack being able to elevate to root-level access:
#### Updates and Patching
Outdated Linux kernels and services often have easy privilege‑escalation exploits.  
Regular updates remove these risks: Ubuntu/Debian use `unattended-upgrades`, and Red Hat systems use `yum-cron` for automatic updates.
#### Configuration Management
This is by no means an exhaustive list, but some simple hardening measures are to:

- Audit writable files and directories and any binaries set with the SUID bit.
- Ensure that any cron jobs and sudo privileges specify any binaries using the absolute path.
- Do not store credentials in cleartext in world-readable files.
- Clean up home directories and bash history.
- Ensure that low-privileged users cannot modify any custom libraries called by programs.
- Remove any unnecessary packages and services that potentially increase the attack surface.
- Consider implementing [SELinux](https://www.redhat.com/en/topics/linux/what-is-selinux), which provides additional access controls on the system.
#### User Management
Limit user/admin accounts, log and monitor logins, enforce strong passphrases, prevent password reuse, apply least-privilege groups and sudo rights.  
Use automation tools (Puppet, SaltStack, Zabbix, Nagios) for checks, alerts, remediation, and binary integrity verification.
#### Audit
Perform regular security and configuration checks using baselines like DISA [STIGs](https://public.cyber.mil/stigs/) and frameworks such as [ISO27001](https://www.iso.org/isoiec-27001-information-security.html), [PCI-DSS](https://www.pcisecuritystandards.org/pci_security/), and [HIPAA](https://www.hhs.gov/hipaa/for-professionals/security/index.html) as references. Tailor controls to your organization and data types.

Audits supplement but do not replace penetration tests or hands-on assessments. Tools like [Lynis](https://github.com/CISOfy/lynis) help review system configurations and provide hardening tips for Unix-based systems.

After cloning the entire repo, we can run the tool by typing `./lynis audit system` and receive a full report.
```bash
./lynis audit system

[ Lynis 3.0.1 ]

################################################################################
  Lynis comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
  welcome to redistribute it under the terms of the GNU General Public License.
  See the LICENSE file for details about using this software.

  2007-2020, CISOfy - https://cisofy.com/lynis/
  Enterprise support available (compliance, plugins, interface and tools)
################################################################################


[+] Initializing program
------------------------------------

  ###################################################################
  #                                                                 #
  #   NON-PRIVILEGED SCAN MODE                                      #
  #                                                                 #
  ###################################################################

  NOTES:
  --------------
  * Some tests will be skipped (as they require root permissions)
  * Some tests might fail silently or give different results

  - Detecting OS...                                           [ DONE ]
  - Checking profiles...                                      [ DONE ]

  ---------------------------------------------------
  Program version:           3.0.1
  Operating system:          Linux
  Operating system name:     Ubuntu
  Operating system version:  16.04
  Kernel version:            4.4.0
  Hardware platform:         x86_64
  Hostname:                  NIX02
```
The resulting scan will be broken down into warnings:
```bash
Warnings (2):
  ----------------------------
  ! Found one or more cronjob files with incorrect file permissions (see log for details) [SCHD-7704] 
      https://cisofy.com/lynis/controls/SCHD-7704/

  ! systemd-timesyncd never successfully synchronized time [TIME-3185] 
      https://cisofy.com/lynis/controls/TIME-3185/
```
Suggestions:
```bash
Suggestions (53):
  ----------------------------
  * Set a password on GRUB boot loader to prevent altering boot configuration (e.g. boot in single user mode without password) [BOOT-5122] 
      https://cisofy.com/lynis/controls/BOOT-5122/

  * If not required, consider explicit disabling of core dump in /etc/security/limits.conf file [KRNL-5820] 
      https://cisofy.com/lynis/controls/KRNL-5820/

  * Run pwck manually and correct any errors in the password file [AUTH-9228] 
      https://cisofy.com/lynis/controls/AUTH-9228/

  * Configure minimum encryption algorithm rounds in /etc/login.defs [AUTH-9230] 
      https://cisofy.com/lynis/controls/AUTH-9230/
```
and an overal scan details section:
```bash
Lynis security scan details:

  Hardening index : 60 [############        ]
  Tests performed : 256
  Plugins enabled : 2

  Components:
  - Firewall               [X]
  - Malware scanner        [X]

  Scan mode:
  Normal [ ]  Forensics [ ]  Integration [ ]  Pentest [V] (running non-privileged)

  Lynis modules:
  - Compliance status      [?]
  - Security audit         [V]
  - Vulnerability scan     [V]

  Files:
  - Test and debug information      : /home/mrb3n/lynis.log
  - Report data                     : /home/mrb3n/lynis-report.dat
```
The tool is useful for informing privilege escalation paths and performing a quick configuration check and will perform even more checks if run as the root user.

