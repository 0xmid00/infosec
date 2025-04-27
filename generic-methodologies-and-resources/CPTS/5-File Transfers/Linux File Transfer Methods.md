Although Linux can communicate via FTP, SMB like Windows, most malware on all different operating systems uses `HTTP` and `HTTPS` for communication.
we will review multiple ways to transfer files on Linux, including HTTP, Bash, SSH, etc.
## Download Operations
![](https://academy.hackthebox.com/storage/modules/24/LinuxDownloadUpload.drawio.png)
### [[Exfiltration#Copy &Paste Base64|Base64 Encode & Decode]]
Depending on the file size we want to transfer, we can use a method that does not require network communication. If we have access to a terminal, we can encode a file to a base64 string, copy its content into the terminal and perform the reverse operation.
### [[Exfiltration#HTTP|Web Downloads with Wget and cURL]] 
Two of the most common utilities in Linux distributions to interact with web applications are `wget` and `curl`. These tools are installed on many Linux distributions.
### [[Exfiltration#HTTP|Fileless Attacks Using Linux]] 
Because of the way Linux works and how [pipes operate](https://www.geeksforgeeks.org/piping-in-unix-or-linux/), most of the tools we use in Linux can be used to replicate fileless operations, which means that we don't have to download a file to execute it.
### [[Exfiltration#/dev/tcp|Download with Bash (/dev/tcp)]] 
There may also be situations where none of the well-known file transfer tools are available. As long as Bash version 2.04 or greater is installed (compiled with --enable-net-redirections), the built-in /dev/TCP device file can be used for simple file downloads.
### [[Exfiltration#SCP| SSH Downloads]] 
SSH (or Secure Shell) is a protocol that allows secure access to remote computers. SSH implementation comes with an `SCP` utility for remote file transfer that, by default, uses the SSH protocol.

## Upload Operations

There are also situations such as binary exploitation and packet capture analysis, where we must upload files from our target machine onto our attack host. The methods we used for downloads will also work for uploads. Let's see how we can upload files in various ways.
###  [[Exfiltration#Upload files| Web Upload]] 
we can use [uploadserver](https://github.com/Densaugeo/uploadserver), an extended module of the Python `HTTP.Server` module, which includes a file upload page.
###  [[Exfiltration#Upload files|Alternative Web File Transfer Method]]  
Since Linux distributions usually have `Python` or `php` installed, starting a web server to transfer files is straightforward. Also, if the server we compromised is a web server, we can move the files we want to transfer to the web server directory and access them from the web page, which means that we are downloading the file from our Pwnbox.

It is possible to stand up a web server using various languages. A compromised Linux machine may not have a web server installed. In such cases, we can use a mini web server. What they perhaps lack in security, they make up for flexibility, as the webroot location and listening ports can quickly be changed.
###  [[Exfiltration#SCP|SCP Upload]]  
## Onwards
These are the most common file transfer methods using built-in tools on Linux systems, but there's more. In the following sections, we'll discuss other mechanisms and tools we can use to perform file transfer operations.