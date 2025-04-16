The use of cloud, such as [AWS](https://aws.amazon.com/), [GCP](https://cloud.google.com/), [Azure](https://azure.microsoft.com/en-us/), and others, is now one of the essential components for many companies nowadays. After all, all companies want to be able to do their work from anywhere, so they need a central point for all management. This is why services from `Amazon` (`AWS`), `Google` (`GCP`), and `Microsoft` (`Azure`) are ideal for this purpose.

Even though cloud providers secure their infrastructure centrally, this does not mean that companies are free from vulnerabilities. The configurations made by the administrators may nevertheless make the company's cloud resources vulnerable. This often starts with the `S3 buckets` (AWS), `blobs` (Azure), `cloud storage` (GCP), which can be accessed without authentication if configured incorrectly.

#### Company Hosted Servers
```bash
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
#-> s3-website-us-west-2.amazonaws.com 10.129.95.250
```
we have already seen that one IP address belongs to the `s3-website-us-west-2.amazonaws.com` server.
**others ways to find cloud storage: **
#### Google Search
```bash
intext:x corp inurl:amazonaws.com # Aws
intext:xcorp inurl:blob.core.windows.net # Azure
```

#### Target website - Source code 
![](https://academy.hackthebox.com/storage/modules/112/cloud3.png)

Such content is also often included in the source code of the web pages, from where the images, JavaScript codes, or CSS are loaded. This procedure often relieves the web server and does not store unnecessary content.
#### Domain.Glass 
![](https://academy.hackthebox.com/storage/modules/112/cloud1.png)

[domain.glass](https://domain.glass) can also tell us a lot about the company's infrastructure. As a positive side effect, we can also see that Cloudflare's security assessment status has been classified as "Safe". This means we have already found a security measure that can be noted for the second layer (gateway).
#### GrayHatWarfare 
Another very useful provider is [GrayHatWarfare](https://buckets.grayhatwarfare.com). We can do many different searches, discover AWS, Azure, and GCP cloud storage, and even sort and filter by file format. Therefore, once we have found them through Google, we can also search for them on GrayHatWarefare and passively discover what files are stored on the given cloud storage.
#### Private and Public SSH Keys Leaked
Sometimes when employees are overworked or under high pressure, mistakes can be fatal for the entire company. These errors can even lead to SSH private keys being leaked, which anyone can download and log onto one or even more machines in the company without using a password.

>Many companies also use abbreviations of the company name, which are then used accordingly within the IT infrastructure. Such terms are also part of an excellent approach to discovering new cloud storage from the company. We can also search for files simultaneously to see the files that can be accessed at the same time.