
## 1- Intro to File Inclusions
Many back-end languages like PHP, JavaScript, and Java use HTTP parameters to dynamically load content on web pages.  
If these parameters are not properly secured, attackers can manipulate them to read local files on the server — a vulnerability known as **Local File Inclusion (LFI)**.

#### Local File Inclusion (LFI)
LFI is common in templating engines where dynamic content is loaded using parameters like:
```
/index.php?page=about
```

If input is not sanitized, an attacker can modify this to load other files on the system.

LFI can expose:

- Source code
- Credentials or sensitive data
- Potential for **Remote Code Execution (RCE)** in certain setups
#### PHP

```php
if (isset($_GET['language'])) {
    include($_GET['language']);
}
```

User input is passed directly to `include()`, allowing reading or execution of local files.  
Other risky PHP functions:
- `include_once()`
- `require()`
- `require_once()`
- `file_get_contents()`

#### NodeJS
```javascript
if(req.query.language){
    fs.readFile(path.join(__dirname, req.query.language),(err,data)=>{
        res.write(data);
    });
}
```
`readFile()` loads files directly from user-controlled input.
```js
app.get("/about/:language",(req,res)=>{
    res.render(`/${req.params.language}/about.html`);
});
```
`res.render()` can render arbitrary files if the path is manipulated.
#### Java

```jsp
<c:if test="${not empty param.language}">
    <jsp:include file="<%= request.getParameter('language') %>" />
</c:if>
```
```jsp
<c:import url="<%= request.getParameter('language') %>"/>
```

These functions include or import files dynamically and can lead to file disclosure or execution.
#### .NET

```cs
@if (!string.IsNullOrEmpty(HttpContext.Request.Query["language"])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
}
```

```cs
@Html.Partial(HttpContext.Request.Query["language"])
```

```cs
<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

These methods write or include files based on user input, risking file exposure or execution.
#### Read vs Execute
Some functions only **read** files; others can **execute** them.  
This determines if exploitation leads to source code disclosure or full code execution.

|Function|Read|Execute|Remote|
|---|:-:|:-:|:-:|
|**PHP**||||
|`include()` / `include_once()`|✅|✅|✅|
|`require()` / `require_once()`|✅|✅|❌|
|`file_get_contents()`|✅|❌|✅|
|`fopen()` / `file()`|✅|❌|❌|
|**NodeJS**||||
|`fs.readFile()`|✅|❌|❌|
|`fs.sendFile()`|✅|❌|❌|
|`res.render()`|✅|✅|❌|
|**Java**||||
|`include`|✅|❌|❌|
|`import`|✅|✅|✅|
|**.NET**||||
|`@Html.Partial()`|✅|❌|❌|
|`@Html.RemotePartial()`|✅|❌|✅|
|`Response.WriteFile()`|✅|❌|❌|
|`include`|✅|✅|✅|
