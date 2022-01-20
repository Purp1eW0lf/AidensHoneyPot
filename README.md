# AidensHoneyPot
Aiden's honeypot!

# How does it work under the hood

First, one has to replace some registry keys from Explorer.exe (basic Windows Desktop GUI) with the honepot
ower

###### This will NOT break the OS, but it will make it harder to use. 
To stil administrate the machine after doing this, open Task Manager via ctl+alt+delete and under file open a new task

```powershell
#confirm you're in the right spot
get-itemproperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' | select Shell

#replace the reg key
set-itemproperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -name 'Shell' -value 'powershell.exe -WindowStyle Hidden C:\hp.ps1'

#confirm replacement
get-itemproperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' | select Shell
```

# Pick up the script [here](https://github.com/Purp1eW0lf/AidensHoneyPot/blob/main/AHP.ps1)
