# AidensHoneyPot
Aiden's honeypot!

# How does it work under the hood

First, one has to replace some registry keys from Explorer.exe (basic Windows Desktop GUI) with the honepot script. 

This means when an adversary signs in or RDPs into a machine, they will be met with our honeypot and not the usual Windows UI

###### This will NOT break the OS, but it will make it harder to use. 
To stil administrate / attack the machine after doing this, open Task Manager via ctl+alt+delete and under file open a new task

```powershell
#confirm you're in the right spot
get-itemproperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' | select Shell

#replace the reg key
set-itemproperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -name 'Shell' -value 'powershell.exe -WindowStyle Hidden C:\ahp.ps1'

#confirm replacement
get-itemproperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' | select Shell
```

### Once active
Your honeypot machine won't load a normal GUI, but a login UI that wastes an adversary's time and potentially forces them to burn a few passwords they might have collected.

A google chat API can be given in the script, to alert when the honeypot is used. It is currently commented out. 

# Pick up the script [here](https://github.com/Purp1eW0lf/AidensHoneyPot/blob/main/AHP.ps1)
