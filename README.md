# AidensHoneyPot
Aiden's honeypot!

##### Code borrowed and ammended from Jordan Borean (@jborean93)

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

<img width="1440" alt="image" src="https://user-images.githubusercontent.com/44196051/156535535-8c002c24-92e7-425d-984e-8900a854af62.png">


### Once active
Your honeypot machine won't load a normal GUI, but a login UI that wastes an adversary's time and potentially forces them to burn a few passwords they might have collected.

<img width="1149" alt="image" src="https://user-images.githubusercontent.com/44196051/156535774-61f16436-0360-47d2-851d-84000dce9cca.png">


## Change details

A google chat API can be given in the script, to alert when the honeypot is used and what credential was attempted. It is currently commented out. 

![image](https://user-images.githubusercontent.com/44196051/156535905-875a7c56-2d56-4e0c-9b7f-6193bfe59210.png)


You can change all text, including username here

![image](https://user-images.githubusercontent.com/44196051/156535986-5acec0a1-13f9-4cd3-a860-bac5c05e0c51.png)


# Pick up the script [here](https://github.com/Purp1eW0lf/AidensHoneyPot/blob/main/AHP.ps1)
