# Initial Enumeration and Automated Tools

1. [System Enumeration](#system-enumeration)
2. [User Enumeration](#user-enumeration)
3. [Network Enumeration](#network-enumeration)
4. [Password Hunting](#password-hunting)
5. [AV Enumeration](#av-enumeration)
6. [Automated Enumeration Tools](#automated-enumeration-tools)

## System Enumeration

* This is the stage where we have a reverse shell, and we need to enumerate the complete system for clues.

```shell
#from Meterpreter shell to Windows cmd
shell

systeminfo

#extract particular info
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

hostname

wmic qfe
#check patches

wmic qfe get Caption,Description,HotFixID,InstalledOn
#filters info

wmic logicaldisk get caption,description,providername
#list drives
```

## User Enumeration

```shell
#in windows cmd
whoami

whoami /priv
#privileges
#certain privileges can be enabled and misused

whoami /groups
#check for administrative groups

net user
#users on machine

net user babis
#get info about user

net localgroup

net localgroup administrators
```

## Network Enumeration

```shell
ipconfig

ipconfig /all

arp -a
#check arp tables

route print
#check routing tables

netstat -ano
#check listening ports
```

## Password Hunting

```shell
findstr /si password *.txt *.config *.ini
#find the word 'password' in txt files in particular directory
#we can use PayloadAllTheThings payloads for password hunting
```

## AV Enumeration

```shell
sc query windefend
#service control
#check windows defender

sc queryex type= service
#show all services
#check for AVs

netsh advfirewall firewall dump
#firewall enum
netsh firewall show state

netsh firewall show config
```

## Automated Enumeration Tools

* Executables:

  * [winPEAS.exe](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
  * [Seatbelt.exe](https://github.com/GhostPack/Seatbelt) (compile)
  * [Watson.exe](https://github.com/rasta-mouse/Watson) (compile)
  * [SharpUp.exe](https://github.com/GhostPack/SharpUp) (compile)

* PowerShell

  * [Sherlock.ps1](https://github.com/rasta-mouse/Sherlock)
  * [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
  * [jaws-enum.ps1](https://github.com/411Hall/JAWS)

* Others:

  * [windows-exploit-suggester.py](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) (run locally)
  * [Exploit Suggester](https://www.rapid7.com/blog/post/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/) (Metasploit)

```shell
#exploring enumeration tools when we cannot upload executables or files

#in Meterpreter shell
#exploit suggester
run post/multi/recon/local_exploit_suggester

#shell
shell

systeminfo
#copy sysinfo to a file sysinfo.txt

#in attacker machine
#update windows-exploit-suggester
python2 windows-exploit-suggester.py --update
#note database .xls file

pip2 install --user xlrd==1.1.0

python2 windows-exploit-suggester.py --database 2022-10-27-mssb.xls --systeminfo samplesysinfo.txt
#this gives us vulnerabilities list
```
