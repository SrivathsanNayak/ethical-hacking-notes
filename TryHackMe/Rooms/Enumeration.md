# Enumeration - Easy

1. [Introduction](#introduction)
2. [Purpose](#purpose)
3. [Linux Enumeration](#linux-enumeration)
4. [Windows Enumeration](#windows-enumeration)
5. [DNS, SMB and SNMP](#dns-smb-and-snmp)
6. [More Tools for Windows](#more-tools-for-windows)

## Introduction

```markdown
1. What command would you use to start the PowerShell interactive command line? - powershell.exe
```

## Purpose

* Post-exploitation enumeration helps in gathering info about system and its network.

```markdown
1. In SSH key-based authentication, which key does the client need? - private key
```

## Linux Enumeration

* System

```shell
ls /etc/*-release
#shows /etc/os-release

cat /etc/os-release
#shows distro info

hostname
#system name

cat /etc/passwd

cat /etc/group

sudo cat /etc/shadow
#includes password hashes

ls -lh /var/mail/
#mail directories contain info

ls -lh /usr/bin
ls -lh /sbin/
#to view installed apps

rpm -qa
#query all packages on RPM-based distros

dpkg -l
#list all packages on Debian-based distros
```

* Users

```shell
who
#shows logged-in users

whoami

w
#users logged in and their activity

id

last
#list of last logged-in users

sudo -l
#lists allowed commands for user
```

* Networking

```shell
ip a s
#ip address show

cat /etc/resolv.conf
#DNS servers

sudo netstat -plt
#returns programs listening on TCP sockets

sudo netstat -pltn
#programs listening on TCP sockets, numerical format for ports and IP

sudo netstat -atupn
#all tcp, udp listening and established connections with program names

#nmap should not be first option as it can trigger intrusion detection & prevention systems

sudo lsof -i
#list open files, display only internet and network connections

sudo lsof -i :25
#output related to port 25
```

* Running Services

```shell
ps -e
#all processes

ps aux
#all processes

ps axjf
#process tree forest

ps aux | grep "THM"
```

```markdown
1. What is the Linux distribution used in the VM? - Ubuntu

2. What is its version number? - 20.04.4

3. What is the name of the user who last logged in to the system? - randa

4. What is the highest listening TCP port number? - 6667

5. What is the program name of the service listening on it? - inspircd

6. There is a script running in the background. Its name starts with THM. What is the name of the script? - THM-24765.sh
```

## Windows Enumeration

* System

```ps
sysinfo

wmic qfe get Caption,Description
#check installed updates

net start
#check installed and started Windows services

wmic product get name,version,vendor
#gets installed apps
```

* Users

```ps
whoami

whoami /priv

whoami /groups

net user
#view users

net group
#works only if machine is DC

net localgroup

net localgroup administrators
#check users that belong to local administrators' group

net accounts

net accounts /domain
```

* Networking

```ps
ipconfig

ipconfig /all

netstat -abno
#display all listening ports and active connections, find binary involved
#and display in numerical format, along with PID
#use -t flag to get TCP connections

arp -a
#discover other systems on the same LAN
```

```markdown
1. What is the full OS Name? - Microsoft Windows Server 2019 Datacenter

2. What is the OS Version? - 10.0.17763

3. How many hotfixes are installed on this MS Windows Server? - 30

4. What is the lowest TCP port number listening on the system? - 22

5. What is the name of the program listening on that port? - sshd.exe
```

## DNS, SMB and SNMP

```shell
#in attacker machine
dig -t AXFR redteam.thm @10.10.7.21
#DNS zone transfer using dig
#this gets copy of all records in DNS server
#-t AXFR flags for zone transfer
#readteam.thm is DOMAIN_NAME and IP is DNS_SERVER

#on Windows command line
net share
#shows shared folders

#on attacker machine
#snmpcheck tool to collect info about network devices
/opt/snmpcheck/snmpcheck.rb 10.10.7.21 -c public | less
#here, 'public' is the community string option
```

```markdown
1. What is the flag that you get in the records? - THM{DNS_ZONE}

2. What is the name of the share available over SMB protocol and starts with THM? - THM{829738}

3. What is the location specified? - THM{SNMP_SERVICE}
```

## More Tools for Windows

* GUI tools for Windows include:

  * [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/)
  * [Process Hacker](https://processhacker.sourceforge.io/)
  * [GhostPack Seatbelt](https://github.com/GhostPack/Seatbelt)

```markdown
1. What utility from Sysinternals Suite shows the logged-in users? - PsLoggedOn
```
