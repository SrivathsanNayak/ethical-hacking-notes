# Initial Enumeration

1. [System Enumeration](#system-enumeration)
2. [User Enumeration](#user-enumeration)
3. [Network Enumeration](#network-enumeration)
4. [Password Hunting](#password-hunting)
5. [AV Enumeration](#av-enumeration)

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
