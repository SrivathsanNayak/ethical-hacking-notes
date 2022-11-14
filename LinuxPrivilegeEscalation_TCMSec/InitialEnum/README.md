# Initial Enumeration and Automated Tools

1. [System Enumeration](#system-enumeration)
2. [User Enumeration](#user-enumeration)
3. [Network Enumeration](#network-enumeration)
4. [Password Hunting](#password-hunting)
5. [Automated Enumeration Tools](#automated-enumeration-tools)

## System Enumeration

```shell
hostname

uname -a
#kernel info

cat /proc/version

cat /etc/issue
#distro info

lscpu
#cpu info

ps aux
#services running

ps aux | grep root
#check processes running as root
```

## User Enumeration

```shell
whoami

id

sudo -l
#view commands that can be run as sudo

cat /etc/passwd

cat /etc/passwd | cut -d : -f 1
#get users

cat /etc/shadow

cat /etc/group

history
```

## Network Enumeration

## Password Hunting

## Automated Enumeration Tools
