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

```shell
ip a s

ip route

ip neigh
#arp tables

netstat -ano
#check open ports
```

## Password Hunting

```shell
grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2>/dev/null
#we can search for any string
#it takes time so choose string carefully

locate password | more
#check for filenames with the term 'password'

find / -name authorized_keys 2>/dev/null
#looking for SSH keys
find / -name id_rsa 2>/dev/null
```

## Automated Enumeration Tools

* [LinPeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

* [LinEnum](https://github.com/rebootuser/LinEnum)

* [Linux exploit suggester](https://github.com/mzet-/linux-exploit-suggester)

* [Linux priv checker](https://github.com/sleventyeleven/linuxprivchecker)

```shell
./linpeas.sh
#complete basic enum

./linux-exploit-suggester.sh
#shows CVEs
```
