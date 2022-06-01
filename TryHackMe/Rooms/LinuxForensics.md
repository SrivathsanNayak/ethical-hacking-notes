# Linux Forensics - Easy

1. [OS and account information](#os-and-account-information)
2. [System Configuration](#system-configuration)
3. [Persistence mechanisms](#persistence-mechanisms)
4. [Evidence of Execution](#evidence-of-execution)
5. [Log files](#log-files)

## OS and account information

```shell
cat /etc/os-release
#find OS release info

cat /etc/passwd
#user accounts info

cat /etc/passwd| column -t -s :
#making it readable

cat /etc/shadow
#stores passwords

cat /etc/group
#info about user groups

cat /etc/sudoers
#sudoers list

sudo last -f /var/log/wtmp
#binary file read using last
#contains login info

less /var/log/auth.log
#info about auth logs
```

```markdown
1. What is the uid of the user account named tryhackme? - 1001

2. Which two users are the members of the group audio? - ubuntu,pulse

3. A session was started on this machine on Sat Apr 16 20:10. How long did this session last? - 01:32
```

## System Configuration

```shell
cat /etc/hostname
#hostname

cat /etc/timezone
#timezone

cat /etc/network/interfaces
#network config

ip a show
#ip addresses

netstat -natp
#active network connections

ps aux
#running processes

cat /etc/hosts
#dns info

cat /etc/resolv.conf
#dns resolution info
```

```markdown
1. What is the hostname of the attached VM? - Linux4n6

2. What is the timezone of the attached VM? - Asia/Karachi

3. What program is listening on the address 127.0.0.1:5901? - Xtigervnc

4. What is the full path of this program? - /usr/bin/Xtigervnc
```

## Persistence mechanisms

```shell
cat /etc/crontab
#view cron jobs

ls /etc/init.d/
#list of startup services

cat ~/.bashrc
#persistence of bash shell

cat /etc/bash.bashrc
#system wide settings
```

```markdown
1. In the bashrc file, the size of the history is defined. What is the size of the history file that is set for the user Ubuntu in the attached machine? - 2000
```

## Evidence of Execution

```shell
cat /var/log/auth.log* | grep -i COMMAND | tail
#view commands run using sudo

cat ~/.bash_history
#history of commands stored for each user in their directory

cat ~/.viminfo
#logs for files opening in vim
```

```markdown
1. The user tryhackme used apt-get to install a package. What was the command that was issued? - sudo apt-get install apache2

2. What was the current working directory when the command to install net-tools was issued? - /home/ubuntu
```

## Log files

```shell
cat /var/log/syslog* | head
#records system activity

cat /var/log/auth.log8 | head
#auth logs

ls /var/log/
#lists logs for third party apps
```

```markdown
1. The machine earlier had a different hostname. What was the previous hostname of the machine? - tryhackme
```
