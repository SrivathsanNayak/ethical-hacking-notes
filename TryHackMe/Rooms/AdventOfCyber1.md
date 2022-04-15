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

```shell
```

## Skilling Up

```shell
```

## SUID Shenanigans

```shell
```

## Requests

```shell
```

## Metasploit-a-ho-ho-ho

```shell
```

## Elf Applications

```shell
```

## Elfcryption

```shell
```

## Accumulate

```shell
```

## Unknown Storage

```shell
```

## LFI

```shell
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
