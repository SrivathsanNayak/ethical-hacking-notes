# Crocodile - Very Easy

```shell
nmap -T4 -A 10.129.105.116

ftp 10.129.105.116 -P 21
#anonymous login

ls

get allowed.userlist

get allowed.userlist.pass

quit
#quit ftp

cat allowed.userlist

cat allowed.userlist.pass

gobuster dir -u http://10.129.105.116 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x .php
#shows login.php, so we can access that page
#using credentials for admin we got earlier
```

1. What nmap scanning switch employs the use of default scripts during a scan? - -sC

2. What service version is found to be running on port 21? - vsftpd 3.0.3

3. What FTP code is returned to us for the "Anonymous FTP login allowed" message? - 230

4. What command can we use to download the files we find on the FTP server? - get

5. What is one of the higher-privilege sounding usernames in the list we retrieved? - admin

6. What version of Apache HTTP Server is running on the target host? - 2.4.41

7. What is the name of a handy web site analysis plug-in we can install in our browser? - Wappalyzer

8. What switch can we use with gobuster to specify we are looking for specific filetypes? - -x

9. What file have we found that can provide us a foothold on the target? - login.php

10. Submit root flag? - c7110277ac44d78b6a9fff2232434d16
