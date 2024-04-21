# TryHack3M: Subscribe - Medium

* Map ```hackme.thm``` to target IP in ```/etc/hosts```

* ```nmap``` scan - ```nmap -T4 -p- -v -A -Pn 10.10.77.25```:

  * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
  * 80/tcp - http - Apache httpd 2.4.41 ((Ubuntu))
  * 8000/tcp - http - Splunkd httpd
  * 8089/tcp - ssl/http - Splunkd httpd
  * 8191/tcp - limnerpressure
  * 40009/tcp - http - Apache httpd 2.4.41

* Exploring <http://hackme.thm>, we can see a login and sign-up page, but signing up requires an invite code.

* We can start enumerating on port 80 as usual:

  ```sh
  gobuster dir -u http://hackme.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 20
  ```

* From initial directory scan, we get a lot of hits - the interesting ones include ```/img```, ```/css```, ```/js```, ```phpmyadmin```, ```/config.php```, and ```/connection.php```

* In ```/js``` directory, we have a file ```invite.js```:

  ```js
  function e(){var e=window.location.hostname;if(e==="capture3millionsubscribers.thm"){var o=new XMLHttpRequest;o.open("POST","inviteCode1337HM.php",true);o.onload=function(){if(this.status==200){console.log("Invite Code:",this.responseText)}else{console.error("Error fetching invite code.")}};o.send()}else if(e==="hackme.thm"){console.log("This function does not operate on hackme.thm")}else{console.log("Lol!! Are you smart enought to get the invite code?")}}
  ```

* From the above snippet, if we make a POST request to "inviteCode1337HM.php" with hostname "capture3millionsubscribers.thm", we can get the Invite Code

* Map the target IP to above hostname in ```/etc/hosts```, visit <http://capture3millionsubscribers.thm> and open Console from Web Developer Tools in the browser.

* Here, we can paste the above snippet of code and then call the function ```e()``` - this gives us the invite code "VkXgo:Invited30MnUsers"

* On using this invite code in the sign up page, we are given the creds "guest@hackme.thm:wedidit1010"

* After logging in, we can explore the dashboard; we can only access one out of the two rooms as we are not a subscriber yet

* Now, from the cookies set, we have a 'isVIP' cookie currently set to 'False' - if we set this to 'True', we can access the second room now

* In this room, if we try to start the machine, we get a prompt saying it's only for VIP users - we need to enumerate further

* By viewing the source code for this page, we get a page "/BBF813FA941496FCE961EBA46D754FF3.php" - this is supposed to be the machine we have to interact with in the room

* When we navigate to this page, we get an emulator capable of running only certain commands:

  ```sh
  # in hackme.thm emulator
  whoami
  # www-data

  ls
  # lists files

  cat advanced_red_teaming.php
  # we cannot view this file
  
  cat config.php
  # this gives us the secure token and admin panel link
  ```

* From 'config.php', we get the secure token "ACC#SS_TO_ADM1N_P@NEL" and the admin panel link <http://admin1337special.hackme.thm:40009>; we can start by mapping this hostname to target IP in ```/etc/hosts```

* If we visit the above URL, we get a '403 Forbidden' page for <http://admin1337special.hackme.thm:40009/public/html/> - we can try directory scanning at this point since we already have a folder '/public':

  ```sh
  gobuster dir -u http://admin1337special.hackme.thm:40009 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 20

  gobuster dir -u http://admin1337special.hackme.thm:40009/public -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 20

  gobuster dir -u http://admin1337special.hackme.thm:40009/public/html -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 20

  gobuster dir -u http://admin1337special.hackme.thm:40009/index -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 20

  gobuster dir -u http://admin1337special.hackme.thm:40009/api -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 20

  gobuster dir -u http://admin1337special.hackme.thm:40009/javascript -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 20
  ```

* This gives us some hits - the interesting ones here are '/index', '/index.php', '/api', '/javascript', 'phpmyadmin' - we can continue to scan these folders while we check the pages for any clues

* For certain pages such as '/api/index', we get a '500 Internal Server Error'

* When we access '/api/login.php', we get an 'invalid request method' error - we can intercept this request in Burp Suite, and 'Change Request Method' from GET to POST, which gives us an 'invalid username or password' error

* While directory scanning, we get a few pages for '/public/html' as well - we get a portal at '/public/html/login'

* We are asked for an auth code here, and if we enter the '$SECURE_TOKEN' value found earlier, we are redirected to a login page. This also shows importance of recursive directory scanning

* Now, we can intercept a request to see how the username and password is transferred, and we can see that it uses the same API endpoint '/api/login.php' we found earlier - we just need to bruteforce this somehow

* We can attempt a bruteforce for 'admin' user - as the payload is sent in JSON format, we have to craft our command accordingly:

  ```sh
  # could not use Hydra with JSON payload as I was getting issues
  # using wfuzz instead

  wfuzz -v -c -z file,/usr/share/wordlists/rockyou.txt -d "{"username":"admin","password":"FUZZ"}" --hw 42 http://admin1337special.hackme.thm:40009/api/login
  ```

* The bruteforce attempt does not work; we will have to try another approach in the login page

* In '/public/html/login', we can try intercepting a mock login request, 'copy to file' from Burp Suite, and try to use ```sqlmap``` to check for any SQLi vulns:

  ```sh
  # copy request to file and use sqlmap
  # i had to save the request twice for some reason
  sqlmap -r test.req --batch --dump --risk=3 --level=5
  # dumps the database
  ```

* ```sqlmap``` dump works and we get creds "admin:adminisadm1n" for the page '/public/html/login'

* On logging into the admin portal, we have two actions to manage registrations - sign up and invite code. It is currently set to invite code

* On changing it to sign up, if we access the main website at <http://hackme.thm>, we get the flag.

* Now, for the detection part, we can log into Splunk using the given creds at port 8000

* Based on given info, the web attack occurred on 4th April 2024 - we need to search the logs in 'Search & Reporting'

* To view all events, simply search for ```index=*``` for time period 'All time' - this gives us a lot of events to search from

* We can now start by viewing & filtering from 'Interesting fields' section - the ```user_agent``` field shows the web hacking tool used on website and it also shows the count of events related to it

* We can filter by that particular ```user_agent``` to view other details of event such as ```source_ip``` (we can search by this field alone to get total events observed from this IP); the ```uri``` field shows the request sent for attack
